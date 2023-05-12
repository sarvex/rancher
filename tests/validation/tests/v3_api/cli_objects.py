import os
import time
import subprocess
from pathlib import Path

from .common import get_user_client, random_test_name, \
    DATA_SUBDIR, run_command, random_str
from .cli_common import DEFAULT_TIMEOUT, BaseCli


class RancherCli(BaseCli):
    def __init__(self, url, token, context):
        self.login(url, token, context=context)
        self.projects = ProjectCli()
        self.apps = AppCli()
        self.mcapps = MultiClusterAppCli()
        self.catalogs = CatalogCli()
        self.clusters = ClusterCli()
        self.nodes = NodeCli()
        self.default_project = self.projects.create_project()
        self.default_namespace = self.projects.create_namespace(
            random_test_name("testdefault"))
        BaseCli.DEFAULT_CONTEXT = self.default_project["id"]
        self.switch_context(self.DEFAULT_CONTEXT)

    def cleanup(self):
        self.log.info(
            f'Cleaning up created test project: {self.default_project["name"]}'
        )
        self.switch_context(self.default_project["id"])
        self.run_command(
            f'project delete {self.default_project["id"]}', expect_error=True
        )


class ProjectCli(BaseCli):
    def create_project(self, name=None,
                       cluster_id=None, use_context=True):
        if name is None:
            name = random_test_name("ptest")
        if cluster_id is None:
            cluster = self.get_context()[0]
            cluster_id = self.get_cluster_by_name(cluster)["id"]
        self.run_command(f"projects create --cluster {cluster_id} {name}")
        project = None
        for p in self.get_current_projects():
            if p["name"] == name:
                project = p
                self.log.info("Project '%s' created successfully "
                              "in cluster '%s'", name, cluster_id)
                break
        if project is None:
            self.log.error("Failed to create project '%s' "
                           "in cluster '%s'", name, cluster_id)
            return project

        if use_context:
            self.log.info("Switching context to newly created project: "
                          "%s", name)
            for p in self.get_current_projects():
                if p["name"] == name:
                    self.switch_context(p["id"])
                    break
        return project

    def delete_project(self, name):
        self.run_command(f"projects rm {name}")

    @classmethod
    def get_current_projects(cls):
        """This uses the Rancher Python Client to retrieve the current projects
        as there is not a CLI way to do this without passing stdin at the time
        of creation (2/13/2020, Rancher v2.3.5).
        Returns array of dictionaries containing id, name, clusterid, & uuid"""
        client = get_user_client()
        projects = client.list_project()
        current_projects = []
        for project in projects:
            p = {
                "id": project["id"],
                "name": project["name"],
                "clusterId": project["clusterId"],
                "state": project["state"],
                "uuid": project["uuid"]
            }
            current_projects.append(p)
        return current_projects

    def create_namespace(self, name=None):
        if name is None:
            name = random_test_name("nstest")
        self.run_command(f"namespace create {name}")
        return name

    def delete_namespace(self, name):
        self.run_command(f"namespace delete {name}")

        self.log.info("Waiting for the namespace to be deleted")
        return self.wait_for_ready(
            "namespace ls -q",
            name,
            condition_func=lambda val, l: val not in l.splitlines(),
        )

    def get_namespaces(self):
        namespaces = self.run_command("namespace ls --format "
                                      "'{{.Namespace.Name}}"
                                      "|{{.Namespace.State}}'")
        return namespaces.splitlines()

    def move_namespace(self, name, project_id):
        self.run_command(f"namespace move {name} {project_id}")


class AppCli(BaseCli):
    def install(self, app_name, namespace, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        version = kwargs.get("version", None)
        context = kwargs.get("context", self.DEFAULT_CONTEXT)
        values = kwargs.get("values", None)
        cmd = f"apps install {app_name} --no-prompt -n {namespace}"
        if version is not None:
            cmd += f" --version {version}"
        if values is not None:
            cmd += f" --values {values}"

        self.switch_context(context)
        app = self.run_command(cmd)
        app = app.split('"')[1].split(" ")[2]
        self.log.info(f"App is: {app}")

        self.log.info("Waiting for the app to be created")
        # Wait for app to be "deploying"
        self.wait_for_ready("apps ls --format '{{.App.Name}} {{.App.State}}' "
                            "| grep deploying | awk '{print $1}'", app,
                            timeout=timeout)
        # Wait for app to be "active"
        created = self.wait_for_ready("apps ls --format '{{.App.Name}} "
                                      "{{.App.State}}' | grep active "
                                      "| awk '{print $1}'", app,
                                      timeout=timeout)
        if not created:
            self.log.warn(
                f"Failed to install app {app_name} within timeout of {timeout} seconds."
            )
        return self.get(app)

    def get(self, app_name):
        app = self.run_command("apps ls --format '{{.App.Name}}|{{.App.ID}}"
                               "|{{.App.State}}|{{.Version}}|{{.Template}}' "
                               "| grep " + app_name)
        app = app.split("|")
        return {"name": app[0], "id": app[1],
                "state": app[2], "version": app[3], "template": app[4]}

    def upgrade(self, app, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        version = kwargs.get("version", None)
        if version is None:
            version = self.run_command(f'apps st {app["template"]} | tail -1')
        self.run_command(f'apps upgrade {app["name"]} {version}')

        self.log.info("Waiting for the app to be upgraded")
        # Wait for app to be "deploying"
        self.wait_for_ready("apps ls --format '{{.App.Name}} {{.App.State}}' "
                            "| grep deploying | awk '{print $1}'", app["name"])
        # Wait for app to be "active"
        upgraded = self.wait_for_ready("apps ls --format '{{.App.Name}} "
                                       "{{.App.State}}' | grep active "
                                       "| awk '{print $1}'", app["name"])
        if not upgraded:
            self.log.warn(
                f'Failed to upgrade app {app["name"]} within timeout of {timeout} seconds.'
            )
        return self.get(app["name"])

    def rollback(self, app, desired_version, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        # Retrieve non-current versions that match desired version
        revision = self.run_command(
            "apps rollback -r %s | grep %s | awk '{print $1}'" %
            (app["name"], desired_version)).splitlines()[0]

        self.run_command(f'apps rollback {app["name"]} {revision}')

        self.log.info("Waiting for the app to be rolled back")
        # Wait for app to be "deploying"
        self.wait_for_ready("apps ls --format '{{.App.Name}} {{.App.State}}' "
                            "| grep deploying | awk '{print $1}'", app["name"])
        # Wait for app to be "active"
        rolled_back = self.wait_for_ready("apps ls --format '{{.App.Name}} "
                                          "{{.App.State}}' | grep active "
                                          "| awk '{print $1}'", app["name"])
        if not rolled_back:
            self.log.warn(
                f'Failed to rollback app {app["name"]} within timeout of {timeout} seconds.'
            )
        return self.get(app["name"])

    def delete(self, app, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.run_command(f'apps delete {app["name"]}')

        self.log.info("Waiting for the app to be deleted")
        return self.wait_for_ready(
            "apps ls -q",
            app["name"],
            timeout=timeout,
            condition_func=lambda val, l: val not in l.splitlines(),
        )

    def install_local_dir(self, catalog_url, branch, chart, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        context = kwargs.get("context", self.DEFAULT_CONTEXT)
        version = kwargs.get("version", None)
        current_dir = os.getcwd()
        os.chdir(DATA_SUBDIR)
        get_charts_cmd = run_command(f"git clone -b {branch} {catalog_url}")
        time.sleep(5)
        os.chdir(f"{DATA_SUBDIR}/integration-test-charts/charts/{chart}/{version}")
        app_name = random_str()
        self.switch_context(context)
        app = self.run_command(f"apps install . {app_name}")
        app = app.split('"')[1].split(" ")[2]
        self.log.info(f"App is: {app}")
        self.log.info("Waiting for the app to be created")
        self.wait_for_ready("apps ls --format '{{.App.Name}} {{.App.State}}' "
                            "| grep deploying | awk '{print $1}'", app,
                            timeout=timeout)
        # Wait for app to be "active"
        created = self.wait_for_ready("apps ls --format '{{.App.Name}} "
                                      "{{.App.State}}' | grep active "
                                      "| awk '{print $1}'", app,
                                      timeout=timeout)
        if not created:
            self.log.warn(
                f"Failed to install app {app_name} within timeout of {timeout} seconds."
            )
        os.chdir(current_dir)
        return self.get(app)


class MultiClusterAppCli(BaseCli):
    def install(self, template_name, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        version = kwargs.get("version", None)
        targets = kwargs.get("targets", [self.DEFAULT_CONTEXT])
        values = kwargs.get("values", None)
        role = kwargs.get("role", "project-member")
        cmd = f"mcapps install {template_name} --no-prompt --role {role}"
        for t in targets:
            cmd += f" --target {t}"
        if version is not None:
            cmd += f" --version {version}"
        if values is not None:
            for k, v in values.items():
                cmd += f" --set {k}={v}"

        app = self.run_command(cmd)
        app = app.split('"')[1]
        self.log.info(f"Multi-Cluster App is: {app}")
        # Wait for multi-cluster app to be "deploying"
        self.wait_for_ready("mcapps ls --format '{{.App.Name}} {{.App.State}}'"
                            " | grep deploying | awk '{print $1}'",
                            app, timeout=timeout)
        # Wait for multi-cluster app to be "active"
        self.log.info("Waiting for the multi-cluster app to be created")
        created = self.wait_for_ready("mcapps ls --format '{{.App.Name}} "
                                      "{{.App.State}}' | grep active "
                                      "| awk '{print $1}'", app,
                                      timeout=timeout)
        if not created:
            self.log.warn(
                f"Failed to install multi-cluster app {template_name} within timeout of {timeout} seconds."
            )
        return self.get(app)

    def get(self, app_name):
        app = self.run_command("mcapps ls --format '{{.App.Name}}|{{.App.ID}}"
                               "|{{.App.State}}|{{.Version}}"
                               "|{{.App.TemplateVersionID}}|"
                               "{{- range $key, $value := .App.Targets}}"
                               "{{$value.AppID}} {{$value.ProjectID}} "
                               "{{$value.State}};;{{- end}}' "
                               "| grep " + app_name)
        app = app.split("|")
        targets = []
        for t in app[5].split(";;")[:-1]:
            t = t.split()
            self.switch_context(t[1])
            t_app = AppCli.get(AppCli(), t[0])
            targets.append(t_app)

        revision = self.run_command("mcapps rollback -r %s | grep '*' | awk "
                                    "'{print $2}'" % app_name).splitlines()[0]

        return {"name": app[0], "id": app[1], "state": app[2],
                "version": app[3], "template": app[4][:-(len(app[3]) + 1)],
                "targets": targets, "revision": revision}

    def upgrade(self, app, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        version = kwargs.get("version", None)
        if version is None:
            version = self.run_command(f'mcapps st {app["template"]} | tail -1')
        self.run_command(f'mcapps upgrade {app["name"]} {version}')

        self.log.info("Waiting for the multi-cluster app to be upgraded")
        # Wait for multi-cluster app to be "deploying"
        self.wait_for_ready("mcapps ls --format '{{.App.Name}} {{.App.State}}'"
                            " | grep deploying | awk '{print $1}'",
                            app["name"], timeout=timeout)
        # Wait for multi-cluster app to be "active"
        upgraded = self.wait_for_ready("mcapps ls --format '{{.App.Name}} "
                                       "{{.App.State}}' | grep active "
                                       "| awk '{print $1}'", app["name"])
        if not upgraded:
            self.log.warn(
                f'Failed to upgrade multi-cluster app {app["name"]} within timeout of {timeout} seconds.'
            )
        return self.get(app["name"])

    def rollback(self, app_name, revision, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.run_command(f"mcapps rollback {app_name} {revision}")

        self.log.info("Waiting for the multi-cluster app to be rolled back")
        # Wait for multi-cluster app to be "deploying"
        self.wait_for_ready("mcapps ls --format '{{.App.Name}} {{.App.State}}'"
                            " | grep deploying | awk '{print $1}'",
                            app_name, timeout=timeout)
        # Wait for multi-cluster app to be "active"
        rolled_back = self.wait_for_ready("mcapps ls --format '{{.App.Name}} "
                                          "{{.App.State}}' | grep active "
                                          "| awk '{print $1}'", app_name)
        if not rolled_back:
            self.log.warn(
                f"Failed to rollback multi-cluster app {app_name} within timeout of {timeout} seconds."
            )
        return self.get(app_name)

    def delete(self, app, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.run_command(f'mcapps delete {app["name"]}')

        self.log.info("Waiting for the app to be deleted")
        deleted = self.wait_for_ready("mcapps ls -q", app["name"],
                                      timeout=timeout, condition_func=
                                      lambda val, l: val not in l.splitlines())
        apps_deleted = False
        for target in app["targets"]:
            apps_deleted = self.wait_for_ready("apps ls -q", target["name"],
                                               timeout=timeout, condition_func=
                                               lambda val, l:
                                               val not in l.splitlines())
            if not apps_deleted:
                break
        return deleted, apps_deleted


class CatalogCli(BaseCli):
    def add(self, url, **kwargs):
        branch = kwargs.get("branch", None)
        catalog_name = random_test_name("ctest")
        cmd = f"catalog add {catalog_name} {url}"
        if branch is not None:
            cmd = f"{cmd} --branch {branch}"
        self.run_command(cmd)
        return self.get(catalog_name)

    def delete(self, name):
        self.run_command(f"catalog delete {name}")
        return self.get(name) is None

    def get(self, name):
        catalog = self.run_command("catalog ls --format '{{.Catalog.Name}}"
                                   "|{{.Catalog.ID}}|{{.Catalog.URL}}"
                                   "|{{.Catalog.Branch}}' | grep " + name)
        if catalog is None:
            return None
        catalog = catalog.split("|")
        return {"name": catalog[0], "id": catalog[1],
                "url": catalog[2], "branch": catalog[3]}


class ClusterCli(BaseCli):
    def delete(self, c_id):
        self.run_command(f"clusters delete {c_id}")

        self.log.info("Waiting for the cluster to be deleted")
        return self.wait_for_ready(
            "cluster ls -q",
            c_id,
            condition_func=lambda val, l: val not in l.splitlines(),
        )


class NodeCli(BaseCli):
    def get(self):
        result = self.run_command(
            "nodes ls --format '{{.Name}}|{{.Node.IPAddress}}'").splitlines()
        return [{"name": n.split("|")[0], "ip": n.split("|")[1]} for n in result]

    def ssh(self, node, cmd, known=False, is_jenkins=False):
        if is_jenkins:
            home = str(Path.home())
            tilde = home
        else:
            tilde = '~'
        if not known:
            self.log.debug("Determining if host is already known")
            known_hosts = os.path.expanduser(f"{tilde}/.ssh/known_hosts")
            with open(known_hosts) as file:
                for line in file:
                    if node["ip"] in line:
                        known = True
                        break
        if not known:
            self.log.debug("Host is not known. Attempting to add it to file")
            try:
                self.log.debug("Storing ecdsa key in known hosts")
                subprocess.run(
                    f'ssh-keyscan -t ecdsa {node["ip"]} >> {tilde}/.ssh/known_hosts',
                    shell=True,
                    stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as e:
                self.log.info("Error storing ecdsa key! Result: %s", e.stderr)
        return self.run_command(f'ssh {node["name"]} "{cmd}"')
