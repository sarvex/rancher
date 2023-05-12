import os
import jinja2
import logging
import tempfile
import time
import subprocess
from yaml import load


logging.getLogger('invoke').setLevel(logging.WARNING)
DEBUG = os.environ.get('DEBUG', 'false')

DEFAULT_CONFIG_NAME = 'cluster.yml'
DEFAULT_NETWORK_PLUGIN = os.environ.get('DEFAULT_NETWORK_PLUGIN', 'canal')
K8S_VERSION = os.environ.get('RANCHER_K8S_VERSION', "")


class RKEClient(object):
    """
    Wrapper to interact with the RKE cli
    """
    def __init__(self, master_ssh_key_path, template_path):
        self.master_ssh_key_path = master_ssh_key_path
        self.template_path = template_path
        self._working_dir = tempfile.mkdtemp()
        self._hide = DEBUG.lower() != 'true'

    def _run(self, command):
        print(f'Running command: {command}')
        start_time = time.time()
        result = self.run_command('cd {0} && {1}'.format(self._working_dir,
                                                         command))
        end_time = time.time()
        print('Run time for command {0}: {1} seconds'.format(
            command, end_time - start_time))
        return result

    def up(self, config_yml, config=None):
        yml_name = config if config else DEFAULT_CONFIG_NAME
        self._save_cluster_yml(yml_name, config_yml)
        cli_args = '' if config is None else ' --config {0}'.format(config)
        result = self._run("rke up {0}".format(cli_args))
        print(
            "RKE kube_config:\n{0}".format(self.get_kube_config_for_config()))
        return result

    def remove(self, config=None):
        return self._run("rke remove --force")

    def build_rke_template(self, template, nodes, **kwargs):
        """
            This method builds RKE cluster.yml from a template,
            and updates the list of nodes in update_nodes
        """
        render_dict = {
            'master_ssh_key_path': self.master_ssh_key_path,
            'network_plugin': DEFAULT_NETWORK_PLUGIN,
            'k8s_version': K8S_VERSION,
        } | kwargs
        for node_index, node in enumerate(nodes):
            node_dict = {
                f'ssh_user_{node_index}': node.ssh_user,
                f'ip_address_{node_index}': node.public_ip_address,
                f'dns_hostname_{node_index}': node.host_name,
                f'ssh_key_path_{node_index}': node.ssh_key_path,
                f'ssh_key_{node_index}': node.ssh_key,
                f'internal_address_{node_index}': node.private_ip_address,
                f'hostname_override_{node_index}': node.node_name,
            }
            render_dict |= node_dict
        yml_contents = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_path)
        ).get_template(template).render(render_dict)
        print("Generated cluster.yml contents:\n", yml_contents)
        nodes = self.update_nodes(yml_contents, nodes)
        return yml_contents, nodes

    @staticmethod
    def convert_to_dict(yml_contents):
        return load(yml_contents)

    def update_nodes(self, yml_contents, nodes):
        """
        This maps some rke logic for how the k8s nodes is configured to
        the nodes created by the cloud provider, so that the nodes list
        is the source of truth to validated against kubectl calls
        """
        yml_dict = self.convert_to_dict(yml_contents)
        for dict_node in yml_dict['nodes']:
            for node in nodes:
                if node.public_ip_address == dict_node['address'] or \
                        node.host_name == dict_node['address']:
                    # dep
                    node.host_name = dict_node['address']
                    if dict_node.get('hostname_override'):
                        node.node_name = dict_node['hostname_override']
                    else:
                        node.node_name = node.host_name
                    node.roles = dict_node['role']

                    # if internal_address is given, used to communicate
                    # this is the expected ip/value in nginx.conf
                    node.node_address = node.host_name
                    if dict_node.get('internal_address'):
                        node.node_address = dict_node['internal_address']
                    break
        return nodes

    def _save_cluster_yml(self, yml_name, yml_contents):
        file_path = f"{self._working_dir}/{yml_name}"
        with open(file_path, 'w') as f:
            f.write(yml_contents)

    def get_kube_config_for_config(self, yml_name=DEFAULT_CONFIG_NAME):
        file_path = f"{self._working_dir}/kube_config_{yml_name}"
        with open(file_path, 'r') as f:
            kube_config = f.read()
        return kube_config

    def kube_config_path(self, yml_name=DEFAULT_CONFIG_NAME):
        return os.path.abspath(f"{self._working_dir}/kube_config_{yml_name}")

    def save_kube_config_locally(self, yml_name=DEFAULT_CONFIG_NAME):
        file_name = f'kube_config_{yml_name}'
        contents = self.get_kube_config_for_config(yml_name)
        with open(file_name, 'w') as f:
            f.write(contents)

    def run_command(self, command):
        return subprocess.check_output(command, shell=True, text=True)

    def run_command_with_stderr(self, command):
        try:
            output = subprocess.check_output(command, shell=True,
                                             stderr=subprocess.PIPE)
            returncode = 0
        except subprocess.CalledProcessError as e:
            output = e.output
            returncode = e.returncode
        print(returncode)
