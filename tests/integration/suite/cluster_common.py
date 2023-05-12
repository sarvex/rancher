import subprocess
import os
import re
import yaml
from .common import random_str
from jinja2 import Template


def generate_cluster_config(request, dind_rke_node_num):
    # generate a random and kube_config file
    dind_name = f'dind-{random_str()}'
    dind_cluster_config_file = f'{dind_name}.yml'
    dind_kube_config_file = f'kube_config_{dind_name}.yml'
    cluster_config_tmpl = get_rke_config_template()
    # generate nodes
    random_nodes = [f'node-{random_str()}' for _ in range(dind_rke_node_num)]
    rke_config_template = Template(cluster_config_tmpl)
    rendered_tmpl = rke_config_template.render(
        random_nodes=random_nodes)
    with open(dind_cluster_config_file, 'w') as cluster_config_file:
        cluster_config_file.write(rendered_tmpl)
    request.addfinalizer(
        lambda: cleanup_dind(dind_cluster_config_file, f'{dind_name}.rkestate')
    )

    return \
        dind_name, \
        yaml.safe_load(rendered_tmpl), \
        dind_cluster_config_file, \
        dind_kube_config_file


def cleanup_dind(cluster_file, state_file):
    remove_cluster(cluster_file)
    os.remove(cluster_file)
    os.remove(state_file)


def get_rke_config_template():
    return """
---
authentication:
    strategy: "x509|webhook"
nodes:{% for node in random_nodes %}
  - address: {{ node }}
    user: docker
    role:
    - controlplane
    - worker
    - etcd{% endfor %}
"""


def create_cluster(cluster_config_file):
    raise Exception('cluster creation needs refactor')


def remove_cluster(cluster_config_file):
    try:
        return subprocess.check_output(
            'rke remove --force --dind --config ' +
            cluster_config_file,
            stderr=subprocess.STDOUT, shell=True
        )
    except subprocess.CalledProcessError as err:
        print(f'RKE down error: {str(err.output)}')
        raise err


def import_cluster(admin_mc, kube_config_file, cluster_name):
    client = admin_mc.client

    imported_cluster = client.create_cluster(
                            replace=True,
                            name=cluster_name,
                            localClusterAuthEndpoint={
                                'enabled': True,
                            },
                            rancherKubernetesEngineConfig={},
                        )
    reg_token = client.create_cluster_registration_token(
                    clusterId=imported_cluster.id
                )

    # modify import command to add auth image
    match = r'\.yaml \|'
    replace = '.yaml?authImage=fixed |'
    insecure_command = re.sub(match, replace, reg_token.insecureCommand)

    # run kubectl command
    os_env = os.environ.copy()
    os_env['KUBECONFIG'] = kube_config_file
    subprocess.check_output(insecure_command, env=os_env, shell=True)
    return imported_cluster
