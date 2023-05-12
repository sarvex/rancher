import base64
import os
import pytest
import re
import time
from lib.aws import AWS_USER
from .common import (
    ADMIN_PASSWORD, AmazonWebServices, run_command, wait_for_status_code,
    TEST_IMAGE, TEST_IMAGE_NGINX, TEST_IMAGE_OS_BASE, readDataFile,
    DEFAULT_CLUSTER_STATE_TIMEOUT
)
from .test_custom_host_reg import (
    random_test_name, RANCHER_SERVER_VERSION, HOST_NAME, AGENT_REG_CMD
)
from .test_create_ha import (
    set_url_and_password,
    RANCHER_HA_CERT_OPTION, RANCHER_VALID_TLS_CERT, RANCHER_VALID_TLS_KEY
)
from .test_import_k3s_cluster import (RANCHER_K3S_VERSION)

PRIVATE_REGISTRY_USERNAME = os.environ.get("RANCHER_BASTION_USERNAME")
PRIVATE_REGISTRY_PASSWORD = \
    os.environ.get("RANCHER_BASTION_PASSWORD", ADMIN_PASSWORD)
BASTION_ID = os.environ.get("RANCHER_BASTION_ID", "")
NUMBER_OF_INSTANCES = int(os.environ.get("RANCHER_AIRGAP_INSTANCE_COUNT", "1"))
IMAGE_LIST = os.environ.get("RANCHER_IMAGE_LIST", ",".join(
    [TEST_IMAGE, TEST_IMAGE_NGINX, TEST_IMAGE_OS_BASE])).split(",")
ARCH = os.environ.get("RANCHER_ARCH", "amd64")

AG_HOST_NAME = random_test_name(HOST_NAME)
RANCHER_AG_INTERNAL_HOSTNAME = f"{AG_HOST_NAME}-internal.qa.rancher.space"
RANCHER_AG_HOSTNAME = f"{AG_HOST_NAME}.qa.rancher.space"
RESOURCE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            'resource')
SSH_KEY_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           '.ssh')


def test_deploy_bastion():
    node = deploy_bastion_server()
    assert node.public_ip_address is not None


def test_deploy_airgap_rancher(check_hostname_length):
    bastion_node = deploy_bastion_server()
    save_res, load_res = add_rancher_images_to_private_registry(bastion_node)
    assert (
        f"Image pull success: rancher/rancher:{RANCHER_SERVER_VERSION}"
        in save_res[0]
    )
    assert (
        f"The push refers to repository [{bastion_node.host_name}/rancher/rancher]"
        in load_res[0]
    )
    ag_node = deploy_airgap_rancher(bastion_node)
    public_dns = create_nlb_and_add_targets([ag_node])
    print(
        f"\nConnect to bastion node with:\nssh -i {bastion_node.ssh_key_name}.pem {AWS_USER}@{bastion_node.host_name}\nConnect to rancher node by connecting to bastion, then run:\nssh -i {bastion_node.ssh_key_name}.pem {AWS_USER}@{ag_node.private_ip_address}\n\nOpen the Rancher UI with: https://{public_dns}\n** IMPORTANT: SET THE RANCHER SERVER URL UPON INITIAL LOGIN TO: {RANCHER_AG_INTERNAL_HOSTNAME} **\nWhen creating a cluster, enable private registry with below settings:\nPrivate Registry URL: {bastion_node.host_name}\nPrivate Registry User: {PRIVATE_REGISTRY_USERNAME}\nPrivate Registry Password: (default admin password or whatever you set in RANCHER_BASTION_PASSWORD)\n"
    )
    time.sleep(180)
    setup_rancher_server()


def test_prepare_airgap_nodes():
    bastion_node = get_bastion_node(BASTION_ID)
    ag_nodes = prepare_airgap_node(bastion_node, NUMBER_OF_INSTANCES)
    assert len(ag_nodes) == NUMBER_OF_INSTANCES

    print(
        f'{NUMBER_OF_INSTANCES} airgapped instance(s) created.\nConnect to these and run commands by connecting to bastion node, then running the following command (with the quotes):\nssh -i {bastion_node.ssh_key_name}.pem {AWS_USER}@NODE_PRIVATE_IP "docker login {bastion_node.host_name} -u {PRIVATE_REGISTRY_USERNAME} -p {PRIVATE_REGISTRY_PASSWORD} && COMMANDS"'
    )
    for ag_node in ag_nodes:
        assert ag_node.private_ip_address is not None
        assert ag_node.public_ip_address is None


def test_deploy_airgap_nodes():
    bastion_node = get_bastion_node(BASTION_ID)
    ag_nodes = prepare_airgap_node(bastion_node, NUMBER_OF_INSTANCES)
    assert len(ag_nodes) == NUMBER_OF_INSTANCES

    print(
        f'{NUMBER_OF_INSTANCES} airgapped instance(s) created.\nConnect to these and run commands by connecting to bastion node, then running the following command (with the quotes):\nssh -i {bastion_node.ssh_key_name}.pem {AWS_USER}@NODE_PRIVATE_IP "docker login {bastion_node.host_name} -u {PRIVATE_REGISTRY_USERNAME} -p {PRIVATE_REGISTRY_PASSWORD} && COMMANDS"'
    )
    for ag_node in ag_nodes:
        assert ag_node.private_ip_address is not None
        assert ag_node.public_ip_address is None
    results = []
    for ag_node in ag_nodes:
        deploy_result = run_command_on_airgap_node(bastion_node, ag_node,
                                                   AGENT_REG_CMD)
        results.append(deploy_result)
    for result in results:
        assert (
            f"Downloaded newer image for {bastion_node.host_name}/rancher/rancher-agent"
            in result[1]
        )


def test_deploy_airgap_k3s_private_registry():
    bastion_node = get_bastion_node(BASTION_ID)

    failures = add_k3s_images_to_private_registry(bastion_node,
                                                  RANCHER_K3S_VERSION)
    assert failures == [], f"Failed to add images: {failures}"
    ag_nodes = prepare_airgap_k3s(bastion_node, NUMBER_OF_INSTANCES,
                                  'private_registry')
    assert len(ag_nodes) == NUMBER_OF_INSTANCES

    print(
        f'{NUMBER_OF_INSTANCES} airgapped k3s instance(s) created.\nConnect to these and run commands by connecting to bastion node, then connecting to these:\nssh -i {bastion_node.ssh_key_name}.pem {AWS_USER}@NODE_PRIVATE_IP'
    )
    for ag_node in ag_nodes:
        assert ag_node.private_ip_address is not None
        assert ag_node.public_ip_address is None

    deploy_airgap_k3s_cluster(bastion_node, ag_nodes)

    wait_for_airgap_pods_ready(bastion_node, ag_nodes)

    # Optionally add k3s cluster to Rancher server
    if AGENT_REG_CMD:
        print("Adding to rancher server")
        result = run_command_on_airgap_node(bastion_node, ag_nodes[0],
                                            AGENT_REG_CMD)
        assert "deployment.apps/cattle-cluster-agent created" in result


def test_deploy_airgap_k3s_tarball():
    bastion_node = get_bastion_node(BASTION_ID)
    add_k3s_tarball_to_bastion(bastion_node, RANCHER_K3S_VERSION)

    ag_nodes = prepare_airgap_k3s(bastion_node, NUMBER_OF_INSTANCES, 'tarball')
    assert len(ag_nodes) == NUMBER_OF_INSTANCES

    print(
        f'{NUMBER_OF_INSTANCES} airgapped k3s instance(s) created.\nConnect to these and run commands by connecting to bastion node, then connecting to these:\nssh -i {bastion_node.ssh_key_name}.pem {AWS_USER}@NODE_PRIVATE_IP'
    )
    for ag_node in ag_nodes:
        assert ag_node.private_ip_address is not None
        assert ag_node.public_ip_address is None

    deploy_airgap_k3s_cluster(bastion_node, ag_nodes)

    wait_for_airgap_pods_ready(bastion_node, ag_nodes)

    # Optionally add k3s cluster to Rancher server
    if AGENT_REG_CMD:
        print("Adding to rancher server")
        for num, ag_node in enumerate(ag_nodes):
            prepare_private_registry_on_k3s_node(bastion_node, ag_node)
            restart_k3s = 'sudo systemctl restart k3s-agent'
            if num == 0:
                restart_k3s = 'sudo systemctl restart k3s && ' \
                              'sudo chmod 644 /etc/rancher/k3s/k3s.yaml'
            run_command_on_airgap_node(bastion_node, ag_node, restart_k3s)
        result = run_command_on_airgap_node(bastion_node, ag_nodes[0],
                                            AGENT_REG_CMD)
        assert "deployment.apps/cattle-cluster-agent created" in result


def test_add_rancher_images_to_private_registry():
    bastion_node = get_bastion_node(BASTION_ID)
    save_res, load_res = add_rancher_images_to_private_registry(bastion_node)
    assert (
        f"Image pull success: rancher/rancher:{RANCHER_SERVER_VERSION}"
        in save_res[0]
    )
    assert (
        f"The push refers to repository [{bastion_node.host_name}/rancher/rancher]"
        in load_res[0]
    )


def test_add_images_to_private_registry():
    bastion_node = get_bastion_node(BASTION_ID)
    failures = add_images_to_private_registry(bastion_node, IMAGE_LIST)
    assert failures == [], f"Failed to add images: {failures}"


def test_deploy_private_registry_without_image_push():
    bastion_node = deploy_bastion_server()
    save_res, load_res = add_rancher_images_to_private_registry(
        bastion_node, push_images=False)
    assert (
        f"Image pull success: rancher/rancher:{RANCHER_SERVER_VERSION}"
        in save_res[0]
    )
    assert load_res is None


def setup_rancher_server():
    base_url = f"https://{RANCHER_AG_HOSTNAME}"
    wait_for_status_code(url=f"{base_url}/v3", expected_code=401)
    auth_url = f"{base_url}/v3-public/localproviders/local?action=login"
    wait_for_status_code(url=auth_url, expected_code=200)
    set_url_and_password(base_url, f"https://{RANCHER_AG_INTERNAL_HOSTNAME}")


def deploy_bastion_server():
    node_name = f"{AG_HOST_NAME}-bastion"
    # Create Bastion Server in AWS
    bastion_node = AmazonWebServices().create_node(node_name)
    setup_ssh_key(bastion_node)

    # Get resources for private registry and generate self signed certs
    get_resources_command = f'scp -q -i {SSH_KEY_DIR}/{bastion_node.ssh_key_name}.pem -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r {RESOURCE_DIR}/airgap/basic-registry/ {AWS_USER}@{bastion_node.host_name}:~/basic-registry/'
    run_command(get_resources_command, log_out=False)

    generate_certs_command = f'docker run -v $PWD/certs:/certs -e CA_SUBJECT="My own root CA" -e CA_EXPIRE="1825" -e SSL_EXPIRE="365" -e SSL_SUBJECT="{bastion_node.host_name}" -e SSL_DNS="{bastion_node.host_name}" -e SILENT="true" superseb/omgwtfssl'
    bastion_node.execute_command(generate_certs_command)

    move_certs_command = \
        'sudo cat certs/cert.pem certs/ca.pem > ' \
        'basic-registry/nginx_config/domain.crt && ' \
        'sudo cat certs/key.pem > basic-registry/nginx_config/domain.key'
    bastion_node.execute_command(move_certs_command)

    # Add credentials for private registry
    store_creds_command = f'docker run --rm melsayed/htpasswd {PRIVATE_REGISTRY_USERNAME} {PRIVATE_REGISTRY_PASSWORD} >> basic-registry/nginx_config/registry.password'
    bastion_node.execute_command(store_creds_command)

    # Ensure docker uses the certs that were generated
    update_docker_command = f'sudo mkdir -p /etc/docker/certs.d/{bastion_node.host_name} && sudo cp ~/certs/ca.pem /etc/docker/certs.d/{bastion_node.host_name}/ca.crt && sudo service docker restart'
    bastion_node.execute_command(update_docker_command)

    # Run private registry
    docker_compose_command = \
        'cd basic-registry && ' \
        'sudo curl -L "https://github.com/docker/compose/releases/' \
        'download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" ' \
        '-o /usr/local/bin/docker-compose && ' \
        'sudo chmod +x /usr/local/bin/docker-compose && ' \
        'sudo docker-compose up -d'
    bastion_node.execute_command(docker_compose_command)
    time.sleep(5)

    print(
        f"Bastion Server Details:\nNAME: {node_name}\nHOST NAME: {bastion_node.host_name}\nINSTANCE ID: {bastion_node.provider_node_id}\n"
    )

    return bastion_node


def add_rancher_images_to_private_registry(bastion_node, push_images=True):
    get_images_command = \
        'wget -O rancher-images.txt https://github.com/rancher/rancher/' \
        'releases/download/{0}/rancher-images.txt && ' \
        'wget -O rancher-save-images.sh https://github.com/rancher/rancher/' \
        'releases/download/{0}/rancher-save-images.sh && ' \
        'wget -O rancher-load-images.sh https://github.com/rancher/rancher/' \
        'releases/download/{0}/rancher-load-images.sh'.format(
            RANCHER_SERVER_VERSION)
    bastion_node.execute_command(get_images_command)

    # Remove the "docker save" and "docker load" lines to save time
    edit_save_and_load_command = \
        "sudo sed -i '58d' rancher-save-images.sh && " \
        "sudo sed -i '76d' rancher-load-images.sh && " \
        "chmod +x rancher-save-images.sh && chmod +x rancher-load-images.sh"
    bastion_node.execute_command(edit_save_and_load_command)

    save_images_command = \
        "./rancher-save-images.sh --image-list ./rancher-images.txt"
    save_res = bastion_node.execute_command(save_images_command)

    if push_images:
        load_images_command = f"docker login {bastion_node.host_name} -u {PRIVATE_REGISTRY_USERNAME} -p {PRIVATE_REGISTRY_PASSWORD} && ./rancher-load-images.sh --image-list ./rancher-images.txt --registry {bastion_node.host_name}"
        load_res = bastion_node.execute_command(load_images_command)
        print(load_res)
    else:
        load_res = None

    return save_res, load_res


def add_k3s_tarball_to_bastion(bastion_node, k3s_version):
    k3s_binary = 'k3s-arm64' if ARCH == 'arm64' else 'k3s'
    get_tarball_command = \
        'wget -O k3s-airgap-images-{1}.tar https://github.com/rancher/k3s/' \
        'releases/download/{0}/k3s-airgap-images-{1}.tar && ' \
        'wget -O k3s-install.sh https://get.k3s.io/ && ' \
        'wget -O k3s https://github.com/rancher/k3s/' \
        'releases/download/{0}/{2}'.format(k3s_version, ARCH, k3s_binary)
    bastion_node.execute_command(get_tarball_command)


def add_k3s_images_to_private_registry(bastion_node, k3s_version):
    k3s_binary = 'k3s-arm64' if ARCH == 'arm64' else 'k3s'
    get_images_command = \
        'wget -O k3s-images.txt https://github.com/rancher/k3s/' \
        'releases/download/{0}/k3s-images.txt && ' \
        'wget -O k3s-install.sh https://get.k3s.io/ && ' \
        'wget -O k3s https://github.com/rancher/k3s/' \
        'releases/download/{0}/{1}'.format(k3s_version, k3s_binary)
    bastion_node.execute_command(get_images_command)

    images = bastion_node.execute_command(
        'cat k3s-images.txt')[0].strip().split("\n")
    assert images
    return add_cleaned_images(bastion_node, images)


def add_cleaned_images(bastion_node, images):
    failures = []
    for image in images:
        pull_image(bastion_node, image)
        cleaned_image = re.search(".*(rancher/.*)", image)[1]
        tag_image(bastion_node, cleaned_image)
        push_image(bastion_node, cleaned_image)

        validate_result = validate_image(bastion_node, cleaned_image)
        if bastion_node.host_name not in validate_result[0]:
            failures.append(image)
    return failures


def add_images_to_private_registry(bastion_node, image_list):
    failures = []
    for image in image_list:
        pull_image(bastion_node, image)
        tag_image(bastion_node, image)
        push_image(bastion_node, image)

        validate_result = validate_image(bastion_node, image)
        if bastion_node.host_name not in validate_result[0]:
            failures.append(image)
    return failures


def pull_image(bastion_node, image):
    pull_image_command = f"docker pull {image}"
    bastion_node.execute_command(pull_image_command)


def tag_image(bastion_node, image):
    tag_image_command = "docker image tag {0} {1}/{0}".format(
        image, bastion_node.host_name)
    bastion_node.execute_command(tag_image_command)


def push_image(bastion_node, image):
    push_image_command = f"docker login {bastion_node.host_name} -u {PRIVATE_REGISTRY_USERNAME} -p {PRIVATE_REGISTRY_PASSWORD} && docker push {bastion_node.host_name}/{image}"
    bastion_node.execute_command(push_image_command)


def validate_image(bastion_node, image):
    validate_image_command = f"docker image ls {bastion_node.host_name}/{image}"
    return bastion_node.execute_command(validate_image_command)


def prepare_airgap_node(bastion_node, number_of_nodes):
    node_name = f"{AG_HOST_NAME}-airgap"
    # Create Airgap Node in AWS
    ag_nodes = AmazonWebServices().create_multiple_nodes(
        number_of_nodes, node_name, public_ip=False)

    for num, ag_node in enumerate(ag_nodes):
        # Update docker for the user in node
        ag_node_update_docker = f'ssh -i "{bastion_node.ssh_key_name}.pem" -o StrictHostKeyChecking=no {AWS_USER}@{ag_node.private_ip_address} "sudo usermod -aG docker {AWS_USER}"'
        bastion_node.execute_command(ag_node_update_docker)

        # Update docker in node with bastion cert details
        ag_node_create_dir = f'ssh -i "{bastion_node.ssh_key_name}.pem" -o StrictHostKeyChecking=no {AWS_USER}@{ag_node.private_ip_address} "sudo mkdir -p /etc/docker/certs.d/{bastion_node.host_name} && sudo chown {AWS_USER} /etc/docker/certs.d/{bastion_node.host_name}"'
        bastion_node.execute_command(ag_node_create_dir)

        ag_node_write_cert = f'scp -i "{bastion_node.ssh_key_name}.pem" -o StrictHostKeyChecking=no /etc/docker/certs.d/{bastion_node.host_name}/ca.crt {AWS_USER}@{ag_node.private_ip_address}:/etc/docker/certs.d/{bastion_node.host_name}/ca.crt'
        bastion_node.execute_command(ag_node_write_cert)

        ag_node_restart_docker = f'ssh -i "{bastion_node.ssh_key_name}.pem" -o StrictHostKeyChecking=no {AWS_USER}@{ag_node.private_ip_address} "sudo service docker restart"'
        bastion_node.execute_command(ag_node_restart_docker)

        print(
            f"Airgapped Instance Details:\nNAME: {node_name}-{num}\nPRIVATE IP: {ag_node.private_ip_address}\n"
        )
    return ag_nodes


def prepare_private_registry_on_k3s_node(bastion_node, ag_node):
    # Ensure registry file has correct data
    reg_file = readDataFile(RESOURCE_DIR, "airgap/registries.yaml")
    reg_file = reg_file.replace("$PRIVATE_REG", bastion_node.host_name)
    reg_file = reg_file.replace("$USERNAME", PRIVATE_REGISTRY_USERNAME)
    reg_file = reg_file.replace("$PASSWORD", PRIVATE_REGISTRY_PASSWORD)
    # Add registry file to node
    ag_node_create_dir = f'sudo mkdir -p /etc/rancher/k3s && sudo chown {AWS_USER} /etc/rancher/k3s'
    run_command_on_airgap_node(bastion_node, ag_node,
                               ag_node_create_dir)
    write_reg_file_command = (
        f"cat <<EOT >> /etc/rancher/k3s/registries.yaml\n{reg_file}\nEOT"
    )
    run_command_on_airgap_node(bastion_node, ag_node,
                               write_reg_file_command)


def prepare_airgap_k3s(bastion_node, number_of_nodes, method):
    node_name = f"{AG_HOST_NAME}-k3s-airgap"
    # Create Airgap Node in AWS
    ag_nodes = AmazonWebServices().create_multiple_nodes(
        number_of_nodes, node_name, public_ip=False)

    ag_node_make_executable = \
        'sudo mv ./k3s /usr/local/bin/k3s && ' \
        'sudo chmod +x /usr/local/bin/k3s && sudo chmod +x install.sh'
    for num, ag_node in enumerate(ag_nodes):
        # Copy relevant k3s files to airgapped node
        ag_node_copy_files = \
            'scp -i "{0}.pem" -o StrictHostKeyChecking=no ./k3s-install.sh ' \
            '{1}@{2}:~/install.sh && ' \
            'scp -i "{0}.pem" -o StrictHostKeyChecking=no ./k3s ' \
            '{1}@{2}:~/k3s && ' \
            'scp -i "{0}.pem" -o StrictHostKeyChecking=no certs/* ' \
            '{1}@{2}:~/'.format(bastion_node.ssh_key_name, AWS_USER,
                                ag_node.private_ip_address)
        bastion_node.execute_command(ag_node_copy_files)

        run_command_on_airgap_node(bastion_node, ag_node,
                                   ag_node_make_executable)

        if method == 'private_registry':
            prepare_private_registry_on_k3s_node(bastion_node, ag_node)
        elif method == 'tarball':
            ag_node_copy_tarball = \
                'scp -i "{0}.pem" -o StrictHostKeyChecking=no ' \
                './k3s-airgap-images-{3}.tar ' \
                '{1}@{2}:~/k3s-airgap-images-{3}.tar'.format(
                    bastion_node.ssh_key_name, AWS_USER,
                    ag_node.private_ip_address, ARCH)
            bastion_node.execute_command(ag_node_copy_tarball)
            ag_node_add_tarball_to_dir = f'sudo mkdir -p /var/lib/rancher/k3s/agent/images/ && sudo cp ./k3s-airgap-images-{ARCH}.tar /var/lib/rancher/k3s/agent/images/'
            run_command_on_airgap_node(bastion_node, ag_node,
                                       ag_node_add_tarball_to_dir)

        print(
            f"Airgapped K3S Instance Details:\nNAME: {node_name}-{num}\nPRIVATE IP: {ag_node.private_ip_address}\n"
        )
    return ag_nodes


def deploy_airgap_k3s_cluster(bastion_node, ag_nodes):
    token = ""
    server_ip = ag_nodes[0].private_ip_address
    for num, ag_node in enumerate(ag_nodes):
        if num == 0:
            # Install k3s server
            install_k3s_server = \
                'INSTALL_K3S_SKIP_DOWNLOAD=true ./install.sh && ' \
                'sudo chmod 644 /etc/rancher/k3s/k3s.yaml'
            run_command_on_airgap_node(bastion_node, ag_node,
                                       install_k3s_server)
            token_command = 'sudo cat /var/lib/rancher/k3s/server/node-token'
            token = run_command_on_airgap_node(bastion_node, ag_node,
                                               token_command)[0].strip()
        else:
            install_k3s_worker = f'INSTALL_K3S_SKIP_DOWNLOAD=true K3S_URL=https://{server_ip}:6443 K3S_TOKEN={token} ./install.sh'
            run_command_on_airgap_node(bastion_node, ag_node,
                                       install_k3s_worker)
    time.sleep(10)


def deploy_airgap_rancher(bastion_node):
    ag_node = prepare_airgap_node(bastion_node, 1)[0]
    if "v2.5" in RANCHER_SERVER_VERSION or "master" in RANCHER_SERVER_VERSION:
        privileged = "--privileged"
    else:
        privileged = ""
    if RANCHER_HA_CERT_OPTION == 'byo-valid':
        write_cert_command = f'cat <<EOT >> fullchain.pem\n{base64.b64decode(RANCHER_VALID_TLS_CERT).decode("utf-8")}\nEOT'
        run_command_on_airgap_node(bastion_node, ag_node,
                                   write_cert_command)
        write_key_command = f'cat <<EOT >> privkey.pem\n{base64.b64decode(RANCHER_VALID_TLS_KEY).decode("utf-8")}\nEOT'
        run_command_on_airgap_node(bastion_node, ag_node,
                                   write_key_command)
        deploy_rancher_command = \
            'sudo docker run -d {} --restart=unless-stopped ' \
            '-p 80:80 -p 443:443 ' \
            '-v ${{PWD}}/fullchain.pem:/etc/rancher/ssl/cert.pem ' \
            '-v ${{PWD}}/privkey.pem:/etc/rancher/ssl/key.pem ' \
            '-e CATTLE_SYSTEM_DEFAULT_REGISTRY={} ' \
            '-e CATTLE_SYSTEM_CATALOG=bundled ' \
            '{}/rancher/rancher:{} --no-cacerts --trace'.format(
                privileged, bastion_node.host_name, bastion_node.host_name,
                RANCHER_SERVER_VERSION)
    else:
        deploy_rancher_command = f'sudo docker run -d {privileged} --restart=unless-stopped -p 80:80 -p 443:443 -e CATTLE_SYSTEM_DEFAULT_REGISTRY={bastion_node.host_name} -e CATTLE_SYSTEM_CATALOG=bundled {bastion_node.host_name}/rancher/rancher:{RANCHER_SERVER_VERSION} --trace'
    deploy_result = run_command_on_airgap_node(bastion_node, ag_node,
                                               deploy_rancher_command,
                                               log_out=True)
    assert (
        f"Downloaded newer image for {bastion_node.host_name}/rancher/rancher:{RANCHER_SERVER_VERSION}"
        in deploy_result[1]
    )
    return ag_node


def run_docker_command_on_airgap_node(bastion_node, ag_node, cmd,
                                      log_out=False):
    docker_login_command = f"docker login {bastion_node.host_name} -u {PRIVATE_REGISTRY_USERNAME} -p {PRIVATE_REGISTRY_PASSWORD}"
    if cmd.startswith("sudo"):
        docker_login_command = f"sudo {docker_login_command}"
    ag_command = f'ssh -i "{bastion_node.ssh_key_name}.pem" -o StrictHostKeyChecking=no {AWS_USER}@{ag_node.private_ip_address} "{docker_login_command} && {cmd}"'
    result = bastion_node.execute_command(ag_command)
    if log_out:
        print(f"Running command: {ag_command}")
        print(f"Result: {result}")
    return result


def run_command_on_airgap_node(bastion_node, ag_node, cmd, log_out=False):
    if cmd.startswith("docker") or cmd.startswith("sudo docker"):
        return run_docker_command_on_airgap_node(
            bastion_node, ag_node, cmd, log_out)
    ag_command = f'ssh -i "{bastion_node.ssh_key_name}.pem" -o StrictHostKeyChecking=no {AWS_USER}@{ag_node.private_ip_address} "{cmd}"'
    result = bastion_node.execute_command(ag_command)
    if log_out:
        print(f"Running command: {ag_command}")
        print(f"Result: {result}")
    return result


def wait_for_airgap_pods_ready(bastion_node, ag_nodes,
                               kubectl='kubectl', kubeconfig=None):
    if kubeconfig:
        node_cmd = f"{kubectl} get nodes --kubeconfig {kubeconfig}"
        command = f"{kubectl} get pods -A --kubeconfig {kubeconfig}"
    else:
        node_cmd = f"{kubectl} get nodes"
        command = f"{kubectl} get pods -A"
    start = time.time()
    wait_for_pods_to_be_ready = True
    while wait_for_pods_to_be_ready:
        unready_pods = []
        unready_nodes = []
        if time.time() - start > DEFAULT_CLUSTER_STATE_TIMEOUT:
            raise AssertionError("Timed out waiting for cluster to be ready")
        time.sleep(10)
        nodes = run_command_on_airgap_node(bastion_node, ag_nodes[0], node_cmd)
        nodes_arr = nodes[0].strip().split("\n")[1:]
        for node in nodes_arr:
            if "NotReady" in node:
                print(f"Waiting for node: {node}")
                unready_nodes.append(node)
        if unready_nodes or not nodes_arr:
            continue
        pods = run_command_on_airgap_node(bastion_node, ag_nodes[0], command)
        pods_arr = pods[0].strip().split("\n")[1:]
        for pod in pods_arr:
            if "Completed" not in pod and "Running" not in pod:
                print(f"Waiting for pod: {pod}")
                unready_pods.append(pod)
        wait_for_pods_to_be_ready = bool(unready_pods or not pods_arr)


def create_nlb_and_add_targets(aws_nodes):
    # Create internet-facing nlb and grab ARN & dns name
    lb = AmazonWebServices().create_network_lb(name=f"{AG_HOST_NAME}-nlb")
    lb_arn = lb["LoadBalancers"][0]["LoadBalancerArn"]
    public_dns = lb["LoadBalancers"][0]["DNSName"]
    # Create internal nlb and grab ARN & dns name
    internal_lb = AmazonWebServices().create_network_lb(
        name=f"{AG_HOST_NAME}-internal-nlb", scheme='internal'
    )
    internal_lb_arn = internal_lb["LoadBalancers"][0]["LoadBalancerArn"]
    internal_lb_dns = internal_lb["LoadBalancers"][0]["DNSName"]

    # Upsert the route53 record -- if it exists, update, if not, insert
    AmazonWebServices().upsert_route_53_record_cname(
        RANCHER_AG_INTERNAL_HOSTNAME, internal_lb_dns)
    if RANCHER_HA_CERT_OPTION == 'byo-valid':
        AmazonWebServices().upsert_route_53_record_cname(
            RANCHER_AG_HOSTNAME, public_dns)
        public_dns = RANCHER_AG_HOSTNAME

    # Create the target groups
    tg80 = AmazonWebServices().create_ha_target_group(
        80, f"{AG_HOST_NAME}-tg-80"
    )
    tg443 = AmazonWebServices().create_ha_target_group(
        443, f"{AG_HOST_NAME}-tg-443"
    )
    tg80_arn = tg80["TargetGroups"][0]["TargetGroupArn"]
    tg443_arn = tg443["TargetGroups"][0]["TargetGroupArn"]
    # Create the internal target groups
    internal_tg80 = AmazonWebServices().create_ha_target_group(
        80, f"{AG_HOST_NAME}-internal-tg-80"
    )
    internal_tg443 = AmazonWebServices().create_ha_target_group(
        443, f"{AG_HOST_NAME}-internal-tg-443"
    )
    internal_tg80_arn = internal_tg80["TargetGroups"][0]["TargetGroupArn"]
    internal_tg443_arn = internal_tg443["TargetGroups"][0]["TargetGroupArn"]

    # Create listeners for the load balancers, to forward to the target groups
    AmazonWebServices().create_ha_nlb_listener(
        loadBalancerARN=lb_arn, port=80, targetGroupARN=tg80_arn)
    AmazonWebServices().create_ha_nlb_listener(
        loadBalancerARN=lb_arn, port=443, targetGroupARN=tg443_arn)
    AmazonWebServices().create_ha_nlb_listener(
        loadBalancerARN=internal_lb_arn, port=80,
        targetGroupARN=internal_tg80_arn)
    AmazonWebServices().create_ha_nlb_listener(
        loadBalancerARN=internal_lb_arn, port=443,
        targetGroupARN=internal_tg443_arn)

    targets = [aws_node.provider_node_id for aws_node in aws_nodes]
    # Register the nodes to the internet-facing targets
    targets_list = [dict(Id=target_id, Port=80) for target_id in targets]
    AmazonWebServices().register_targets(targets_list, tg80_arn)
    targets_list = [dict(Id=target_id, Port=443) for target_id in targets]
    AmazonWebServices().register_targets(targets_list, tg443_arn)
    # Wait up to approx. 5 minutes for targets to begin health checks
    for _ in range(300):
        health80 = AmazonWebServices().describe_target_health(
            tg80_arn)['TargetHealthDescriptions'][0]['TargetHealth']['State']
        health443 = AmazonWebServices().describe_target_health(
            tg443_arn)['TargetHealthDescriptions'][0]['TargetHealth']['State']
        if health80 in ['initial', 'healthy'] \
                and health443 in ['initial', 'healthy']:
            break
        time.sleep(1)

    # Register the nodes to the internal targets
    targets_list = [dict(Id=target_id, Port=80) for target_id in targets]
    AmazonWebServices().register_targets(targets_list, internal_tg80_arn)
    targets_list = [dict(Id=target_id, Port=443) for target_id in targets]
    AmazonWebServices().register_targets(targets_list, internal_tg443_arn)
    # Wait up to approx. 5 minutes for targets to begin health checks
    for _ in range(300):
        try:
            health80 = AmazonWebServices().describe_target_health(
                internal_tg80_arn)[
                'TargetHealthDescriptions'][0]['TargetHealth']['State']
            health443 = AmazonWebServices().describe_target_health(
                internal_tg443_arn)[
                'TargetHealthDescriptions'][0]['TargetHealth']['State']
            if health80 in ['initial', 'healthy'] \
                    and health443 in ['initial', 'healthy']:
                break
        except Exception:
            print("Target group healthchecks unavailable...")
        time.sleep(1)

    return public_dns


def get_bastion_node(provider_id):
    bastion_node = AmazonWebServices().get_node(provider_id, ssh_access=True)
    if bastion_node is None:
        pytest.fail("Did not provide a valid Provider ID for the bastion node")
    return bastion_node


def setup_ssh_key(bastion_node):
    # Copy SSH Key to Bastion and local dir and give it proper permissions
    write_key_command = f"cat <<EOT >> {bastion_node.ssh_key_name}.pem\n{bastion_node.ssh_key}\nEOT"
    bastion_node.execute_command(write_key_command)
    local_write_key_command = f"mkdir -p {SSH_KEY_DIR} && cat <<EOT >> {SSH_KEY_DIR}/{bastion_node.ssh_key_name}.pem\n{bastion_node.ssh_key}\nEOT"
    run_command(local_write_key_command, log_out=False)

    set_key_permissions_command = f"chmod 400 {bastion_node.ssh_key_name}.pem"
    bastion_node.execute_command(set_key_permissions_command)
    local_set_key_permissions_command = (
        f"chmod 400 {SSH_KEY_DIR}/{bastion_node.ssh_key_name}.pem"
    )
    run_command(local_set_key_permissions_command, log_out=False)


@pytest.fixture()
def check_hostname_length():
    print(f"Host Name: {AG_HOST_NAME}")
    assert len(AG_HOST_NAME) < 17, "Provide hostname that is 16 chars or less"
