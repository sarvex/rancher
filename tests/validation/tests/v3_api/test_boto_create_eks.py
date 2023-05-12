import base64

from .common import run_command_with_stderr
from .test_eks_cluster import ekscredential
from .test_eks_cluster import \
    DATA_SUBDIR, EKS_ACCESS_KEY, EKS_SECRET_KEY, EKS_REGION
from .test_rke_cluster_provisioning import evaluate_clustername
from lib.aws import AmazonWebServices


@ekscredential
def test_boto_create_eks():
    cluster_name = evaluate_clustername()
    AmazonWebServices().create_eks_cluster(cluster_name)
    kc_path = get_eks_kubeconfig(cluster_name)
    out = run_command_with_stderr(f'kubectl --kubeconfig {kc_path} get svc')
    print(out)
    out = run_command_with_stderr(f'kubectl --kubeconfig {kc_path} get nodes')
    print(out)


def get_eks_kubeconfig(cluster_name):
    kubeconfig_path = f"{DATA_SUBDIR}/kube_config_hosted_eks.yml"

    exports = (
        'export AWS_ACCESS_KEY_ID={} && '
        + f'export AWS_SECRET_ACCESS_KEY={EKS_ACCESS_KEY}'
    )

    # log_out=False so we don't write the keys to the console
    run_command_with_stderr(exports, log_out=False)

    command = (
        f'aws eks --region {EKS_REGION} update-kubeconfig '
        + f'--name {cluster_name} --kubeconfig {kubeconfig_path}'
    )
    run_command_with_stderr(command)

    print("\n\nKubeconfig:")
    with open(kubeconfig_path, "r") as kubeconfig_file:
        kubeconfig_contents = kubeconfig_file.read()
    kubeconfig_contents_encoded = base64.b64encode(
        kubeconfig_contents.encode("utf-8")).decode("utf-8")
    print("\n\n" + kubeconfig_contents + "\n\n")
    print("\nBase64 encoded: \n\n" + kubeconfig_contents_encoded + "\n\n")

    return kubeconfig_path
