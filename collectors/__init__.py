"""
Kubernetes resource collectors for BloodHound ingestion.
Each collector is responsible for gathering specific K8s resources and converting them to OpenGraph format.
"""

from .namespace_collector import NamespaceCollector
from .node_collector import NodeCollector
from .pod_collector import PodCollector
from .secret_collector import SecretCollector
from .configmap_collector import ConfigMapCollector
from .serviceaccount_collector import ServiceAccountCollector
from .role_collector import RoleCollector
from .clusterrole_collector import ClusterRoleCollector
from .rolebinding_collector import RoleBindingCollector
from .clusterrolebinding_collector import ClusterRoleBindingCollector
from .service_collector import ServiceCollector
from .deployment_collector import DeploymentCollector
from .daemonset_collector import DaemonSetCollector
from .statefulset_collector import StatefulSetCollector
from .ingress_collector import IngressCollector

__all__ = [
    "NamespaceCollector",
    "NodeCollector",
    "PodCollector",
    "SecretCollector",
    "ConfigMapCollector",
    "ServiceAccountCollector",
    "RoleCollector",
    "ClusterRoleCollector",
    "RoleBindingCollector",
    "ClusterRoleBindingCollector",
    "ServiceCollector",
    "DeploymentCollector",
    "DaemonSetCollector",
    "StatefulSetCollector",
    "IngressCollector",
]
