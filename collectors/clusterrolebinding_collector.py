"""
ClusterRoleBinding collector (raw K8s objects only; edges are created in edges/ modules).
"""

from .base import RawCollector


class ClusterRoleBindingCollector(RawCollector):
    """Collects Kubernetes cluster role bindings."""

    resource = "clusterrolebindings"
    list_method = "list_cluster_role_binding"
