"""
ClusterRole collector for Kubernetes cluster roles.
"""

from typing import Dict, Any
from .base import BaseCollector
from .rbac_rules import analyze_rules


class ClusterRoleCollector(BaseCollector):
    """Collects Kubernetes cluster roles and converts them to OpenGraph nodes."""

    kind = "K8sClusterRole"
    resource = "clusterroles"
    list_method = "list_cluster_role"
    namespaced = False

    def _properties(self, clusterrole: Any) -> Dict[str, Any]:
        return analyze_rules(clusterrole.rules, cluster_scoped=True)
