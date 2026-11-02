"""
Role collector for Kubernetes roles.
"""

from typing import Dict, Any
from .base import BaseCollector
from .rbac_rules import analyze_rules


class RoleCollector(BaseCollector):
    """Collects Kubernetes roles and converts them to OpenGraph nodes."""

    kind = "K8sRole"
    resource = "roles"
    list_method = "list_role_for_all_namespaces"

    def _properties(self, role: Any) -> Dict[str, Any]:
        return analyze_rules(role.rules, cluster_scoped=False)
