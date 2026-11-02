"""
RoleBinding collector (raw K8s objects only; edges are created in edges/ modules).
"""

from .base import RawCollector


class RoleBindingCollector(RawCollector):
    """Collects Kubernetes role bindings."""

    resource = "rolebindings"
    list_method = "list_role_binding_for_all_namespaces"
