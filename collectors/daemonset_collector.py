"""
DaemonSet collector for Kubernetes daemonsets (nodes only).
"""

from typing import Dict, Any
from .base import BaseCollector, template_service_account, match_labels


class DaemonSetCollector(BaseCollector):
    """Collects Kubernetes daemonsets and converts them to OpenGraph nodes."""

    kind = "K8sDaemonSet"
    resource = "daemonsets"
    list_method = "list_daemon_set_for_all_namespaces"

    def _properties(self, daemonset: Any) -> Dict[str, Any]:
        return {
            "service_account": template_service_account(daemonset),
            "selector": match_labels(daemonset),
        }
