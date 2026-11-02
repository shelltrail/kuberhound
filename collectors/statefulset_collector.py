"""
StatefulSet collector for Kubernetes statefulsets (nodes only).
"""

from typing import Dict, Any
from .base import BaseCollector, template_service_account, match_labels


class StatefulSetCollector(BaseCollector):
    """Collects Kubernetes statefulsets and converts them to OpenGraph nodes."""

    kind = "K8sStatefulSet"
    resource = "statefulsets"
    list_method = "list_stateful_set_for_all_namespaces"

    def _properties(self, statefulset: Any) -> Dict[str, Any]:
        spec = statefulset.spec
        return {
            "replicas": spec.replicas if spec and spec.replicas else 1,
            "service_account": template_service_account(statefulset),
            "service_name": spec.service_name if spec and spec.service_name else "",
            "selector": match_labels(statefulset),
        }
