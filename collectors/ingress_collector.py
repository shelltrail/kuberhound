"""
Ingress collector for Kubernetes ingresses (nodes only).
"""

from typing import Dict, Any
from .base import BaseCollector


class IngressCollector(BaseCollector):
    """Collects Kubernetes ingresses and converts them to OpenGraph nodes."""

    kind = "K8sIngress"
    resource = "ingresses"
    list_method = "list_ingress_for_all_namespaces"

    def _properties(self, ingress: Any) -> Dict[str, Any]:
        spec = ingress.spec
        return {
            "ingress_class": spec.ingress_class_name if spec and spec.ingress_class_name else "",
            "hosts": [rule.host for rule in (spec.rules if spec else None) or [] if rule.host],
            "tls_hosts": [host for tls in (spec.tls if spec else None) or [] for host in tls.hosts or []],
        }
