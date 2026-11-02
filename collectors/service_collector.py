"""
Service collector for Kubernetes services (nodes only).
"""

from typing import Dict, Any
from .base import BaseCollector, kv_list


class ServiceCollector(BaseCollector):
    """Collects Kubernetes services and converts them to OpenGraph nodes."""

    kind = "K8sService"
    resource = "services"
    list_method = "list_service_for_all_namespaces"

    def _properties(self, service: Any) -> Dict[str, Any]:
        spec = service.spec
        ports = []
        for port in (spec.ports if spec else None) or []:
            port_info = f"{port.name}:{port.port}" if port.name else f"{port.port}"
            if port.protocol:
                port_info = f"{port_info}/{port.protocol}"
            ports.append(port_info)

        return {
            "service_type": spec.type if spec and spec.type else "ClusterIP",
            "cluster_ip": spec.cluster_ip if spec and spec.cluster_ip else "",
            "external_ips": (spec.external_ips if spec else None) or [],
            "ports": ports,
            "selector": kv_list(spec.selector if spec else None),
        }
