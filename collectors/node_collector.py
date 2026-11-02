"""
Collector for Kubernetes Nodes (the worker machines in Kubernetes clusters).
"""

from typing import Dict, Any
from .base import BaseCollector

ROLE_LABEL = "node-role.kubernetes.io/"


class NodeCollector(BaseCollector):
    """Collects Kubernetes Node resources."""

    kind = "K8sNode"
    resource = "nodes"
    list_method = "list_node"
    namespaced = False
    exit_on_error = False

    def _properties(self, node: Any) -> Dict[str, Any]:
        status = node.status
        conditions = {c.type: c.status == "True" for c in (status.conditions if status else None) or []}
        addresses = {}
        for addr in (status.addresses if status else None) or []:
            addresses[addr.type] = addr.address

        properties = {
            "roles": [key.split("/")[1] for key in node.metadata.labels or {}
                      if key.startswith(ROLE_LABEL) and key.split("/")[1]],
            "internal_ip": addresses.get("InternalIP", ""),
            "hostname": addresses.get("Hostname", ""),
            "is_schedulable": not (node.spec and node.spec.unschedulable),
            "taints": [f"{t.key}={t.value}:{t.effect}" for t in (node.spec.taints if node.spec else None) or []],
            "ready": conditions.get("Ready", False),
            "memory_pressure": conditions.get("MemoryPressure", False),
            "disk_pressure": conditions.get("DiskPressure", False),
            "pid_pressure": conditions.get("PIDPressure", False),
            "network_unavailable": conditions.get("NetworkUnavailable", False),
        }

        node_info = status.node_info if status else None
        if node_info:
            properties.update({
                "os_image": node_info.os_image or "",
                "kernel_version": node_info.kernel_version or "",
                "container_runtime_version": node_info.container_runtime_version or "",
                "kubelet_version": node_info.kubelet_version or "",
                "kube_proxy_version": node_info.kube_proxy_version or "",
                "architecture": node_info.architecture or "",
                "operating_system": node_info.operating_system or "",
            })

        return properties
