"""
Pod collector for Kubernetes pods.
Collects pod data and converts to BloodHound OpenGraph format (nodes only).
Edge creation is handled separately in edges/ modules.
"""

from typing import Dict, Any
from .base import BaseCollector

# Added Linux capabilities that enable host escape, privilege escalation or network attacks
DANGEROUS_CAPABILITIES = {
    "ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
    "DAC_READ_SEARCH", "DAC_OVERRIDE", "NET_ADMIN", "NET_RAW", "BPF", "PERFMON",
    "MAC_ADMIN", "MAC_OVERRIDE", "SYSLOG",
}

# hostPath mounts that allow host compromise
DANGEROUS_HOST_PATHS = {
    "/", "/etc", "/root", "/var/run/docker.sock", "/var/run/containerd/containerd.sock",
    "/var/lib/kubelet", "/var/lib/kubelet/pki", "/etc/kubernetes", "/var/log",
}


class PodCollector(BaseCollector):
    """Collects Kubernetes pods and converts them to OpenGraph nodes."""

    kind = "K8sPod"
    resource = "pods"
    list_method = "list_pod_for_all_namespaces"

    def _properties(self, pod: Any) -> Dict[str, Any]:
        spec = pod.spec
        containers = (spec.containers if spec else None) or []
        container_images = [c.image for c in containers if c.image]
        security_contexts = [c.security_context for c in containers if c.security_context]

        # Added capabilities across all containers, de-duplicated in first-seen order
        capabilities = list(dict.fromkeys(
            cap
            for sc in security_contexts if sc.capabilities and sc.capabilities.add
            for cap in sc.capabilities.add
        ))
        normalized_caps = {cap.upper().removeprefix("CAP_") for cap in capabilities}

        host_paths = [v.host_path.path for v in (spec.volumes if spec else None) or [] if v.host_path]

        return {
            "status": pod.status.phase if pod.status and pod.status.phase else "Unknown",
            "node_name": spec.node_name if spec and spec.node_name else "",
            "service_account": spec.service_account_name if spec and spec.service_account_name else "default",
            "container_names": [c.name for c in containers],
            "container_images": container_images,
            "has_argocd_image": any("argocd" in image.lower() for image in container_images),
            "has_fluentd_image": any("fluentd" in image.lower() or "fluent-bit" in image.lower()
                                     for image in container_images),
            "host_network": bool(spec and spec.host_network),
            "host_pid": bool(spec and spec.host_pid),
            "host_ipc": bool(spec and spec.host_ipc),
            "privileged": any(sc.privileged for sc in security_contexts),
            "capabilities": capabilities,
            "dangerous_capabilities": sorted(normalized_caps & DANGEROUS_CAPABILITIES),
            "has_host_path": bool(host_paths),
            "dangerous_host_paths": [path for path in host_paths if path in DANGEROUS_HOST_PATHS],
        }
