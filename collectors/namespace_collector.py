"""
Namespace collector for Kubernetes namespaces.
"""

from typing import Dict, Any
from .base import BaseCollector

PSA_LABEL = "pod-security.kubernetes.io/"


class NamespaceCollector(BaseCollector):
    """Collects Kubernetes namespaces and converts them to OpenGraph nodes."""

    kind = "K8sNamespace"
    resource = "namespaces"
    list_method = "list_namespace"
    namespaced = False

    def __init__(self, k8s_client, default_psa: str = "privileged"):
        """
        Args:
            k8s_client: Kubernetes CoreV1Api client instance
            default_psa: Cluster-wide PSA enforce level applied to namespaces without an
                         enforce label (Kubernetes default is "privileged"; clusters can change it
                         in the API server's AdmissionConfiguration, which is not visible via the API)
        """
        super().__init__(k8s_client)
        self.default_psa = default_psa

    def _properties(self, namespace: Any) -> Dict[str, Any]:
        labels = namespace.metadata.labels or {}
        name = namespace.metadata.name.lower()

        # Pod Security Admission (PSA) levels. The effective enforce level decides whether
        # dangerous pods are admitted:
        # "privileged" - allows everything: privileged containers, hostPath, hostPID/hostNetwork
        # "baseline"   - blocks privileged containers, hostPath volumes, host namespaces and
        #                dangerous capabilities, so no host escape via pod creation
        # "restricted" - baseline plus further hardening
        # "" (not set) - the cluster-wide default applies (Kubernetes default: privileged)
        psa_enforce = labels.get(PSA_LABEL + "enforce", "")
        psa_effective = psa_enforce or self.default_psa

        return {
            "status": namespace.status.phase if namespace.status and namespace.status.phase else "Unknown",
            "psa_enforce": psa_enforce,
            "psa_audit": labels.get(PSA_LABEL + "audit", ""),
            "psa_warn": labels.get(PSA_LABEL + "warn", ""),
            "psa_configured": PSA_LABEL + "enforce" in labels,
            "psa_effective": psa_effective,
            "allows_dangerous_pods": psa_effective == "privileged",
            "has_argocd_keyword": "argocd" in name,
            "has_fluentd_keyword": "fluentd" in name,
        }
