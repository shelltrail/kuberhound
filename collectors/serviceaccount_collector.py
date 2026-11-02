"""
ServiceAccount collector for Kubernetes service accounts.
"""

from typing import Dict, Any
from .base import BaseCollector


class ServiceAccountCollector(BaseCollector):
    """Collects Kubernetes service accounts and converts them to OpenGraph nodes."""

    kind = "K8sServiceAccount"
    resource = "serviceaccounts"
    list_method = "list_service_account_for_all_namespaces"

    def _properties(self, sa: Any) -> Dict[str, Any]:
        return {
            # automountServiceAccountToken defaults to true
            "automount_token": sa.automount_service_account_token is not False,
            "secret_names": [secret.name for secret in sa.secrets or []],
        }
