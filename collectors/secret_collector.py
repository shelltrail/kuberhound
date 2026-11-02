"""
Secret collector for Kubernetes secrets.
Collects secret metadata (NOT the actual secret data) and converts to BloodHound OpenGraph format.
"""

from typing import Dict, Any
from .base import BaseCollector

# kubectl apply stores the full applied manifest here, including the secret's data
LAST_APPLIED_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"


class SecretCollector(BaseCollector):
    """Collects Kubernetes secrets and converts them to OpenGraph nodes."""

    kind = "K8sSecret"
    resource = "secrets"
    list_method = "list_secret_for_all_namespaces"

    def _trim(self, secret: Any) -> Any:
        # The API returns secret values; keep only the key names so values never linger in memory
        if secret.data:
            secret.data = dict.fromkeys(secret.data, "")
        annotations = secret.metadata.annotations
        if annotations and LAST_APPLIED_ANNOTATION in annotations:
            secret.metadata.annotations = {k: v for k, v in annotations.items() if k != LAST_APPLIED_ANNOTATION}
        return secret

    def _properties(self, secret: Any) -> Dict[str, Any]:
        return {
            "secret_type": secret.type or "Opaque",
            "data_keys": list(secret.data or {}),  # Only keys, not values
        }
