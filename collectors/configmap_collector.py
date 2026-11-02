"""
ConfigMap collector for Kubernetes configmaps.
Collects configmap data keys and converts to BloodHound OpenGraph format.
"""

from typing import Dict, Any
from .base import BaseCollector


class ConfigMapCollector(BaseCollector):
    """Collects Kubernetes configmaps and converts them to OpenGraph nodes."""

    kind = "K8sConfigMap"
    resource = "configmaps"
    list_method = "list_config_map_for_all_namespaces"

    def _properties(self, configmap: Any) -> Dict[str, Any]:
        return {
            "data_keys": list(configmap.data or {}),
            "binary_data_keys": list(configmap.binary_data or {}),
        }
