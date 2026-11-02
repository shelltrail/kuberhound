"""
Shared base for Kubernetes resource collectors.
Handles paginated listing, API errors and the metadata properties common to every node.
"""

import sys
from typing import List, Dict, Any, Optional
from kubernetes.client.exceptions import ApiException

# Items per list request; large clusters are fetched in pages instead of one huge response
PAGE_SIZE = 500


def kv_list(mapping: Optional[Dict[str, str]]) -> List[str]:
    """Convert a dict (labels, annotations, selectors) to an array of "key=value" strings."""
    return [f"{k}={v}" for k, v in (mapping or {}).items()]


def template_service_account(obj: Any) -> str:
    """Service account used by the pod template of a workload controller."""
    template = obj.spec.template if obj.spec else None
    if template and template.spec and template.spec.service_account_name:
        return template.spec.service_account_name
    return "default"


def match_labels(obj: Any) -> List[str]:
    """Pod selector (matchLabels) of a workload controller as "key=value" strings."""
    if obj.spec and obj.spec.selector:
        return kv_list(obj.spec.selector.match_labels)
    return []


class BaseCollector:
    """
    Collects one Kubernetes resource type and converts it to OpenGraph nodes.

    Subclasses set the class attributes and implement _properties() for type-specific properties.
    """

    kind = ""              # BloodHound node kind, e.g. "K8sPod"
    resource = ""          # Plural resource name used in messages, e.g. "pods"
    list_method = ""       # API client method listing the resource across all namespaces
    namespaced = True      # Cluster-scoped nodes have no "namespace" property
    exit_on_error = True   # Abort the run if the resource cannot be listed

    def __init__(self, api_client):
        """
        Args:
            api_client: Kubernetes API client instance exposing list_method
        """
        self.api_client = api_client

    def collect(self) -> List[Any]:
        """
        Collect all objects of this resource type from the cluster.

        Returns:
            List of Kubernetes API objects

        Raises:
            SystemExit: If the API call fails and exit_on_error is set
        """
        list_fn = getattr(self.api_client, self.list_method)
        items = []
        continue_token = None
        try:
            while True:
                response = list_fn(limit=PAGE_SIZE, _continue=continue_token)
                items.extend(self._trim(item) for item in response.items)
                continue_token = response.metadata._continue
                if not continue_token:
                    break
        except ApiException as e:
            if e.status == 403:
                print(f"Error: Permission denied. You need ClusterRole with 'get' and 'list' verbs on '{self.resource}' resources.")
            else:
                print(f"Error calling Kubernetes API: {e}")
            if self.exit_on_error:
                sys.exit(1)
            return []

        print(f"Successfully retrieved {len(items)} {self.resource}")
        return items

    def to_nodes(self, items: List[Any]) -> List[Dict[str, Any]]:
        """Convert Kubernetes API objects to BloodHound OpenGraph nodes."""
        return [self._to_node(item) for item in items]

    def _to_node(self, obj: Any) -> Dict[str, Any]:
        meta = obj.metadata
        properties = {"name": meta.name}
        if self.namespaced:
            properties["namespace"] = meta.namespace
        properties.update({
            "creation_timestamp": meta.creation_timestamp.isoformat() if meta.creation_timestamp else "",
            "labels": kv_list(meta.labels),
            "annotations": kv_list(meta.annotations),
            "resource_version": meta.resource_version or "",
        })
        properties.update(self._properties(obj))
        return {"id": meta.uid, "kinds": [self.kind], "properties": properties}

    def _properties(self, obj: Any) -> Dict[str, Any]:
        """Type-specific node properties."""
        return {}

    def _trim(self, obj: Any) -> Any:
        """Drop data from a fetched object that is never used (applied per page while listing)."""
        return obj


class RawCollector(BaseCollector):
    """Collector for resources that only feed edge creation and produce no nodes."""

    def to_nodes(self, items: List[Any]) -> List[Dict[str, Any]]:
        return []
