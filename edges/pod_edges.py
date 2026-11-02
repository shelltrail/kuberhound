"""
Pod relationship edges.
Creates edges for Pod relationships to Namespaces, Nodes, ServiceAccounts, Secrets, and ConfigMaps.
"""

from typing import List, Dict, Any, Tuple, Callable
from .edge_categories import classify_edge


def create_pod_relationship_edges(pods_raw: List[Any]) -> Tuple[List[Dict[str, Any]], Dict[str, set]]:
    """
    Create all Pod relationship edges (non-attack edges).

    Edges created:
    - IN_NAMESPACE: Pod → Namespace
    - HOSTS_POD: Node → Pod
    - USES_SERVICEACCOUNT: Pod → ServiceAccount
    - USES_SECRET: Pod → Secret
    - USES_CONFIGMAP: Pod → ConfigMap

    Args:
        pods_raw: List of V1Pod objects (raw Kubernetes objects)

    Returns:
        Tuple of (edges, referenced_resources) where:
        - edges: List of edge dictionaries with placeholder IDs
        - referenced_resources: Dict with 'secrets' and 'configmaps' sets of "namespace:name"
          strings referenced by pods (used to detect missing resources)
    """
    edges = []
    referenced = {"secrets": set(), "configmaps": set()}

    for pod in pods_raw:
        uid = pod.metadata.uid
        namespace = pod.metadata.namespace

        edges.append(_edge(uid, f"namespace:{namespace}", "IN_NAMESPACE"))

        if not pod.spec:
            continue

        if pod.spec.node_name:
            edges.append(_edge(f"node:{pod.spec.node_name}", uid, "HOSTS_POD"))

        sa_name = pod.spec.service_account_name or "default"
        edges.append(_edge(uid, f"serviceaccount:{namespace}:{sa_name}", "USES_SERVICEACCOUNT"))

        for name, optional in _secret_references(pod).items():
            referenced["secrets"].add(f"{namespace}:{name}")
            edges.append(_edge(uid, f"secret:{namespace}:{name}", "USES_SECRET", {"optional": optional}))

        for name, optional in _configmap_references(pod).items():
            referenced["configmaps"].add(f"{namespace}:{name}")
            edges.append(_edge(uid, f"configmap:{namespace}:{name}", "USES_CONFIGMAP", {"optional": optional}))

    return edges, referenced


def _edge(start: str, end: str, kind: str, properties: Dict[str, Any] = None) -> Dict[str, Any]:
    """Build an edge; namespace:/node:/serviceaccount:/secret:/configmap: placeholders are resolved later."""
    return {
        "start": {"value": start},
        "end": {"value": end},
        "kind": kind,
        "properties": {"edge_category": classify_edge(kind), **(properties or {})}
    }


def _collect_references(pod: Any, volume_ref: Callable, env_ref: Callable, env_from_ref: Callable) -> Dict[str, bool]:
    """
    Collect the Secret/ConfigMap names a pod references via volumes, env valueFrom and envFrom.

    Each *_ref callable returns (name, optional) for a matching reference, or None.

    Returns:
        name -> optional; a name is optional only if every reference to it is
    """
    references = {}

    def add(ref):
        if ref:
            name, optional = ref
            references[name] = references.get(name, True) and bool(optional)

    for volume in pod.spec.volumes or []:
        add(volume_ref(volume))

    for container in pod.spec.containers or []:
        for env_var in container.env or []:
            if env_var.value_from:
                add(env_ref(env_var.value_from))
        for env_from in container.env_from or []:
            add(env_from_ref(env_from))

    return references


def _secret_references(pod: Any) -> Dict[str, bool]:
    return _collect_references(
        pod,
        lambda v: v.secret and (v.secret.secret_name, v.secret.optional),
        lambda vf: vf.secret_key_ref and (vf.secret_key_ref.name, vf.secret_key_ref.optional),
        lambda ef: ef.secret_ref and (ef.secret_ref.name, ef.secret_ref.optional),
    )


def _configmap_references(pod: Any) -> Dict[str, bool]:
    return _collect_references(
        pod,
        lambda v: v.config_map and (v.config_map.name, v.config_map.optional),
        lambda vf: vf.config_map_key_ref and (vf.config_map_key_ref.name, vf.config_map_key_ref.optional),
        lambda ef: ef.config_map_ref and (ef.config_map_ref.name, ef.config_map_ref.optional),
    )
