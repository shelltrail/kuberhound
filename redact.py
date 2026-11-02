"""
Redaction of potentially sensitive values in a KuberHound graph (--redact).

Keeps everything attack-path analysis and the saved queries rely on (names, namespaces, labels,
RBAC rules, security flags) and masks content that is not needed to find attack paths.
"""

from typing import Dict, Any

REDACTED = "<redacted>"

# Node kind -> properties whose values are masked
NODE_PROPERTIES = {
    "K8sSecret": ["data_keys"],
    "K8sConfigMap": ["data_keys", "binary_data_keys"],
    "K8sNode": ["internal_ip", "hostname"],
    "K8sService": ["cluster_ip", "external_ips"],
    "K8sIngress": ["hosts", "tls_hosts"],
}

# Edge kind -> properties whose values are masked
EDGE_PROPERTIES = {
    "ROUTES_TO": ["host"],
}


def _mask(value: Any) -> Any:
    """Mask a string or each item of a list, keeping empty values and list lengths."""
    if isinstance(value, list):
        return [REDACTED for _ in value]
    if isinstance(value, str) and value:
        return REDACTED
    return value


def _mask_properties(properties: Dict[str, Any], keys) -> None:
    for key in keys:
        if key in properties:
            properties[key] = _mask(properties[key])


def redact_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask potentially sensitive values in place:
    - annotation values on every node (they can embed full manifests, e.g. ConfigMap data in
      kubectl's last-applied-configuration); annotation keys are kept
    - Secret and ConfigMap key names
    - Node IPs and hostnames, Service IPs, Ingress hosts

    Returns:
        The same graph, for chaining
    """
    for node in graph["graph"]["nodes"]:
        properties = node["properties"]
        if "annotations" in properties:
            properties["annotations"] = [f"{a.split('=', 1)[0]}={REDACTED}" for a in properties["annotations"]]
        _mask_properties(properties, NODE_PROPERTIES.get(node["kinds"][0], []))

    for edge in graph["graph"]["edges"]:
        _mask_properties(edge.get("properties", {}), EDGE_PROPERTIES.get(edge["kind"], []))

    return graph
