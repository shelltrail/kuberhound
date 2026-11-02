"""
Edge classification system for differentiating attack paths from informational relationships.
"""

from functools import lru_cache
from typing import Set

# Direct attack/exploitation edges
ATTACK_EDGES: Set[str] = {
    # Container escape edges
    "CE_PRIV_MOUNT",
    "CE_NSENTER",
    "CE_SYS_PTRACE",
    "CE_MODULE_LOAD",
    "EXPLOIT_HOST_WRITE",
    "EXPLOIT_HOST_READ",

    # Identity and privilege escalation
    "IDENTITY_ASSUME",
    "CAN_ESCALATE_VIA_POD",
    "CAN_ESCALATE_VIA_ARGOCD_SECRET",
    "CAN_ESCALATE_VIA_FLUENTD_CONFIG",
    "CAN_EXEC_VIA_NODE_PROXY",

    # RBAC privilege escalation (edges/privesc_edges.py)
    "CAN_EXEC_PODS",
    "CAN_ATTACH_PODS",
    "CAN_DEBUG_PODS",
    "CAN_RUN_POD_AS",
    "CAN_CREATE_TOKEN",
    "CAN_PLANT_TOKEN_SECRET",
    "CAN_IMPERSONATE",
    "CAN_BIND",
    "CAN_ESCALATE",
    "CONTAINS_TOKEN",
}

# Permission edges (RBAC capabilities)
PERMISSION_EDGES: Set[str] = {
    "BOUND_TO",
}

# Permission edges that are security-critical
CRITICAL_PERMISSION_PATTERNS: Set[str] = {
    "CAN_LIST_SECRETS",
    "CAN_WATCH_SECRETS",
    "CAN_GET_SECRETS",
    "CAN_CREATE_SECRETS",
    "CAN_UPDATE_SECRETS",
    "CAN_PATCH_SECRETS",
    "CAN_DELETE_SECRETS",

    "CAN_CREATE_PODS",
    "CAN_UPDATE_PODS",
    "CAN_PATCH_PODS",
    "CAN_DELETE_PODS",
    "CAN_PORTFORWARD_PODS",

    "CAN_CREATE_ROLES",
    "CAN_UPDATE_ROLES",
    "CAN_PATCH_ROLES",
    "CAN_CREATE_CLUSTERROLES",
    "CAN_UPDATE_CLUSTERROLES",
    "CAN_PATCH_CLUSTERROLES",

    "CAN_CREATE_ROLEBINDINGS",
    "CAN_UPDATE_ROLEBINDINGS",
    "CAN_PATCH_ROLEBINDINGS",
    "CAN_CREATE_CLUSTERROLEBINDINGS",
    "CAN_UPDATE_CLUSTERROLEBINDINGS",
    "CAN_PATCH_CLUSTERROLEBINDINGS",

    "CAN_CREATE_SERVICEACCOUNTS",
    "CAN_UPDATE_SERVICEACCOUNTS",
    "CAN_PATCH_SERVICEACCOUNTS",

    # Node access (relabeling/tainting a node can steer workloads onto it)
    "CAN_UPDATE_NODES",
    "CAN_PATCH_NODES",
}

# Informational permission patterns (less critical)
INFORMATIONAL_PERMISSION_PATTERNS: Set[str] = {
    "CAN_LIST_PODS",
    "CAN_WATCH_PODS",
    "CAN_GET_PODS",

    "CAN_LIST_SERVICES",
    "CAN_WATCH_SERVICES",
    "CAN_GET_SERVICES",

    "CAN_LIST_DEPLOYMENTS",
    "CAN_WATCH_DEPLOYMENTS",
    "CAN_GET_DEPLOYMENTS",

    "CAN_LIST_CONFIGMAPS",
    "CAN_WATCH_CONFIGMAPS",
    "CAN_GET_CONFIGMAPS",

    "CAN_LIST_NAMESPACES",
    "CAN_WATCH_NAMESPACES",
    "CAN_GET_NAMESPACES",

    # Reading Node objects is reconnaissance only
    "CAN_LIST_NODES",
    "CAN_WATCH_NODES",
    "CAN_GET_NODES",
}

# Structural/relationship edges (purely informational)
STRUCTURAL_EDGES: Set[str] = {
    "IN_NAMESPACE",
    "HOSTS_POD",
    "USES_SERVICEACCOUNT",
    "USES_SECRET",
    "USES_CONFIGMAP",
    "EXPOSES",
    "MANAGES",
    "ROUTES_TO",
}


@lru_cache(maxsize=None)
def classify_edge(edge_kind: str) -> str:
    """
    Classify an edge by its kind/type.

    Args:
        edge_kind: Edge type (e.g., "CE_PRIV_MOUNT", "CAN_LIST_SECRETS", "USES_SECRET")

    Returns:
        Category string: "attack", "permission", "permission_critical", "permission_informational", or "structural"
    """
    if edge_kind in ATTACK_EDGES:
        return "attack"

    if edge_kind in PERMISSION_EDGES:
        return "permission"

    if edge_kind in CRITICAL_PERMISSION_PATTERNS:
        return "permission_critical"

    if edge_kind in INFORMATIONAL_PERMISSION_PATTERNS:
        return "permission_informational"

    if edge_kind in STRUCTURAL_EDGES:
        return "structural"

    # Default classification for dynamic CAN_* edges
    if edge_kind.startswith("CAN_"):
        # Heuristic: create/update/patch/delete are critical, list/watch/get are informational
        verb = edge_kind.split("_")[1] if "_" in edge_kind else ""
        if verb in ["CREATE", "UPDATE", "PATCH", "DELETE"]:
            return "permission_critical"
        else:
            return "permission_informational"

    # Unknown edge type - default to informational
    return "structural"
