"""
RBAC rule analysis shared by the Role and ClusterRole collectors.
"""

from typing import List, Dict, Any

# Resources whose controllers create pods (pod templates go through the same PSA admission)
WORKLOAD_RESOURCES = {
    "deployments", "daemonsets", "statefulsets", "replicasets",
    "replicationcontrollers", "jobs", "cronjobs",
}

# (capability, resources, verbs, cluster_only) - a rule granting any listed verb on any listed
# resource enables the attack capability. Order defines the order of attack_capabilities.
CAPABILITY_RULES = [
    ("POD_EXEC", {"pods/exec"}, {"create", "*"}, False),
    ("POD_PATCH", {"pods"}, {"patch", "update", "*"}, False),
    ("POD_CREATE", {"pods", "*"}, {"create", "*"}, False),
    # Workload controllers create pods on the caller's behalf, subject to the same PSA checks
    ("WORKLOAD_CREATE", WORKLOAD_RESOURCES | {"*"}, {"create", "update", "patch", "*"}, False),
    ("POD_EPHEMERAL_PATCH", {"pods/ephemeralcontainers"}, {"patch", "update", "*"}, False),
    ("TOKEN_LIST", {"secrets"}, {"list", "get", "watch", "*"}, False),
    ("TOKEN_CREATE", {"serviceaccounts/token"}, {"create", "*"}, False),
    ("IDENTITY_IMPERSONATE", {"users", "groups", "serviceaccounts"}, {"impersonate", "*"}, False),
    ("ROLE_BIND", {"rolebindings", "clusterrolebindings"}, {"create", "update", "patch", "*"}, False),
    # GET is enough: kubelet exec/attach over WebSocket arrives as a GET request
    ("NODE_PROXY", {"nodes/proxy", "*"}, {"get", "create", "*"}, True),
    ("SECRET_CREATE", {"secrets"}, {"create", "*"}, False),
    ("SECRET_UPDATE", {"secrets"}, {"update", "*"}, False),
    ("SECRET_PATCH", {"secrets"}, {"patch", "*"}, False),
    ("CONFIGMAP_CREATE", {"configmaps"}, {"create", "*"}, False),
    ("CONFIGMAP_UPDATE", {"configmaps"}, {"update", "*"}, False),
    ("CONFIGMAP_PATCH", {"configmaps"}, {"patch", "*"}, False),
]

RBAC_RESOURCES = {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
RBAC_WRITE_VERBS = {"create", "update", "patch", "delete", "escalate", "bind"}


def is_dangerous_permission(resource: str, verb: str, cluster_scoped: bool) -> bool:
    """
    Determine if a permission is considered dangerous.

    Args:
        resource: Resource type
        verb: Verb (get, list, create, etc.)
        cluster_scoped: Whether the rule belongs to a ClusterRole

    Returns:
        True if permission is dangerous
    """
    return (
        verb == "*" or resource == "*"
        or (resource == "secrets" and verb in {"get", "list", "watch"})
        or (resource == "pods" and verb in {"create", "delete", "deletecollection"})
        or resource == "pods/exec"
        or (resource in RBAC_RESOURCES and verb in RBAC_WRITE_VERBS)
        or (resource == "serviceaccounts/token" and verb == "create")
        # Kubelet API access (exec into any pod on the node)
        or (cluster_scoped and resource == "nodes/proxy")
        # PersistentVolumes (can access data)
        or (cluster_scoped and resource == "persistentvolumes" and verb in {"get", "list", "watch", "create"})
    )


def analyze_rules(rules: List[Any], cluster_scoped: bool) -> Dict[str, List[str]]:
    """
    Flatten RBAC rules and detect dangerous permissions and attack capabilities.

    Args:
        rules: List of V1PolicyRule objects (may be None)
        cluster_scoped: Whether the rules belong to a ClusterRole

    Returns:
        Dict with "rules", "dangerous_permissions" and "attack_capabilities" lists
    """
    rule_strs = []
    dangerous_permissions = []
    attack_capabilities = {}  # Ordered set
    capability_rules = [c for c in CAPABILITY_RULES if cluster_scoped or not c[3]]

    for rule in rules or []:
        verbs = rule.verbs or []
        names_suffix = f":{','.join(rule.resource_names)}" if rule.resource_names else ""

        for api_group in rule.api_groups or [""]:
            for resource in rule.resources or []:
                for verb in verbs:
                    rule_str = f"{verb}:{api_group}:{resource}{names_suffix}"
                    rule_strs.append(rule_str)

                    if is_dangerous_permission(resource, verb, cluster_scoped):
                        dangerous_permissions.append(rule_str)

                    for capability, cap_resources, cap_verbs, _ in capability_rules:
                        if resource in cap_resources and verb in cap_verbs:
                            attack_capabilities[capability] = None

        # Non-resource URLs (only valid in ClusterRoles)
        for url in rule.non_resource_urls or []:
            for verb in verbs:
                rule_strs.append(f"{verb}::{url}")

    return {
        "rules": rule_strs,
        "dangerous_permissions": dangerous_permissions,
        "attack_capabilities": list(attack_capabilities),
    }
