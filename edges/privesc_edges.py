"""
RBAC privilege escalation edges.

Turns permissions that let a subject act as another identity, or reach into a pod, into edges from the
Role/ClusterRole granting them to the target, so BloodHound pathfinding can follow them:

- CAN_EXEC_PODS, CAN_ATTACH_PODS, CAN_DEBUG_PODS, CAN_PORTFORWARD_PODS: Role → Pod
- CAN_RUN_POD_AS: Role → ServiceAccount (create a pod or workload that runs as it, or patch a workload)
- CAN_CREATE_TOKEN: Role → ServiceAccount (TokenRequest API)
- CAN_PLANT_TOKEN_SECRET: Role → ServiceAccount (create a service-account-token Secret and read it)
- CAN_IMPERSONATE: Role → ServiceAccount/User/Group
- CAN_BIND: Role → Role/ClusterRole it can bind to anyone (bind verb plus write access to bindings)
- CAN_ESCALATE: Role → Role/ClusterRole it can rewrite with any permission (escalate verb plus update)
- CONTAINS_TOKEN: Secret → ServiceAccount (legacy service-account-token Secrets)
"""

from typing import List, Dict, Any, Optional
from .edge_categories import classify_edge
from .rbac_edges import ClusterRoleBindingMaps, iter_role_scopes
from .generic_rbac_edges import RESOURCE_API_GROUPS, apply_resource_names

WRITE_VERBS = {"update", "patch"}

# Pod subresources that give a shell, a debug container or network access inside a pod:
# (edge kind, subresource, verbs, description)
POD_ACCESS = [
    ("CAN_EXEC_PODS", "pods/exec", {"create"}, "can exec into the pod's containers"),
    ("CAN_ATTACH_PODS", "pods/attach", {"create"}, "can attach to the pod's running containers"),
    ("CAN_DEBUG_PODS", "pods/ephemeralcontainers", WRITE_VERBS,
     "can add an ephemeral (debug) container to the pod, sharing its service account and volumes"),
    ("CAN_PORTFORWARD_PODS", "pods/portforward", {"create"}, "can port-forward to the pod's ports"),
]

# Workloads whose pod template sets serviceAccountName (a Job's template is immutable after creation)
POD_TEMPLATE_RESOURCES = ["deployments", "daemonsets", "statefulsets", "replicasets",
                          "replicationcontrollers", "jobs", "cronjobs"]
MUTABLE_POD_TEMPLATE_RESOURCES = [r for r in POD_TEMPLATE_RESOURCES if r != "jobs"]

DESCRIPTIONS = {
    "CAN_RUN_POD_AS": "can run a pod as this ServiceAccount and read its token from inside the pod",
    "CAN_CREATE_TOKEN": "can request a token for this ServiceAccount (serviceaccounts/token)",
    "CAN_PLANT_TOKEN_SECRET": "can create a kubernetes.io/service-account-token Secret for this ServiceAccount "
                              "and read the token the cluster writes into it",
    "CAN_IMPERSONATE": "can impersonate this identity (kubectl --as / --as-group)",
    "CAN_BIND": "can bind this role to any subject, including itself (bind verb plus binding write access)",
    "CAN_ESCALATE": "can add any permission to this role (escalate verb plus update access)",
}


def _grants(rule: Any, resource: str, verbs: set) -> bool:
    """True if the rule grants any of the verbs on the resource or subresource (e.g. "pods/exec")."""
    groups = rule.api_groups or [""]
    base, _, subresource = resource.partition("/")
    if "*" not in groups and RESOURCE_API_GROUPS[base] not in groups:
        return False

    # Like the RBAC authorizer: "*" matches everything, "*/exec" matches the exec subresource of any resource
    resources = rule.resources or []
    if not (resource in resources or "*" in resources or (subresource and f"*/{subresource}" in resources)):
        return False

    rule_verbs = rule.verbs or []
    return "*" in rule_verbs or not verbs.isdisjoint(rule_verbs)


def _granted_targets(rules: List[Any], resource: str, verbs: set, nodes: List[Dict]) -> List[Dict]:
    """
    The nodes a role can act on with any of the verbs, honoring resourceNames.

    All these requests name their object (subresources like pods/exec name the pod), so resourceNames
    limit them to the named objects.
    """
    targets = {}
    for rule in rules:
        if _grants(rule, resource, verbs):
            for node in apply_resource_names(nodes, rule, "get")[0]:
                targets[node["id"]] = node
    return list(targets.values())


def _in_scope(nodes: List[Dict], namespace: Optional[str]) -> List[Dict]:
    """Namespaced nodes reachable in a scope (namespace None = cluster-wide)."""
    if namespace is None:
        return nodes
    return [node for node in nodes if node["properties"].get("namespace") == namespace]


def _can_create(rules: List[Any], resource: str) -> bool:
    """True if a rule grants create on the resource; create carries no name, so resourceNames without "" forbid it."""
    return any(_grants(rule, resource, {"create"}) and (not rule.resource_names or "" in rule.resource_names)
               for rule in rules)


def _can_read_planted_secret(rules: List[Any], namespace: str, existing: set) -> bool:
    """
    True if a role can read back a Secret it plants in the namespace: unrestricted get/list, or a get
    limited by resourceNames to a name that no Secret uses yet (so it can plant under that name).
    """
    for rule in rules:
        if not _grants(rule, "secrets", {"get", "list"}):
            continue
        names = rule.resource_names or []
        if not names or ("" in names and _grants(rule, "secrets", {"list"})):
            return True
        if any(name and (namespace, name) not in existing for name in names):
            return True
    return False


def _run_pod_as_via(rules: List[Any]) -> List[str]:
    """How a role can get a pod running under a ServiceAccount of its choice, e.g. ["create pods"]."""
    via = [f"create {resource}" for resource in ["pods"] + POD_TEMPLATE_RESOURCES if _can_create(rules, resource)]
    # Only unrestricted update/patch: a named workload might not exist
    via += [f"update {resource}" for resource in MUTABLE_POD_TEMPLATE_RESOURCES
            if any(_grants(rule, resource, WRITE_VERBS) and not rule.resource_names for rule in rules)]
    return via


def _scope_edges(rules: List[Any], namespace: Optional[str], nodes: Dict[str, List[Dict]]) -> Dict[tuple, List[str]]:
    """(edge kind, target node ID) -> details ("via") for every escalation one role scope grants."""
    found = {}

    def add(kind, targets, via=()):
        for target in targets:
            found.setdefault((kind, target["id"]), []).extend(via)

    pods = _in_scope(nodes["pods"], namespace)
    service_accounts = _in_scope(nodes["serviceaccounts"], namespace)
    roles = _in_scope(nodes["roles"], namespace)

    for kind, subresource, verbs, _ in POD_ACCESS:
        add(kind, _granted_targets(rules, subresource, verbs, pods))

    via = _run_pod_as_via(rules)
    if via:
        add("CAN_RUN_POD_AS", service_accounts, via)

    add("CAN_CREATE_TOKEN", _granted_targets(rules, "serviceaccounts/token", {"create"}, service_accounts))

    if _can_create(rules, "secrets"):
        existing = {(node["properties"]["namespace"], node["properties"]["name"]) for node in nodes["secrets"]}
        add("CAN_PLANT_TOKEN_SECRET", [sa for sa in service_accounts if _can_read_planted_secret(
            rules, sa["properties"]["namespace"], existing)])

    add("CAN_IMPERSONATE", _granted_targets(rules, "serviceaccounts", {"impersonate"}, service_accounts))
    if namespace is None:
        # Users and groups are cluster-scoped: only a ClusterRoleBinding grants impersonating them
        for resource in ("users", "groups"):
            add("CAN_IMPERSONATE", _granted_targets(rules, resource, {"impersonate"}, nodes[resource]))

    # bind: a RoleBinding can reference Roles in its namespace. ClusterRoles only count in the cluster-wide
    # scope: bound by a RoleBinding they apply to one namespace, but a path through the ClusterRole node
    # would follow its cluster-wide edges
    binding_verbs = {"create"} | WRITE_VERBS
    if any(_grants(rule, "rolebindings", binding_verbs) for rule in rules):
        add("CAN_BIND", _granted_targets(rules, "roles", {"bind"}, roles))
    if namespace is None and any(_grants(rule, binding, binding_verbs)
                                 for rule in rules for binding in ("rolebindings", "clusterrolebindings")):
        add("CAN_BIND", _granted_targets(rules, "clusterroles", {"bind"}, nodes["clusterroles"]))

    # escalate: rewrite roles it can update with permissions it doesn't hold (ClusterRoles are cluster-scoped)
    role_types = [("roles", roles)] + ([("clusterroles", nodes["clusterroles"])] if namespace is None else [])
    for resource, candidates in role_types:
        updatable = {node["id"] for node in _granted_targets(rules, resource, WRITE_VERBS, candidates)}
        add("CAN_ESCALATE", [node for node in _granted_targets(rules, resource, {"escalate"}, candidates)
                             if node["id"] in updatable])

    return found


def create_privilege_escalation_edges(roles_raw: List[Any], clusterroles_raw: List[Any],
                                      clusterrole_bindings: ClusterRoleBindingMaps,
                                      nodes: Dict[str, List[Dict]]) -> List[Dict]:
    """
    Create privilege escalation edges from Roles/ClusterRoles, per binding scope (see iter_role_scopes).

    Args:
        roles_raw: List of V1Role objects
        clusterroles_raw: List of V1ClusterRole objects
        clusterrole_bindings: Result of build_clusterrole_binding_maps()
        nodes: Node lists for "pods", "secrets", "serviceaccounts", "roles", "clusterroles", "users" and "groups"
               (may be empty when not collected)

    Returns:
        List of edge dictionaries
    """
    descriptions = {**DESCRIPTIONS, **{kind: description for kind, _, _, description in POD_ACCESS}}
    edges = []

    for role, namespace, properties in iter_role_scopes(roles_raw, clusterroles_raw, clusterrole_bindings):
        for (kind, target), via in _scope_edges(role.rules or [], namespace, nodes).items():
            if target == role.metadata.uid:
                continue  # binding or escalating itself
            edge_properties = {
                **properties,
                "edge_category": classify_edge(kind),
                "description": f"{'ClusterRole' if 'clusterrole_name' in properties else 'Role'} {descriptions[kind]}",
            }
            if via:
                edge_properties["via"] = sorted(set(via))
            edges.append({"start": {"value": role.metadata.uid}, "end": {"value": target},
                          "kind": kind, "properties": edge_properties})

    return edges


def create_token_secret_edges(secrets_raw: List[Any]) -> List[Dict]:
    """
    Create CONTAINS_TOKEN edges from legacy service-account-token Secrets to their ServiceAccount.

    Anyone who can read such a Secret can authenticate as the ServiceAccount.
    """
    edges = []
    for secret in secrets_raw:
        if secret.type != "kubernetes.io/service-account-token":
            continue
        sa_name = (secret.metadata.annotations or {}).get("kubernetes.io/service-account.name")
        if not sa_name:
            continue
        edges.append({
            "start": {"value": secret.metadata.uid},
            "end": {"value": f"serviceaccount:{secret.metadata.namespace}:{sa_name}"},
            "kind": "CONTAINS_TOKEN",
            "properties": {
                "edge_category": classify_edge("CONTAINS_TOKEN"),
                "description": "Secret holds a long-lived token for this ServiceAccount; reading it means "
                               "authenticating as the ServiceAccount",
            }
        })
    return edges
