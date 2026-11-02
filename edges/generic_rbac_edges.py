"""
Generic RBAC edge builder - dynamically creates edges for ANY Kubernetes resource type.
No hardcoding required - edge types are generated from (verb, resource) pairs.

Edge naming: CAN_{VERB}_{RESOURCE}
Examples: CAN_WATCH_SECRETS, CAN_GET_PODS, CAN_LIST_SERVICES, CAN_DELETE_NODES

RBAC resourceNames semantics (the authorizer matches the request's object name against
resourceNames; unfiltered list/watch, create and deletecollection requests carry the name ""):
- resourceNames: [] means every verb applies to all resources in scope
- list, watch: limited to the named resources (clients must use a metadata.name field selector),
  unrestricted only if resourceNames contains ""
- get, update, patch, delete: limited to the non-empty names
- create, deletecollection: denied unless resourceNames contains ""
"""

from typing import List, Dict, Any, Tuple
from .edge_categories import classify_edge
from .rbac_edges import ClusterRoleBindingMaps, iter_role_scopes


# Verbs whose requests target a whole collection; list/watch can still be scoped to names
# with a metadata.name field selector, create/deletecollection cannot
COLLECTION_VERBS = {"list", "watch"}
NAMELESS_VERBS = {"create", "deletecollection"}
OBJECT_VERBS = {"get", "update", "patch", "delete"}
ALL_VERBS = COLLECTION_VERBS | NAMELESS_VERBS | OBJECT_VERBS

RBAC_GROUP = "rbac.authorization.k8s.io"

# API group of each resource type KuberHound reasons about, e.g. to expand resources: ["*"] only
# within a rule's apiGroups
RESOURCE_API_GROUPS = {
    "secrets": "", "configmaps": "", "pods": "", "services": "", "serviceaccounts": "",
    "namespaces": "", "nodes": "", "replicationcontrollers": "", "users": "", "groups": "",
    "deployments": "apps", "daemonsets": "apps", "statefulsets": "apps", "replicasets": "apps",
    "jobs": "batch", "cronjobs": "batch",
    "ingresses": "networking.k8s.io",
    "roles": RBAC_GROUP, "clusterroles": RBAC_GROUP, "rolebindings": RBAC_GROUP, "clusterrolebindings": RBAC_GROUP,
}


def wildcard_resources(rule: Any, resource_types) -> List[str]:
    """Resource types granted by a rule's resources: ["*"], limited to the rule's apiGroups."""
    groups = rule.api_groups or [""]
    return [r for r in resource_types if "*" in groups or RESOURCE_API_GROUPS.get(r) in groups]


def apply_resource_names(nodes: List[Dict], rule: Any, verb: str) -> Tuple[List[Dict], bool]:
    """
    Narrow the in-scope nodes to what a rule's resourceNames actually grants for one verb.

    Returns:
        Tuple of (target_nodes, resource_restricted)
    """
    raw_names = rule.resource_names or []
    if not raw_names:
        return nodes, False

    names = {name for name in raw_names if name}
    if verb in OBJECT_VERBS:
        # "" never matches a named object
        return [node for node in nodes if node["properties"]["name"] in names], True
    if "" in raw_names:
        return nodes, False
    if verb in NAMELESS_VERBS:
        return [], False
    return [node for node in nodes if node["properties"]["name"] in names], True


def _index_resource_nodes(resource_nodes: List[Dict]) -> Tuple[List[Dict], Dict[str, List[Dict]], bool]:
    """
    Index resource nodes so per-namespace lookups don't rescan every node.

    Returns:
        Tuple of (all_nodes, nodes_by_namespace, is_cluster_scoped); nodes_by_namespace is
        empty for cluster-scoped resources (e.g. nodes, clusterroles)
    """
    # Cluster-scoped nodes have no "namespace" property
    is_cluster_scoped = bool(resource_nodes) and "namespace" not in resource_nodes[0]["properties"]

    nodes_by_namespace = {}
    if not is_cluster_scoped:
        for node in resource_nodes:
            nodes_by_namespace.setdefault(node["properties"]["namespace"], []).append(node)

    return resource_nodes, nodes_by_namespace, is_cluster_scoped


def _create_edges_for_resource_verb(
    source_uid: str,
    resource_type: str,
    verb: str,
    target_nodes: List[Dict],
    properties: Dict
) -> List[Dict]:
    """
    Create edges for a specific (resource_type, verb) pair.

    Args:
        source_uid: UID of the Role/ClusterRole
        resource_type: Resource type (e.g., "secrets", "pods", "services")
        verb: RBAC verb (e.g., "get", "list", "watch")
        target_nodes: List of resource nodes to create edges to
        properties: Additional edge properties

    Returns:
        List of edge dictionaries
    """
    edges = []

    # Dynamically generate edge type: CAN_{VERB}_{RESOURCE}
    edge_kind = f"CAN_{verb.upper()}_{resource_type.upper()}"

    for node in target_nodes:
        edges.append({
            "start": {"value": source_uid},
            "end": {"value": node["id"]},
            "kind": edge_kind,
            "properties": {
                **properties,
                "edge_category": classify_edge(edge_kind),
                "verb": verb,
                "resource_type": resource_type
            }
        })

    return edges


def _rule_edges(source_uid: str, resource_type: str, rule: Any, nodes: List[Dict],
                properties: Dict) -> List[Dict]:
    """
    Create edges for every verb a rule grants on the in-scope nodes, narrowed per verb by resourceNames.

    Args:
        source_uid: UID of the Role/ClusterRole
        resource_type: Resource type (e.g., "secrets", "pods", "nodes")
        rule: RBAC rule object
        nodes: Resource nodes within the binding's scope
        properties: Additional edge properties
    """
    edges = []
    verbs = rule.verbs or []
    properties = {**properties, "verbs": verbs}

    for verb in ALL_VERBS:
        if verb in verbs or "*" in verbs:
            target_nodes, restricted = apply_resource_names(nodes, rule, verb)
            edges.extend(_create_edges_for_resource_verb(
                source_uid, resource_type, verb, target_nodes,
                {**properties, "resource_restricted": restricted}
            ))

    return edges


def create_generic_rbac_edges(
    roles_raw: List[Any],
    clusterroles_raw: List[Any],
    clusterrole_bindings: ClusterRoleBindingMaps,
    collected_resources: Dict[str, List[Dict]]
) -> List[Dict]:
    """
    Create RBAC edges dynamically for ANY Kubernetes resource type.
    No hardcoding required - edge types are generated from (verb, resource) pairs.

    Edge naming: CAN_{VERB}_{RESOURCE}
    Examples:
    - CAN_WATCH_SECRETS
    - CAN_GET_PODS
    - CAN_LIST_SERVICES
    - CAN_DELETE_NODES
    - CAN_CREATE_DEPLOYMENTS

    A rule on resources ["*"] gets edges to every collected resource type in the rule's apiGroups.

    RBAC Verb Semantics (see apply_resource_names):
    - list, watch: limited to resourceNames unless it contains ""
    - get, update, patch, delete: limited to the non-empty resourceNames
    - create, deletecollection: denied when resourceNames is set without ""

    ClusterRole Scope Handling:
    - ClusterRole + RoleBinding → namespace-scoped edges (binding_scope: "namespace")
    - ClusterRole + ClusterRoleBinding → cluster-wide edges (binding_scope: "cluster-wide")

    Args:
        roles_raw: List of V1Role objects
        clusterroles_raw: List of V1ClusterRole objects
        clusterrole_bindings: Result of build_clusterrole_binding_maps()
        collected_resources: Dict mapping resource type → list of nodes
                             Example: {
                                 "secrets": [secret_node1, secret_node2, ...],
                                 "pods": [pod_node1, pod_node2, ...],
                                 "services": [service_node1, ...]
                             }

    Returns:
        List of edge dictionaries
    """
    edges = []
    indexes = {resource_type: _index_resource_nodes(nodes) for resource_type, nodes in collected_resources.items()}

    for role, namespace, properties in iter_role_scopes(roles_raw, clusterroles_raw, clusterrole_bindings):
        for rule in role.rules or []:
            resources = rule.resources or []
            if "*" in resources:
                resource_types = wildcard_resources(rule, indexes)
            else:
                resource_types = [r for r in resources if r in indexes]
            for resource_type in resource_types:
                all_nodes, nodes_by_namespace, is_cluster_scoped = indexes[resource_type]
                if namespace is None:
                    nodes = all_nodes
                elif is_cluster_scoped:
                    continue  # cluster-scoped resources are only reachable through a ClusterRoleBinding
                else:
                    nodes = nodes_by_namespace.get(namespace, [])
                edges.extend(_rule_edges(role.metadata.uid, resource_type, rule, nodes, properties))

    return edges
