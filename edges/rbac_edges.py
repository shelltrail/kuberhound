"""
RBAC binding edges.
Creates BOUND_TO edges from Subjects (ServiceAccount/User/Group) to Roles/ClusterRoles.
"""

from typing import List, Dict, Any, Tuple, Set, Iterator, Optional
from .edge_categories import classify_edge

# (ClusterRole name -> namespaces it is bound in via RoleBindings, ClusterRole names bound cluster-wide)
ClusterRoleBindingMaps = Tuple[Dict[str, Set[str]], Set[str]]


def build_clusterrole_binding_maps(rolebindings_raw: List[Any],
                                   clusterrolebindings_raw: List[Any]) -> ClusterRoleBindingMaps:
    """
    Build maps of where each ClusterRole is bound.

    Returns:
        Tuple of (clusterrole_to_namespaces, clusterrole_cluster_wide) where:
        - clusterrole_to_namespaces: ClusterRole name -> set of namespaces (from RoleBindings)
        - clusterrole_cluster_wide: Set of ClusterRole names with cluster-wide bindings
    """
    clusterrole_to_namespaces = {}
    for rb in rolebindings_raw:
        if rb.role_ref.kind == "ClusterRole":
            clusterrole_to_namespaces.setdefault(rb.role_ref.name, set()).add(rb.metadata.namespace)

    clusterrole_cluster_wide = {crb.role_ref.name for crb in clusterrolebindings_raw}
    return clusterrole_to_namespaces, clusterrole_cluster_wide


def iter_role_scopes(roles_raw: List[Any], clusterroles_raw: List[Any],
                     clusterrole_bindings: ClusterRoleBindingMaps) -> Iterator[Tuple[Any, Optional[str], Dict]]:
    """
    Yield (role, namespace, properties) for every scope in which a Role/ClusterRole grants its rules.

    namespace is None for a ClusterRole bound cluster-wide, which reaches namespaced resources in all
    namespaces and cluster-scoped resources. A Role applies in its own namespace; a ClusterRole bound
    by RoleBindings applies once per binding namespace. Unbound ClusterRoles grant nothing.
    """
    for role in roles_raw:
        yield role, role.metadata.namespace, {"role_name": role.metadata.name}

    clusterrole_to_namespaces, clusterrole_cluster_wide = clusterrole_bindings
    for clusterrole in clusterroles_raw:
        cr_name = clusterrole.metadata.name
        for namespace in clusterrole_to_namespaces.get(cr_name, set()):
            yield clusterrole, namespace, {"clusterrole_name": cr_name, "binding_scope": "namespace",
                                           "binding_namespace": namespace}
        if cr_name in clusterrole_cluster_wide:
            yield clusterrole, None, {"clusterrole_name": cr_name, "binding_scope": "cluster-wide"}


def create_rbac_binding_edges(rolebindings_raw: List[Any],
                               clusterrolebindings_raw: List[Any]) -> Tuple[List[Dict[str, Any]], set, set]:
    """
    Create BOUND_TO edges from RoleBindings and ClusterRoleBindings.

    Edge created:
    - BOUND_TO: Subject (ServiceAccount/User/Group) → Role/ClusterRole

    Args:
        rolebindings_raw: List of V1RoleBinding objects
        clusterrolebindings_raw: List of V1ClusterRoleBinding objects

    Returns:
        Tuple of (edges, user_subjects, group_subjects) where:
        - edges: List of edge dictionaries with placeholder IDs
        - user_subjects: Set of user names referenced in bindings
        - group_subjects: Set of group names referenced in bindings
    """
    edges = []
    user_subjects = set()
    group_subjects = set()

    for rb in rolebindings_raw:
        # A RoleBinding can reference a namespaced Role or a ClusterRole
        if rb.role_ref.kind == "ClusterRole":
            role_id = f"clusterrole:{rb.role_ref.name}"
        else:
            role_id = f"role:{rb.metadata.namespace}:{rb.role_ref.name}"
        edges.extend(_binding_edges(
            rb, role_id, rb.metadata.namespace, {"binding_namespace": rb.metadata.namespace},
            user_subjects, group_subjects
        ))

    for crb in clusterrolebindings_raw:
        edges.extend(_binding_edges(
            crb, f"clusterrole:{crb.role_ref.name}", None, {"binding_type": "ClusterRoleBinding"},
            user_subjects, group_subjects
        ))

    return edges, user_subjects, group_subjects


def _binding_edges(binding: Any, role_id: str, default_namespace: str, extra_properties: Dict[str, Any],
                   user_subjects: set, group_subjects: set) -> List[Dict[str, Any]]:
    """Create a BOUND_TO edge from each subject of a binding, recording User/Group names."""
    edges = []

    for subject in binding.subjects or []:
        if subject.kind == "ServiceAccount":
            namespace = subject.namespace or default_namespace
            if not namespace:
                continue  # ServiceAccount must have a namespace
            subject_id = f"serviceaccount:{namespace}:{subject.name}"
        elif subject.kind == "User":
            subject_id = f"user:{subject.name}"
            user_subjects.add(subject.name)
        elif subject.kind == "Group":
            subject_id = f"group:{subject.name}"
            group_subjects.add(subject.name)
        else:
            continue  # Unknown subject kind

        edges.append({
            "start": {"value": subject_id},
            "end": {"value": role_id},
            "kind": "BOUND_TO",
            "properties": {
                "edge_category": classify_edge("BOUND_TO"),
                "binding_name": binding.metadata.name,
                **extra_properties,
            }
        })

    return edges
