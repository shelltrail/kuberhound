"""
Edge builders for KuberHound.
Separate edge creation logic from data collection.
"""

from .pod_edges import create_pod_relationship_edges
from .rbac_edges import create_rbac_binding_edges, build_clusterrole_binding_maps
from .generic_rbac_edges import create_generic_rbac_edges
from .attack_edges import (
    create_container_escape_edges,
    create_identity_assume_edges,
    create_pod_create_escalation_edges,
    create_argocd_secret_manipulation_edges,
    create_fluentd_config_manipulation_edges,
    create_phantom_resource_creation_edges,
    create_node_proxy_edges
)
from .privesc_edges import create_privilege_escalation_edges, create_token_secret_edges
from .workload_edges import create_workload_edges
from .edge_categories import classify_edge

__all__ = [
    'create_pod_relationship_edges',
    'create_rbac_binding_edges',
    'build_clusterrole_binding_maps',
    'create_generic_rbac_edges',
    'create_container_escape_edges',
    'create_identity_assume_edges',
    'create_pod_create_escalation_edges',
    'create_argocd_secret_manipulation_edges',
    'create_fluentd_config_manipulation_edges',
    'create_phantom_resource_creation_edges',
    'create_node_proxy_edges',
    'create_privilege_escalation_edges',
    'create_token_secret_edges',
    'create_workload_edges',
    'classify_edge',
]
