#!/usr/bin/env python3
"""
KuberHound - Kubernetes Resource Collector for BloodHound
Collects Kubernetes resources and exports in BloodHound OpenGraph JSON format.
"""

import json
import argparse
import hashlib
import os
import sys
from typing import Dict, Any, List

try:
    import kubernetes  # noqa: F401
    import requests  # noqa: F401
except ImportError:
    print("Error: Required modules not found. Install with: pip install -r requirements.txt")
    sys.exit(1)

from k8s_client import get_api_clients
from bloodhound_client import BloodHoundClient
from redact import redact_graph
from collectors import (
    NamespaceCollector, NodeCollector, PodCollector, SecretCollector, ConfigMapCollector,
    ServiceAccountCollector, RoleCollector, ClusterRoleCollector,
    RoleBindingCollector, ClusterRoleBindingCollector,
    ServiceCollector, DeploymentCollector, DaemonSetCollector, StatefulSetCollector, IngressCollector
)
from edges import (
    create_pod_relationship_edges,
    create_rbac_binding_edges,
    build_clusterrole_binding_maps,
    create_generic_rbac_edges,
    create_container_escape_edges,
    create_identity_assume_edges,
    create_pod_create_escalation_edges,
    create_argocd_secret_manipulation_edges,
    create_fluentd_config_manipulation_edges,
    create_phantom_resource_creation_edges,
    create_node_proxy_edges,
    create_privilege_escalation_edges,
    create_token_secret_edges,
    create_workload_edges
)

# Resource name -> (display name, collector class, API client key), in collection order
RESOURCES = {
    "namespaces": ("Namespaces", NamespaceCollector, "core"),
    "nodes": ("Nodes", NodeCollector, "core"),
    "secrets": ("Secrets", SecretCollector, "core"),
    "configmaps": ("ConfigMaps", ConfigMapCollector, "core"),
    "pods": ("Pods", PodCollector, "core"),
    "serviceaccounts": ("ServiceAccounts", ServiceAccountCollector, "core"),
    "roles": ("Roles", RoleCollector, "rbac"),
    "clusterroles": ("ClusterRoles", ClusterRoleCollector, "rbac"),
    "rolebindings": ("RoleBindings", RoleBindingCollector, "rbac"),
    "clusterrolebindings": ("ClusterRoleBindings", ClusterRoleBindingCollector, "rbac"),
    "services": ("Services", ServiceCollector, "core"),
    "deployments": ("Deployments", DeploymentCollector, "apps"),
    "daemonsets": ("DaemonSets", DaemonSetCollector, "apps"),
    "statefulsets": ("StatefulSets", StatefulSetCollector, "apps"),
    "ingresses": ("Ingresses", IngressCollector, "networking"),
}

RBAC_RESOURCES = ["serviceaccounts", "roles", "clusterroles", "rolebindings", "clusterrolebindings"]

# Resource types that get dynamic CAN_{VERB}_{RESOURCE} edges from Roles/ClusterRoles
RBAC_TARGET_RESOURCES = [
    "secrets", "configmaps", "pods", "services", "deployments", "daemonsets", "statefulsets",
    "ingresses", "serviceaccounts", "namespaces", "roles", "nodes", "clusterroles",
]

# Graph node order
NODE_ORDER = [
    "namespaces", "nodes", "pods", "secrets", "configmaps", "serviceaccounts", "roles", "clusterroles",
    "users", "groups", "services", "deployments", "daemonsets", "statefulsets", "ingresses",
]

PHANTOM_DESCRIPTION = (
    "This {noun} is referenced by one or more pods but does not currently exist in the cluster. "
    "This could indicate: (1) Optional volume mount, (2) Configuration drift, "
    "(3) Potential {impact} if an attacker creates this {noun}."
)

# Phantom node settings per referenced resource type: (kind, id prefix, type-specific properties, impact)
PHANTOM_TYPES = {
    "secrets": ("K8sSecret", "phantom-secret", {"secret_type": "Unknown", "data_keys": []},
                "privilege escalation vector"),
    "configmaps": ("K8sConfigMap", "phantom-configmap", {"data_keys": [], "binary_data_keys": []},
                   "attack vector"),
}


def create_phantom_node(resource: str, namespace: str, name: str) -> Dict[str, Any]:
    """
    Create a phantom node for a missing/non-existent secret or configmap that is referenced by pods.

    Args:
        resource: "secrets" or "configmaps"
        namespace: Namespace where the resource would exist
        name: Name of the missing resource

    Returns:
        Node dictionary marked as missing, with a deterministic ID
    """
    kind, id_prefix, extra_properties, impact = PHANTOM_TYPES[resource]
    noun = resource[:-1]
    return {
        "id": hashlib.sha256(f"{id_prefix}:{namespace}:{name}".encode()).hexdigest()[:32],
        "kinds": [kind],
        "properties": {
            "name": f"{name} (Missing)",
            "namespace": namespace,
            "creation_timestamp": "",
            **extra_properties,
            "labels": [],
            "annotations": [],
            "resource_version": "",
            "missing": True,
            "description": PHANTOM_DESCRIPTION.format(noun=noun, impact=impact),
        }
    }


def create_subject_nodes(names: set, kind: str, prefix: str, subject_type: str) -> List[Dict[str, Any]]:
    """Create K8sUser/K8sGroup nodes for the subject names referenced by bindings."""
    return [
        {"id": f"{prefix}:{name}", "kinds": [kind], "properties": {"name": name, "type": subject_type}}
        for name in names
    ]


def _uid_map(nodes: List[Dict]) -> Dict[str, str]:
    """Map "namespace:name" (namespaced) or "name" (cluster-scoped) to node ID."""
    uid_map = {}
    for node in nodes:
        props = node["properties"]
        key = f"{props['namespace']}:{props['name']}" if "namespace" in props else props["name"]
        uid_map[key] = node["id"]
    return uid_map


def _resolve(value: str, maps: Dict[str, Dict[str, str]], warn: Dict[str, str]):
    """
    Resolve a "prefix:key" placeholder to a node ID.

    Returns the value unchanged if it is already a node ID, or None if the referenced node
    was not collected (warning for prefixes listed in warn).
    """
    prefix, sep, key = value.partition(":")
    lookup = maps.get(prefix) if sep else None
    if lookup is None:
        return value
    uid = lookup.get(key)
    if uid is None and prefix in warn:
        print(f"Warning: {warn[prefix]} '{key}' not found for edge")
    return uid


def build_graph(nodes: Dict[str, List[Dict]], all_edges: List[Dict], referenced_resources: Dict[str, set],
                raw: Dict[str, List[Any]], clusterrole_bindings) -> Dict[str, Any]:
    """
    Build BloodHound OpenGraph JSON structure from collected resources.

    Creates phantom nodes for secrets/configmaps referenced by pods but missing from the cluster,
    then resolves placeholder IDs in edges and drops edges whose endpoints were not collected.

    Args:
        nodes: Resource name -> list of node dictionaries (see NODE_ORDER)
        all_edges: List of all edge dictionaries (needs UID resolution)
        referenced_resources: Dict with "secrets"/"configmaps" sets of "namespace:name" referenced by pods
        raw: Resource name -> raw Kubernetes objects
        clusterrole_bindings: Result of build_clusterrole_binding_maps()

    Returns:
        Dictionary in BloodHound OpenGraph format
    """
    uid_maps = {
        "namespace": _uid_map(nodes["namespaces"]),
        "node": _uid_map(nodes["nodes"]),
        "secret": _uid_map(nodes["secrets"]),
        "configmap": _uid_map(nodes["configmaps"]),
        "serviceaccount": _uid_map(nodes["serviceaccounts"]),
        "role": _uid_map(nodes["roles"]),
        "clusterrole": _uid_map(nodes["clusterroles"]),
        "user": _uid_map(nodes["users"]),
        "group": _uid_map(nodes["groups"]),
    }

    # Create phantom nodes for resources referenced but not found
    phantom_nodes = []
    for resource, map_key in (("secrets", "secret"), ("configmaps", "configmap")):
        for key in referenced_resources.get(resource, set()):
            if key not in uid_maps[map_key]:
                namespace, name = key.split(":", 1)
                phantom_node = create_phantom_node(resource, namespace, name)
                phantom_nodes.append(phantom_node)
                uid_maps[map_key][key] = phantom_node["id"]
                print(f"[*] Created phantom node for missing {resource[:-1]}: {namespace}/{name}")

    # Connect Roles/ClusterRoles that can CREATE a missing secret/configmap to its phantom node
    if phantom_nodes:
        phantom_creation_edges = create_phantom_resource_creation_edges(
            phantom_nodes, raw["roles"], raw["clusterroles"], clusterrole_bindings
        )
        all_edges.extend(phantom_creation_edges)
        if phantom_creation_edges:
            print(f"[*] Created {len(phantom_creation_edges)} edges from Roles/ClusterRoles to phantom nodes they can create")

    # Placeholders that may appear as edge start/end; other values are already node IDs
    start_maps = {k: uid_maps[k] for k in ("node", "serviceaccount", "user", "group")}
    end_maps = {k: uid_maps[k] for k in ("namespace", "secret", "configmap", "serviceaccount", "role", "clusterrole", "node")}

    resolved_edges = []
    for edge in all_edges:
        start = _resolve(edge["start"]["value"], start_maps, {"node": "Node"})
        if start is None:
            continue
        end = _resolve(edge["end"]["value"], end_maps,
                       {"namespace": "Namespace", "serviceaccount": "ServiceAccount", "node": "Node"})
        if end is None:
            continue
        edge["start"]["value"] = start
        edge["end"]["value"] = end
        resolved_edges.append(edge)

    all_nodes = [node for resource in NODE_ORDER for node in nodes[resource]] + phantom_nodes

    return {
        "metadata": {
            "source_kind": "Kubernetes"
        },
        "graph": {
            "nodes": all_nodes,
            "edges": resolved_edges
        }
    }


def connect_bloodhound(args) -> BloodHoundClient:
    """Create an authenticated BloodHound client from --api-key or --username/--password."""
    if args.api_key:
        return BloodHoundClient(args.bloodhound_url, args.api_key)

    bh_client = BloodHoundClient.from_credentials(args.bloodhound_url, args.username, args.password)
    if not bh_client:
        print("Error: Failed to authenticate with BloodHound")
        sys.exit(1)
    return bh_client


def create_edges(selected: set, nodes: Dict[str, List[Dict]], raw: Dict[str, List[Any]],
                 clusterrole_bindings) -> tuple:
    """
    Create all edges for the collected resources.

    Returns:
        Tuple of (edges, referenced_resources)
    """
    all_edges = []
    referenced_resources = {"secrets": set(), "configmaps": set()}

    def add(description, edges, verb="Created"):
        all_edges.extend(edges)
        print(f"    {verb} {len(edges)} {description}")

    # Create Pod relationship edges (IN_NAMESPACE, USES_*, HOSTS_POD)
    if "pods" in selected:
        print("\n[*] Creating Pod relationship edges...")
        pod_rel_edges, referenced_resources = create_pod_relationship_edges(raw["pods"])
        add("Pod relationship edges", pod_rel_edges)

    # Create RBAC binding edges (BOUND_TO), plus User and Group nodes from the binding subjects
    if raw["rolebindings"] or raw["clusterrolebindings"]:
        print("\n[*] Creating RBAC binding edges...")
        rbac_edges, all_users, all_groups = create_rbac_binding_edges(raw["rolebindings"], raw["clusterrolebindings"])
        add("RBAC binding edges", rbac_edges)

        print("\n[*] Creating User and Group nodes...")
        nodes["users"] = create_subject_nodes(all_users, "K8sUser", "user", "User")
        nodes["groups"] = create_subject_nodes(all_groups, "K8sGroup", "group", "Group")
        print(f"    Created {len(nodes['users'])} User nodes and {len(nodes['groups'])} Group nodes")

    if "pods" in selected:
        print("\n[*] Creating container escape edges...")
        add("container escape edges", create_container_escape_edges(raw["pods"]))

        print("\n[*] Creating identity assumption edges...")
        add("identity assumption edges", create_identity_assume_edges(raw["pods"]))

    has_roles = "roles" in selected or "clusterroles" in selected

    # Role/ClusterRole → resource access edges (CAN_{VERB}_{RESOURCE}) for every collected resource type
    if has_roles:
        collected_resources = {r: nodes[r] for r in RBAC_TARGET_RESOURCES if r in selected}
        if collected_resources:
            print("\n[*] Creating generic RBAC resource access edges...")
            print(f"    Processing {len(collected_resources)} resource types: {', '.join(collected_resources)}")
            add("dynamic RBAC edges", create_generic_rbac_edges(
                raw["roles"], raw["clusterroles"], clusterrole_bindings, collected_resources
            ))

    # Role/ClusterRole → Pod/ServiceAccount/User/Group/Role edges for exec, token, impersonation and bind rights
    if has_roles:
        print("\n[*] Detecting RBAC privilege escalation paths...")
        add("privilege escalation edges", create_privilege_escalation_edges(
            raw["roles"], raw["clusterroles"], clusterrole_bindings, nodes
        ), verb="Found")

    if "secrets" in selected:
        print("\n[*] Linking ServiceAccount token Secrets...")
        add("ServiceAccount token Secret edges", create_token_secret_edges(raw["secrets"]))

    if has_roles and "namespaces" in selected:
        print("\n[*] Detecting POD_CREATE escalation paths...")
        add("POD_CREATE escalation opportunities", create_pod_create_escalation_edges(
            nodes["roles"], nodes["clusterroles"], nodes["namespaces"], clusterrole_bindings
        ), verb="Found")

    if "clusterroles" in selected and "nodes" in selected:
        print("\n[*] Detecting nodes/proxy kubelet access...")
        add("nodes/proxy kubelet access paths", create_node_proxy_edges(
            nodes["clusterroles"], nodes["nodes"], clusterrole_bindings
        ), verb="Found")

    if has_roles and "namespaces" in selected and "pods" in selected:
        takeover_args = (nodes["roles"], nodes["clusterroles"], nodes["namespaces"], nodes["pods"])

        print("\n[*] Detecting ArgoCD secret manipulation attack paths...")
        add("ArgoCD secret manipulation opportunities",
            create_argocd_secret_manipulation_edges(*takeover_args), verb="Found")

        print("\n[*] Detecting Fluentd config manipulation attack paths...")
        add("Fluentd config manipulation opportunities",
            create_fluentd_config_manipulation_edges(*takeover_args), verb="Found")

    # Workload relationship edges (Service→Pod, Deployment→Pod, Ingress→Service, etc.)
    workload_types = ["services", "deployments", "daemonsets", "statefulsets", "ingresses"]
    if any(raw[r] for r in workload_types):
        print("\n[*] Creating workload relationship edges...")
        add("workload relationship edges", create_workload_edges(
            [node for r in workload_types for node in nodes[r]],
            nodes["services"], nodes["pods"], raw["services"],
            [("Deployment", raw["deployments"]), ("DaemonSet", raw["daemonsets"]),
             ("StatefulSet", raw["statefulsets"])],
            raw["ingresses"]
        ))

    return all_edges, referenced_resources


def main():
    """
    Main entry point for KuberHound.
    """
    parser = argparse.ArgumentParser(
        description="Collect Kubernetes resources and export to BloodHound OpenGraph JSON format"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: kuberhound.json, skipped if --bloodhound-url is provided without this flag)"
    )
    parser.add_argument(
        "--bloodhound-url",
        "-u",
        default=os.environ.get("BLOODHOUND_URL"),
        help="BloodHound server URL (e.g., http://localhost:8080) [env: BLOODHOUND_URL]"
    )
    parser.add_argument(
        "--api-key",
        "-k",
        default=os.environ.get("BLOODHOUND_API_KEY"),
        help="BloodHound API key (JWT token) for authentication [env: BLOODHOUND_API_KEY]"
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("BLOODHOUND_USERNAME"),
        help="BloodHound username (alternative to --api-key, requires --password) [env: BLOODHOUND_USERNAME]"
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("BLOODHOUND_PASSWORD"),
        help="BloodHound password (alternative to --api-key, requires --username) [env: BLOODHOUND_PASSWORD]"
    )
    parser.add_argument(
        "--upload-queries",
        action="store_true",
        help="Upload custom saved queries to BloodHound (requires --bloodhound-url and authentication)"
    )
    parser.add_argument(
        "--clear-database",
        action="store_true",
        help="Clear BloodHound database only (no data collection or import, requires --bloodhound-url and authentication)"
    )
    parser.add_argument(
        "--skip-clear-owned",
        action="store_true",
        help="Skip clearing 'Owned' selectors when clearing database (use with --clear-database)"
    )
    parser.add_argument(
        "--skip-clear-queries",
        action="store_true",
        help="Skip clearing saved queries when clearing database (use with --clear-database)"
    )
    parser.add_argument(
        "--resources",
        "-r",
        nargs="+",
        choices=list(RESOURCES) + ["rbac", "all"],
        default=["all"],
        help="Resources to collect (default: all). Use 'rbac' to collect all RBAC resources"
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Mask potentially sensitive values (annotation values, secret/configmap key names, IPs, hostnames) "
             "before writing or uploading, e.g. when sharing the output with a third party"
    )
    parser.add_argument(
        "--input",
        "-i",
        help="Upload (or redact) an existing KuberHound JSON file instead of collecting from a cluster "
             "(requires --bloodhound-url with authentication, or --output)"
    )
    parser.add_argument(
        "--default-psa",
        choices=["privileged", "baseline", "restricted"],
        default="privileged",
        help="Cluster-wide Pod Security enforce level for namespaces without an enforce label "
             "(default: privileged, the Kubernetes default; set this if the API server's AdmissionConfiguration changes it)"
    )

    args = parser.parse_args()

    print("KuberHound - Kubernetes Resource Collector")
    print("=" * 50)

    has_auth = bool(args.api_key or (args.username and args.password))

    # Handle --clear-database as exclusive operation (no data collection/import)
    if args.clear_database:
        if not args.bloodhound_url:
            print("Error: --clear-database requires --bloodhound-url")
            sys.exit(1)
        if not has_auth:
            print("Error: --clear-database requires either --api-key or both --username and --password")
            sys.exit(1)

        print("[*] Clear database mode - no data will be collected or imported\n")
        bh_client = connect_bloodhound(args)

        print("[*] Clearing BloodHound database...")
        if bh_client.clear_database(clear_owned=not args.skip_clear_owned,
                                    clear_queries=not args.skip_clear_queries):
            print("\nDatabase cleared successfully!")
            sys.exit(0)
        print("\nError: Failed to clear database")
        sys.exit(1)

    upload_mode = bool(args.bloodhound_url and has_auth)

    if args.input:
        if not (upload_mode or args.output):
            print("Error: --input requires --bloodhound-url with authentication, or --output")
            sys.exit(1)
        print(f"[*] Loading graph from {args.input}")
        try:
            with open(args.input) as f:
                graph = json.load(f)
        except (IOError, ValueError) as e:
            print(f"Error reading {args.input}: {e}")
            sys.exit(1)
    else:
        graph = collect_graph(args)

    if args.redact:
        print("\n[*] Redacting sensitive values...")
        redact_graph(graph)

    success = True

    # Upload to BloodHound if credentials provided
    if upload_mode:
        print("\n[*] Uploading to BloodHound...")
        bh_client = connect_bloodhound(args)

        # Register custom node types with icons
        print("[*] Registering custom Kubernetes node types...")
        bh_client.register_custom_nodes()

        if args.upload_queries:
            print("\n[*] Uploading saved queries...")
            if not bh_client.upload_saved_queries():
                print("Warning: Query upload failed, but continuing with graph upload")

        print("\n[*] Ingesting graph data to BloodHound...")
        if not bh_client.upload_graph(graph, "kuberhound.json"):
            success = False

    # Write to file if --output specified or if no upload configured
    if args.output or not upload_mode:
        output_file = args.output or "kuberhound.json"
        print(f"\n[*] Writing to file: {output_file}")
        try:
            with open(output_file, 'w') as f:
                json.dump(graph, f, indent=2)
            print(f"Success! Exported data to: {output_file}")
        except IOError as e:
            print(f"Error writing to file {output_file}: {e}")
            success = False

    if not success:
        sys.exit(1)


def collect_graph(args) -> Dict[str, Any]:
    """Collect the selected resources from the cluster and build the OpenGraph structure."""
    # Determine which resources to collect
    if "all" in args.resources:
        selected = set(RESOURCES)
    else:
        selected = set(args.resources) - {"rbac"}
        if "rbac" in args.resources:
            selected.update(RBAC_RESOURCES)

    clients = get_api_clients()

    # Collect resources; raw objects are kept for edge creation
    raw = {resource: [] for resource in RESOURCES}
    nodes = {resource: [] for resource in NODE_ORDER}
    for resource, (display_name, collector_class, client_key) in RESOURCES.items():
        if resource not in selected:
            continue
        print(f"\n[*] Collecting {display_name}...")
        if collector_class is NamespaceCollector:
            collector = collector_class(clients[client_key], default_psa=args.default_psa)
        else:
            collector = collector_class(clients[client_key])
        raw[resource] = collector.collect()
        nodes[resource] = collector.to_nodes(raw[resource])

    clusterrole_bindings = build_clusterrole_binding_maps(raw["rolebindings"], raw["clusterrolebindings"])

    all_edges, referenced_resources = create_edges(selected, nodes, raw, clusterrole_bindings)

    # Build combined graph (will create phantom nodes for missing resources)
    graph = build_graph(nodes, all_edges, referenced_resources, raw, clusterrole_bindings)

    print(f"\n[*] Collected {len(graph['graph']['nodes'])} nodes and {len(graph['graph']['edges'])} edges")
    return graph


if __name__ == "__main__":
    main()
