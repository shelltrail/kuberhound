"""
Attack path edges.
Creates edges representing Kubernetes attack techniques and privilege escalation paths.
"""

from typing import List, Dict, Any, Optional
from .edge_categories import classify_edge
from .rbac_edges import ClusterRoleBindingMaps

# hostPath mounts that allow writing to sensitive host locations
HOST_WRITE_PATHS = {"/", "/etc", "/root", "/var/lib/kubelet", "/var/lib/kubelet/pki", "/etc/kubernetes", "/var/log"}

SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def _has_capability(pod: Any, capability: Optional[str] = None) -> bool:
    """True if any container is privileged or (when given) adds the capability."""
    for container in pod.spec.containers or []:
        sc = container.security_context
        if not sc:
            continue
        if sc.privileged:
            return True
        if capability and sc.capabilities and sc.capabilities.add and capability in sc.capabilities.add:
            return True
    return False


def _escape_edges(pod: Any) -> List[tuple]:
    """(edge kind, properties) for every container escape technique available to a scheduled pod."""
    edges = []
    host_pid = bool(pod.spec.host_pid)

    # CE_PRIV_MOUNT: privileged container can mount the host filesystem
    if _has_capability(pod):
        edges.append(("CE_PRIV_MOUNT", {
            "attack_description": "Privileged container can mount host filesystem and escape to node",
            "mitre_attack": "T1611",  # Escape to Host
        }))

    # CE_NSENTER: hostPID + SYS_ADMIN (or privileged)
    if host_pid and _has_capability(pod, "SYS_ADMIN"):
        edges.append(("CE_NSENTER", {
            "attack_description": "Pod with hostPID and SYS_ADMIN can use nsenter to escape to host namespace",
            "mitre_attack": "T1611",  # Escape to Host
            "technique": "nsenter -t 1 -m -u -i -n -p -- bash",
        }))

    # CE_SYS_PTRACE: hostPID + SYS_PTRACE + SYS_ADMIN (capabilities may come from different containers)
    if host_pid and _has_capability(pod, "SYS_PTRACE") and _has_capability(pod, "SYS_ADMIN"):
        edges.append(("CE_SYS_PTRACE", {
            "attack_description": "Pod with hostPID, SYS_PTRACE and SYS_ADMIN can inject code into host processes",
            "mitre_attack": "T1055",  # Process Injection
            "required_capabilities": ["SYS_PTRACE", "SYS_ADMIN"],
        }))

    # CE_MODULE_LOAD: SYS_MODULE (or privileged)
    if _has_capability(pod, "SYS_MODULE"):
        edges.append(("CE_MODULE_LOAD", {
            "attack_description": "Pod with SYS_MODULE can load malicious kernel modules to compromise host",
            "mitre_attack": "T1547.006",  # Kernel Modules and Extensions
            "technique": "insmod malicious.ko",
        }))

    # EXPLOIT_HOST_WRITE: dangerous hostPath mounts
    dangerous_paths = [v.host_path.path for v in pod.spec.volumes or []
                       if v.host_path and v.host_path.path in HOST_WRITE_PATHS]
    if dangerous_paths:
        edges.append(("EXPLOIT_HOST_WRITE", {
            "attack_description": f"Pod has dangerous hostPath mounts allowing write to host filesystem: {', '.join(dangerous_paths)}",
            "mitre_attack": "T1611",  # Escape to Host
            "dangerous_paths": dangerous_paths,
            "techniques": ["Write to /etc/cron.d", "Modify /root/.ssh/authorized_keys", "Write to /etc/kubernetes", "Symlink attack via /var/log/pods for file exfiltration"],
        }))

    # EXPLOIT_HOST_READ: DAC_READ_SEARCH (or privileged)
    if _has_capability(pod, "DAC_READ_SEARCH"):
        edges.append(("EXPLOIT_HOST_READ", {
            "attack_description": "Pod with DAC_READ_SEARCH can read arbitrary files from host filesystem",
            "mitre_attack": "T1005",  # Data from Local System
            "sensitive_files": ["/etc/shadow", "/root/.ssh/id_rsa", "/var/lib/kubelet/pki/kubelet-client-current.pem"],
        }))

    return edges


def create_container_escape_edges(pods_raw: List[Any]) -> List[Dict[str, Any]]:
    """
    Create container escape edges from Pods to Nodes.

    Edges created:
    - CE_PRIV_MOUNT: Privileged container → Node
    - CE_NSENTER: hostPID + SYS_ADMIN → Node (nsenter escape)
    - CE_SYS_PTRACE: hostPID + SYS_PTRACE + SYS_ADMIN → Node (process injection)
    - CE_MODULE_LOAD: SYS_MODULE capability → Node (kernel module loading)
    - EXPLOIT_HOST_WRITE: Dangerous hostPath mounts → Node
    - EXPLOIT_HOST_READ: DAC_READ_SEARCH capability → Node

    Args:
        pods_raw: List of V1Pod objects

    Returns:
        List of edge dictionaries with placeholder IDs
    """
    edges = []

    for pod in pods_raw:
        if not pod.spec or not pod.spec.node_name:
            continue
        for kind, properties in _escape_edges(pod):
            edges.append({
                "start": {"value": pod.metadata.uid},
                "end": {"value": f"node:{pod.spec.node_name}"},
                "kind": kind,
                "properties": {"edge_category": classify_edge(kind), **properties}
            })

    return edges


def create_identity_assume_edges(pods_raw: List[Any]) -> List[Dict[str, Any]]:
    """
    Create IDENTITY_ASSUME edges from Pods to ServiceAccounts.

    Pods with mounted service account tokens (automount defaults to true) can use them to
    authenticate as that SA.

    Args:
        pods_raw: List of V1Pod objects

    Returns:
        List of edge dictionaries with placeholder IDs
    """
    edges = []

    for pod in pods_raw:
        if not pod.spec or pod.spec.automount_service_account_token is False:
            continue

        sa_name = pod.spec.service_account_name or "default"
        edges.append({
            "start": {"value": pod.metadata.uid},
            "end": {"value": f"serviceaccount:{pod.metadata.namespace}:{sa_name}"},
            "kind": "IDENTITY_ASSUME",
            "properties": {
                "edge_category": classify_edge("IDENTITY_ASSUME"),
                "attack_description": f"Pod can assume ServiceAccount identity via mounted token at {SA_TOKEN_PATH}",
                "mitre_attack": "T1528",  # Steal Application Access Token
                "token_path": SA_TOKEN_PATH
            }
        })

    return edges


def create_node_proxy_edges(clusterrole_nodes: List[Dict],
                            node_nodes: List[Dict],
                            clusterrole_bindings: ClusterRoleBindingMaps) -> List[Dict]:
    """
    Create CAN_EXEC_VIA_NODE_PROXY edges from ClusterRoles to Nodes.

    get/create on nodes/proxy reaches the kubelet API, which can exec into any container on the
    node (WebSocket exec is a GET, so get alone is enough). nodes/proxy is cluster-scoped, so only
    ClusterRoles bound via a ClusterRoleBinding grant it.

    Args:
        clusterrole_nodes: List of ClusterRole node dictionaries
        node_nodes: List of Node node dictionaries
        clusterrole_bindings: Result of build_clusterrole_binding_maps()

    Returns:
        List of edge dictionaries
    """
    edges = []
    _, clusterrole_cluster_wide = clusterrole_bindings

    for clusterrole in clusterrole_nodes:
        if "NODE_PROXY" not in clusterrole["properties"].get("attack_capabilities", []):
            continue
        if clusterrole["properties"]["name"] not in clusterrole_cluster_wide:
            continue

        for node in node_nodes:
            edges.append({
                "start": {"value": clusterrole["id"]},
                "end": {"value": node["id"]},
                "kind": "CAN_EXEC_VIA_NODE_PROXY",
                "properties": {
                    "edge_category": classify_edge("CAN_EXEC_VIA_NODE_PROXY"),
                    "description": "ClusterRole grants nodes/proxy, reaching the kubelet API to exec into any pod on the node",
                    "attack_vector": "Call https://<node>:10250/exec/<namespace>/<pod>/<container> through the API server's nodes/proxy, bypassing pods/exec RBAC and audit",
                    "mitre_attack": "T1609",
                    "reference": "https://grahamhelton.com/blog/nodes-proxy-rce"
                }
            })

    return edges


POD_SPAWNING_CAPABILITIES = ("POD_CREATE", "WORKLOAD_CREATE")

ESCALATE_VIA_POD_ATTACK_VECTOR = (
    "Create a pod (directly or via a workload controller) with a hostPath mount to /var/lib/kubelet/pki, "
    "or a privileged/hostPID container, to take over the Node and steal the kubelet client certificate"
)


def _escalate_via_pod_properties(role_kind: str, attack_caps: List[str], ns_props: Dict) -> Dict:
    """Build CAN_ESCALATE_VIA_POD edge properties for a namespace whose effective PSA level is privileged."""
    psa_enforce = ns_props.get("psa_enforce", "")
    psa_configured = ns_props.get("psa_configured", False)
    via = [cap for cap in POD_SPAWNING_CAPABILITIES if cap in attack_caps]
    how = "create pods" if "POD_CREATE" in via else "create or modify pod-spawning workloads"

    if psa_configured and psa_enforce:
        psa_status = f"enforce={psa_enforce} (allows privileged containers, hostPath and host namespaces)"
        description = f"{role_kind} can {how} in namespace with PSA enforce={psa_enforce}, allowing Node escalation"
    else:
        psa_status = f"not-configured (cluster default: {ns_props.get('psa_effective', 'privileged')})"
        description = f"{role_kind} can {how} in namespace with no PSA enforce label (cluster default applies), allowing Node escalation"

    return {
        "edge_category": classify_edge("CAN_ESCALATE_VIA_POD"),
        "description": description,
        "psa_enforce": psa_enforce,
        "psa_configured": psa_configured,
        "psa_status": psa_status,
        "via": via,
        "attack_vector": ESCALATE_VIA_POD_ATTACK_VECTOR,
    }


def create_pod_create_escalation_edges(role_nodes: List[Dict],
                                        clusterrole_nodes: List[Dict],
                                        namespace_nodes: List[Dict],
                                        clusterrole_bindings: ClusterRoleBindingMaps) -> List[Dict]:
    """
    Create CAN_ESCALATE_VIA_POD edges showing privilege escalation via pod creation.

    When a Role/ClusterRole can create pods (POD_CREATE) or pod-spawning workloads (WORKLOAD_CREATE)
    in a namespace whose effective PSA enforce level is "privileged", an attacker can run a privileged
    or hostPath pod and escalate to Node access. "baseline" and "restricted" block this.

    ClusterRoles only get edges to namespaces where they are bound via a RoleBinding, or to all
    namespaces when bound via a ClusterRoleBinding.

    Args:
        role_nodes: List of Role node dictionaries
        clusterrole_nodes: List of ClusterRole node dictionaries
        namespace_nodes: List of Namespace node dictionaries
        clusterrole_bindings: Result of build_clusterrole_binding_maps()

    Returns:
        List of edge dictionaries
    """
    edges = []

    # Only namespaces where privileged/hostPath pods are admitted
    vulnerable_ns = {
        ns["properties"]["name"]: ns
        for ns in namespace_nodes
        if ns["properties"].get("allows_dangerous_pods", False)
    }

    # Roles (namespace-scoped)
    for role in role_nodes:
        attack_caps = role["properties"].get("attack_capabilities", [])
        if not any(cap in attack_caps for cap in POD_SPAWNING_CAPABILITIES):
            continue

        ns_node = vulnerable_ns.get(role["properties"].get("namespace", ""))
        if not ns_node:
            continue

        edges.append({
            "start": {"value": role["id"]},
            "end": {"value": ns_node["id"]},
            "kind": "CAN_ESCALATE_VIA_POD",
            "properties": _escalate_via_pod_properties("Role", attack_caps, ns_node["properties"])
        })

    # ClusterRoles (namespace-scoped via RoleBinding, or cluster-wide via ClusterRoleBinding)
    clusterrole_to_namespaces, clusterrole_cluster_wide = clusterrole_bindings

    for clusterrole in clusterrole_nodes:
        attack_caps = clusterrole["properties"].get("attack_capabilities", [])
        if not any(cap in attack_caps for cap in POD_SPAWNING_CAPABILITIES):
            continue

        cr_name = clusterrole["properties"]["name"]
        is_cluster_wide = cr_name in clusterrole_cluster_wide
        target_namespaces = vulnerable_ns.keys() if is_cluster_wide else (
            clusterrole_to_namespaces.get(cr_name, set()) & vulnerable_ns.keys()
        )

        for ns_name in target_namespaces:
            ns_node = vulnerable_ns[ns_name]
            properties = _escalate_via_pod_properties("ClusterRole", attack_caps, ns_node["properties"])
            properties["cluster_scoped"] = is_cluster_wide
            edges.append({
                "start": {"value": clusterrole["id"]},
                "end": {"value": ns_node["id"]},
                "kind": "CAN_ESCALATE_VIA_POD",
                "properties": properties
            })

    return edges


# Workloads that act on attacker-writable namespace objects with their own privileges.
# A Role/ClusterRole that can write the trigger resource in such a namespace can abuse them.
NAMESPACE_TAKEOVER_TARGETS = {
    "argocd": {
        "edge_kind": "CAN_ESCALATE_VIA_ARGOCD_SECRET",
        "product": "ArgoCD",
        "keyword": "argocd",
        "namespace_flag": "has_argocd_keyword",
        "pod_flag": "has_argocd_image",
        "resource": "secrets",
        "capabilities": ("SECRET_CREATE", "SECRET_UPDATE", "SECRET_PATCH"),
        "capability_marker": "SECRET",
        "impact": "allowing command execution via ArgoCD controller",
        "attack_vector": "Modify ArgoCD Application secret to inject malicious commands that will be executed by argocd-application-controller with its privileges",
        "mitre_attack": "T1574.010",  # Hijack Execution Flow: Services File Permissions Weakness
        "reference": {"Role": "N/A", "ClusterRole": "https://shelltrail.com/research/working-as-intended-argocd-rce"},
    },
    "fluentd": {
        "edge_kind": "CAN_ESCALATE_VIA_FLUENTD_CONFIG",
        "product": "Fluentd",
        "keyword": "fluentd",
        "namespace_flag": "has_fluentd_keyword",
        "pod_flag": "has_fluentd_image",
        "resource": "configmaps",
        "capabilities": ("CONFIGMAP_CREATE", "CONFIGMAP_UPDATE", "CONFIGMAP_PATCH"),
        "capability_marker": "CONFIGMAP",
        "impact": "allowing host file exfiltration via Fluentd's exec plugin + symlink",
        "attack_vector": "Inject an 'exec' input plugin into Fluentd's extra-config ConfigMap that symlinks Fluentd's own log file to a sensitive host path (e.g. kubelet-client-current.pem); Fluentd's own tail input then leaks the file's contents into its stdout log, readable via 'kubectl logs'",
        "mitre_attack": "T1552.001",  # Unsecured Credentials: Credentials In Files
        "reference": {"Role": "N/A", "ClusterRole": "N/A"},
    },
}


def create_argocd_secret_manipulation_edges(role_nodes: List[Dict], clusterrole_nodes: List[Dict],
                                            namespace_nodes: List[Dict], pod_nodes: List[Dict]) -> List[Dict]:
    """
    Create CAN_ESCALATE_VIA_ARGOCD_SECRET edges showing secret manipulation attacks on ArgoCD.

    If a Role/ClusterRole has permissions to create/patch/update secrets in a namespace
    that contains "argocd" in its name OR runs ArgoCD images, this represents an attack
    vector because argocd-application-controller fetches configs from secrets and executes
    OS commands specified within them.
    """
    return _create_namespace_takeover_edges(NAMESPACE_TAKEOVER_TARGETS["argocd"],
                                            role_nodes, clusterrole_nodes, namespace_nodes, pod_nodes)


def create_fluentd_config_manipulation_edges(role_nodes: List[Dict], clusterrole_nodes: List[Dict],
                                             namespace_nodes: List[Dict], pod_nodes: List[Dict]) -> List[Dict]:
    """
    Create CAN_ESCALATE_VIA_FLUENTD_CONFIG edges showing config manipulation attacks on Fluentd.

    If a Role/ClusterRole has permissions to create/patch/update configmaps in a namespace
    that contains "fluentd" in its name OR runs Fluentd/Fluent Bit images, this represents
    an attack vector: Fluentd auto-includes extra config from a mounted ConfigMap, and a
    malicious config can use the 'exec' input plugin to replace Fluentd's own log file with
    a symlink to a sensitive host file (e.g. the kubelet client certificate). Fluentd's own
    log-tailing then reads through the symlink and leaks the file's contents into its
    stdout/error log, retrievable via 'kubectl logs' with no direct node or file access.
    """
    return _create_namespace_takeover_edges(NAMESPACE_TAKEOVER_TARGETS["fluentd"],
                                            role_nodes, clusterrole_nodes, namespace_nodes, pod_nodes)


def _create_namespace_takeover_edges(target: Dict[str, Any], role_nodes: List[Dict], clusterrole_nodes: List[Dict],
                                     namespace_nodes: List[Dict], pod_nodes: List[Dict]) -> List[Dict]:
    """
    Create edges from Roles/ClusterRoles that can write the target's trigger resource to the
    namespaces where the target product runs (detected by namespace name or pod image).
    Roles only reach their own namespace; ClusterRoles reach every detected namespace.
    """
    edges = []
    ns_map = {ns["properties"]["name"]: ns for ns in namespace_nodes}

    # namespace name -> detection method
    target_namespaces = {
        name: "namespace-keyword"
        for name, ns in ns_map.items()
        if ns["properties"].get(target["namespace_flag"], False)
    }
    for pod in pod_nodes:
        if pod["properties"].get(target["pod_flag"], False):
            ns_name = pod["properties"]["namespace"]
            target_namespaces[ns_name] = "namespace-keyword+pod-image" if ns_name in target_namespaces else "pod-image"

    if not target_namespaces:
        return edges

    def edge(role_kind, role, ns_name, attack_caps, extra):
        detection_method = target_namespaces[ns_name]
        where = {
            "namespace-keyword": f"in namespace '{ns_name}' (contains '{target['keyword']}' keyword)",
            "pod-image": f"in namespace '{ns_name}' (runs {target['product']} pods)",
        }.get(detection_method, f"in {target['product']} namespace '{ns_name}'")

        return {
            "start": {"value": role["id"]},
            "end": {"value": ns_map[ns_name]["id"]},
            "kind": target["edge_kind"],
            "properties": {
                "edge_category": classify_edge(target["edge_kind"]),
                "description": f"{role_kind} can manipulate {target['resource']} {where}, {target['impact']}",
                f"{target['keyword']}_detection_method": detection_method,
                **extra,
                "attack_capabilities": [cap for cap in attack_caps if target["capability_marker"] in cap],
                "attack_vector": target["attack_vector"],
                "mitre_attack": target["mitre_attack"],
                "reference": target["reference"][role_kind],
            }
        }

    def can_write(role):
        attack_caps = role["properties"].get("attack_capabilities", [])
        return attack_caps if any(cap in attack_caps for cap in target["capabilities"]) else None

    # Roles (namespace-scoped)
    for role in role_nodes:
        attack_caps = can_write(role)
        ns_name = role["properties"].get("namespace", "")
        if attack_caps and ns_name in ns_map and ns_name in target_namespaces:
            edges.append(edge("Role", role, ns_name, attack_caps, {}))

    # ClusterRoles (can write in ANY namespace)
    for clusterrole in clusterrole_nodes:
        attack_caps = can_write(clusterrole)
        if attack_caps:
            for ns_name in target_namespaces:
                edges.append(edge("ClusterRole", clusterrole, ns_name, attack_caps, {"cluster_scoped": True}))

    return edges


def create_phantom_resource_creation_edges(
    phantom_nodes: List[Dict],
    roles_raw: List[Any],
    clusterroles_raw: List[Any],
    clusterrole_bindings: ClusterRoleBindingMaps
) -> List[Dict]:
    """
    Create CAN_CREATE_SECRETS / CAN_CREATE_CONFIGMAPS edges from Roles/ClusterRoles
    to phantom (missing) Secret/ConfigMap nodes.

    The 'create' verb can only ever apply to objects that don't exist yet, so it's
    meaningless against already-ingested resources - the generic RBAC edge builder
    only knows about those, so 'create' grants on secrets/configmaps never connect
    to anything. The one case a CREATE edge is actually meaningful is a phantom
    node: a resource a Pod references that hasn't been created yet. This function
    closes that gap.

    Args:
        phantom_nodes: List of phantom Secret/ConfigMap node dictionaries
        roles_raw: List of V1Role objects
        clusterroles_raw: List of V1ClusterRole objects
        clusterrole_bindings: Result of build_clusterrole_binding_maps()

    Returns:
        List of edge dictionaries
    """
    KIND_TO_RESOURCE = {"K8sSecret": "secrets", "K8sConfigMap": "configmaps"}
    RESOURCE_TO_EDGE = {"secrets": "CAN_CREATE_SECRETS", "configmaps": "CAN_CREATE_CONFIGMAPS"}

    edges = []
    if not phantom_nodes:
        return edges

    # Group phantom nodes by (namespace, resource_type)
    phantom_by_ns_resource = {}
    for node in phantom_nodes:
        resource = KIND_TO_RESOURCE.get(node["kinds"][0])
        if not resource:
            continue
        ns = node["properties"]["namespace"]
        phantom_by_ns_resource.setdefault((ns, resource), []).append(node)

    if not phantom_by_ns_resource:
        return edges

    def _rule_grants_create(rule, resource) -> bool:
        resources = rule.resources or []
        verbs = rule.verbs or []
        return ("create" in verbs or "*" in verbs) and (resource in resources or "*" in resources)

    # Namespaced Roles
    for role in roles_raw:
        if not role.rules:
            continue
        ns = role.metadata.namespace
        for resource in RESOURCE_TO_EDGE:
            phantoms = phantom_by_ns_resource.get((ns, resource))
            if not phantoms:
                continue
            if not any(_rule_grants_create(rule, resource) for rule in role.rules):
                continue
            for phantom in phantoms:
                edges.append({
                    "start": {"value": role.metadata.uid},
                    "end": {"value": phantom["id"]},
                    "kind": RESOURCE_TO_EDGE[resource],
                    "properties": {
                        "edge_category": classify_edge(RESOURCE_TO_EDGE[resource]),
                        "description": f"Role can create the missing {resource[:-1]} referenced by one or more pods, planting attacker-controlled content",
                        "targets_phantom_resource": True
                    }
                })

    # ClusterRoles (namespace-scoped via RoleBinding, or cluster-wide via ClusterRoleBinding)
    clusterrole_to_namespaces, clusterrole_cluster_wide = clusterrole_bindings

    for clusterrole in clusterroles_raw:
        if not clusterrole.rules:
            continue
        cr_name = clusterrole.metadata.name
        bound_namespaces = clusterrole_to_namespaces.get(cr_name, set())
        is_cluster_wide = cr_name in clusterrole_cluster_wide
        if not bound_namespaces and not is_cluster_wide:
            continue

        for resource in RESOURCE_TO_EDGE:
            if not any(_rule_grants_create(rule, resource) for rule in clusterrole.rules):
                continue

            target_namespaces = set(bound_namespaces)
            if is_cluster_wide:
                target_namespaces.update(
                    ns for (ns, res) in phantom_by_ns_resource if res == resource
                )

            for ns in target_namespaces:
                for phantom in phantom_by_ns_resource.get((ns, resource), []):
                    edges.append({
                        "start": {"value": clusterrole.metadata.uid},
                        "end": {"value": phantom["id"]},
                        "kind": RESOURCE_TO_EDGE[resource],
                        "properties": {
                            "edge_category": classify_edge(RESOURCE_TO_EDGE[resource]),
                            "description": f"ClusterRole can create the missing {resource[:-1]} referenced by one or more pods, planting attacker-controlled content",
                            "cluster_scoped": is_cluster_wide,
                            "targets_phantom_resource": True
                        }
                    })

    return edges
