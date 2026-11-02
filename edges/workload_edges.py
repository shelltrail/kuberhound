"""
Workload relationship edges.
Creates edges for workload resources (Services, Deployments, DaemonSets, StatefulSets, Ingresses).
"""

from typing import List, Dict, Any, Tuple
from .edge_categories import classify_edge


def create_workload_edges(workload_nodes: List[Dict[str, Any]],
                          service_nodes: List[Dict[str, Any]],
                          pod_nodes: List[Dict[str, Any]],
                          services_raw: List[Any],
                          controllers_raw: List[Tuple[str, List[Any]]],
                          ingresses_raw: List[Any]) -> List[Dict[str, Any]]:
    """
    Create all workload-related edges.

    Edges created:
    - IN_NAMESPACE: Workload → Namespace
    - EXPOSES: Service → Pod (based on selector matching)
    - MANAGES: Deployment/DaemonSet/StatefulSet → Pod (based on selector matching)
    - ROUTES_TO: Ingress → Service (based on backend references)
    - USES_SERVICEACCOUNT: Deployment/DaemonSet/StatefulSet → ServiceAccount

    Args:
        workload_nodes: Service, Deployment, DaemonSet, StatefulSet and Ingress node dictionaries
        service_nodes: List of service node dictionaries
        pod_nodes: List of pod node dictionaries
        services_raw: List of V1Service objects
        controllers_raw: List of (controller kind, raw objects), e.g. ("Deployment", deployments_raw)
        ingresses_raw: List of V1Ingress objects

    Returns:
        List of edge dictionaries with placeholder IDs
    """
    edges = []
    pods_by_namespace = _index_pods(pod_nodes)

    # IN_NAMESPACE: Workload → Namespace
    for workload in workload_nodes:
        namespace = workload["properties"].get("namespace")
        if namespace:
            edges.append(_edge(workload["id"], f"namespace:{namespace}", "IN_NAMESPACE"))

    # EXPOSES: Service → Pod
    for service in services_raw:
        if service.spec and service.spec.selector:
            edges.extend(_selector_edges(service, service.spec.selector, pods_by_namespace, "EXPOSES",
                                         {"service_name": service.metadata.name}))

    # MANAGES: Deployment/DaemonSet/StatefulSet → Pod
    for controller_kind, controllers in controllers_raw:
        for controller in controllers:
            spec = controller.spec
            if spec and spec.selector and spec.selector.match_labels:
                edges.extend(_selector_edges(controller, spec.selector.match_labels, pods_by_namespace, "MANAGES",
                                             {"controller": controller_kind,
                                              "controller_name": controller.metadata.name}))

    # ROUTES_TO: Ingress → Service
    edges.extend(_create_ingress_to_service_edges(ingresses_raw, service_nodes))

    # USES_SERVICEACCOUNT: Deployment/DaemonSet/StatefulSet → ServiceAccount
    for controller_kind, controllers in controllers_raw:
        for controller in controllers:
            template = controller.spec.template if controller.spec else None
            if not template or not template.spec:
                continue
            sa_name = template.spec.service_account_name or "default"
            edges.append(_edge(controller.metadata.uid,
                               f"serviceaccount:{controller.metadata.namespace}:{sa_name}",
                               "USES_SERVICEACCOUNT", {"workload_type": controller_kind}))

    return edges


def _edge(start: str, end: str, kind: str, properties: Dict[str, Any] = None) -> Dict[str, Any]:
    return {
        "start": {"value": start},
        "end": {"value": end},
        "kind": kind,
        "properties": {"edge_category": classify_edge(kind), **(properties or {})}
    }


def _index_pods(pod_nodes: List[Dict[str, Any]]) -> Dict[str, List[Tuple[Dict[str, Any], Dict[str, str]]]]:
    """Group pods by namespace, with their "key=value" label strings parsed once into a dict."""
    pods_by_namespace = {}
    for pod_node in pod_nodes:
        labels = dict(label.split("=", 1) for label in pod_node["properties"].get("labels", []) if "=" in label)
        pods_by_namespace.setdefault(pod_node["properties"].get("namespace"), []).append((pod_node, labels))
    return pods_by_namespace


def _selector_edges(obj: Any, selector: Dict[str, str], pods_by_namespace: Dict, kind: str,
                    properties: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Create edges from obj to every pod in its namespace whose labels match the selector."""
    return [
        _edge(obj.metadata.uid, pod_node["id"], kind, properties)
        for pod_node, labels in pods_by_namespace.get(obj.metadata.namespace, [])
        if _selector_matches(selector, labels)
    ]


def _create_ingress_to_service_edges(ingresses_raw: List[Any],
                                      service_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create ROUTES_TO edges from Ingresses to Services based on backend references.
    """
    edges = []

    # "namespace:name" -> service node ID
    service_map = {
        f"{node['properties']['namespace']}:{node['properties']['name']}": node["id"]
        for node in service_nodes
        if node["properties"].get("namespace") and node["properties"].get("name")
    }

    for ingress in ingresses_raw:
        if not ingress.spec:
            continue

        def add_route(backend, properties):
            service_id = service_map.get(f"{ingress.metadata.namespace}:{backend.service.name}")
            if service_id:
                edges.append(_edge(ingress.metadata.uid, service_id, "ROUTES_TO",
                                   {"ingress_name": ingress.metadata.name, **properties}))

        default_backend = ingress.spec.default_backend
        if default_backend and default_backend.service:
            add_route(default_backend, {"backend_type": "default"})

        for rule in ingress.spec.rules or []:
            if not rule.http:
                continue
            for path in rule.http.paths or []:
                if path.backend and path.backend.service:
                    add_route(path.backend, {
                        "host": rule.host if rule.host else "*",
                        "path": path.path if path.path else "/",
                        "backend_type": "rule"
                    })

    return edges


def _selector_matches(selector: Dict[str, str], labels: Dict[str, str]) -> bool:
    """Check that the selector is non-empty and all its key-value pairs match the labels."""
    return bool(selector) and all(labels.get(key) == value for key, value in selector.items())
