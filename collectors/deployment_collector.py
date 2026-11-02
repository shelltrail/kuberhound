"""
Deployment collector for Kubernetes deployments (nodes only).
"""

from typing import Dict, Any
from .base import BaseCollector, template_service_account, match_labels


class DeploymentCollector(BaseCollector):
    """Collects Kubernetes deployments and converts them to OpenGraph nodes."""

    kind = "K8sDeployment"
    resource = "deployments"
    list_method = "list_deployment_for_all_namespaces"

    def _properties(self, deployment: Any) -> Dict[str, Any]:
        spec = deployment.spec
        return {
            "replicas": spec.replicas if spec and spec.replicas else 1,
            "service_account": template_service_account(deployment),
            "selector": match_labels(deployment),
            "strategy": spec.strategy.type if spec and spec.strategy and spec.strategy.type else "RollingUpdate",
        }
