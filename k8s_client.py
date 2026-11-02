"""
Kubernetes client initialization and configuration.
Handles authentication auto-detection for in-cluster and kubeconfig.
"""

import sys
from typing import Dict, Any
from kubernetes import client, config


def get_api_clients() -> Dict[str, Any]:
    """
    Load Kubernetes configuration and return the API clients KuberHound uses.

    Auto-detects authentication: tries in-cluster config first, falls back to kubeconfig.

    Returns:
        Dict with "core", "rbac", "apps" and "networking" API clients

    Raises:
        SystemExit: If configuration cannot be loaded
    """
    try:
        config.load_incluster_config()
        print("Using in-cluster configuration")
    except config.ConfigException:
        try:
            config.load_kube_config()
            print("Using kubeconfig from ~/.kube/config")
        except config.ConfigException as e:
            print(f"Error: Could not load Kubernetes configuration: {e}")
            sys.exit(1)

    return {
        "core": client.CoreV1Api(),
        "rbac": client.RbacAuthorizationV1Api(),
        "apps": client.AppsV1Api(),
        "networking": client.NetworkingV1Api(),
    }
