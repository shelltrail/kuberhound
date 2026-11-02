#!/usr/bin/env bash
# Deploy or tear down an isolated per-user instance of lab 08 (phantom ConfigMap RCE).
#
# Usage:
#   ./08-deploy.sh <user-id>            Deploy namespace 08-phantom-configmap-rce-<user-id>
#   ./08-deploy.sh <user-id> --delete   Tear down that namespace
#
# <user-id> must be a valid DNS-1123 label fragment: lowercase alphanumeric or '-'.
# It's appended to the namespace name, which has a 63-char limit, so keep it short.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/08-phantom-configmap-rce.yaml"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <user-id> [--delete]" >&2
  exit 1
fi

USER_ID="$1"
ACTION="${2:-apply}"

if [[ ! "$USER_ID" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
  echo "Error: <user-id> must be lowercase alphanumeric or '-' (DNS-1123 label), e.g. 'team7' or 'alice-2'" >&2
  exit 1
fi

NAMESPACE="08-phantom-configmap-rce-${USER_ID}"
if [[ ${#NAMESPACE} -gt 63 ]]; then
  echo "Error: resulting namespace '$NAMESPACE' exceeds the 63-char Kubernetes name limit" >&2
  exit 1
fi

case "$ACTION" in
  apply)
    echo "[*] Deploying lab 08 to namespace: $NAMESPACE"
    sed "s/USERID/${USER_ID}/g" "$TEMPLATE" | kubectl apply -f -
    echo "[*] Done. Namespace: $NAMESPACE"
    ;;
  --delete|delete)
    echo "[*] Deleting namespace: $NAMESPACE"
    kubectl delete namespace "$NAMESPACE" --ignore-not-found
    ;;
  *)
    echo "Error: unknown action '$ACTION' (expected nothing or --delete)" >&2
    exit 1
    ;;
esac
