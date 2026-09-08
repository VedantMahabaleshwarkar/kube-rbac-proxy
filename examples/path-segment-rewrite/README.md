# path segment rewrite example

> Note to try this out with minikube, make sure you enable RBAC correctly as explained [here](../minikube-rbac).

This example demonstrates the `byPathSegment` rewrite, which extracts a value from the URL path to use in a SubjectAccessReview. This is similar to the [query parameter rewrite example](../rewrites), but instead of reading the namespace from a query parameter, it reads it from a path segment.

We deploy a [prometheus-example-app](https://github.com/brancz/prometheus-example-app) and protect it with kube-rbac-proxy. A requesting entity must be allowed to call the `metrics` subresource on a Kubernetes Namespace, where the namespace name is extracted from the URL path. For a request to `/metrics/default`, path segment at index 1 (0-based) yields `default`. This is configured in the file passed to the kube-rbac-proxy with the `--config-file` flag. Additionally the `--upstream` flag has to be set to configure the application that should be proxied to on successful authentication as well as authorization.

The kube-rbac-proxy itself also requires RBAC access, in order to perform TokenReviews as well as SubjectAccessReviews. These are the APIs available from the Kubernetes API to authenticate and then validate the authorization of an entity.

```bash
$ kubectl create -f deployment.yaml
```

The content of this manifest is:

[embedmd]:# (./deployment.yaml)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-rbac-proxy
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy
subjects:
- kind: ServiceAccount
  name: kube-rbac-proxy
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy
rules:
- apiGroups: ["authentication.k8s.io"]
  resources:
  - tokenreviews
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources:
  - subjectaccessreviews
  verbs: ["create"]
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: kube-rbac-proxy
  name: kube-rbac-proxy
spec:
  ports:
  - name: https
    port: 8443
    targetPort: https
  selector:
    app: kube-rbac-proxy
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-rbac-proxy
data:
  config-file.yaml: |+
    authorization:
      rewrites:
        byPathSegment:
          index: 1
      resourceAttributes:
        apiVersion: v1
        resource: namespace
        subresource: metrics
        namespace: "{{ .Value }}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-rbac-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-rbac-proxy
  template:
    metadata:
      labels:
        app: kube-rbac-proxy
    spec:
      securityContext:
        runAsUser: 65532
      serviceAccountName: kube-rbac-proxy
      containers:
      - name: kube-rbac-proxy
        image: quay.io/brancz/kube-rbac-proxy:v0.21.1
        args:
        - "--secure-listen-address=0.0.0.0:8443"
        - "--upstream=http://127.0.0.1:8081/"
        - "--config-file=/etc/kube-rbac-proxy/config-file.yaml"
        - "--logtostderr=true"
        - "--v=10"
        ports:
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: config
          mountPath: /etc/kube-rbac-proxy
        securityContext:
          allowPrivilegeEscalation: false
      - name: prometheus-example-app
        image: quay.io/brancz/prometheus-example-app:v0.5.0
        args:
        - "--bind=127.0.0.1:8081"
      volumes:
      - name: config
        configMap:
          name: kube-rbac-proxy
```

Once the prometheus-example-app is up and running, we can test it. In order to test it, we deploy a client that performs a `curl` against the above deployment with the namespace embedded in the URL path (`/metrics/default`). Because it has the correct RBAC roles, the request will succeed.

```bash
$ kubectl create -f client-rbac.yaml
```

The content of this manifest is:

[embedmd]:# (./client-rbac.yaml)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: namespace-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: namespace-metrics
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: namespace-metrics
rules:
- apiGroups: [""]
  resources:
  - namespace/metrics
  verbs: ["get"]
```

Then you can test the setup with a curl command that includes the namespace in the path:

```bash
$ curl -v -s -k -H "Authorization: Bearer <token>" https://kube-rbac-proxy.default.svc:8443/metrics/default
```

The path `/metrics/default` is split into segments: `metrics` (index 0) and `default` (index 1). The `byPathSegment` rewrite with `index: 1` extracts `default` and uses it as the namespace in the SubjectAccessReview.
