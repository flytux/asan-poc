echo "==== 3) Prepare Gitlab Runner  ===="

openssl s_client -showcerts -connect gitlab.amc.seoul.kr:443 -servername gitlab.amc.seoul.kr < /dev/null 2>/dev/null | openssl x509 -outform PEM > gitlab.amc.seoul.kr.crt

kubectl create secret generic gitlab-runner-tls --from-file=gitlab.amc.seoul.kr.crt  -n gitlab

cat << EOF > gitlab-runner-values.yaml
gitlabUrl: https://gitlab.${domain_name}

runnerToken: glrt-vZuAwYks8JRqx5GULT-f
rbac:
  create: true

certsSecretName: gitlab-runner-tls 

runners:
  config: |
    [[runners]]
      [runners.kubernetes]
        namespace = "{{.Release.Namespace}}"
        image = "ubuntu:20.04"
    [[runners.kubernetes.volumes.pvc]]
      mount_path = "/cache/maven.repository"
      name = "gitlab-runner-cache-pvc"
EOF

kubectl -n gitlab apply -f - <<"EOF"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: gitlab-runner-cache-pvc
  namespace: gitlab
spec:
  storageClassName: nfs-csi
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
EOF

echo "==== 4) Import Repository and Install runner  ===="


echo "==== Create user argo / abcd!234  ===="
echo "==== Admin > Setting >  General > Import and Export > Repository by URL  ===="
echo "==== Import https://github.com/flytux/kw-mvn, kw-mvn-deploy  ===="

helm upgrade -i gitlab-runner gitlab/gitlab-runner -f gitlab-runner-values.yaml -n gitlab

echo "==== 5) Install ArgoCD  ===="

kubectl create namespace argocd

kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

kubectl patch cm argocd-cmd-params-cm -n argocd --type merge -p '{"data":{"server.insecure": "true"}}'

kubectl rollout restart deploy argocd-server -n argocd

kubectl -n argocd apply -f - <<"EOF"
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: argocd-server
  namespace: argocd
spec:
  entryPoints:
    - websecure
  routes:
    - kind: Rule
      match: Host(`argocd.${domain_name}`)
      priority: 10
      services:
        - name: argocd-server
          port: 80
    - kind: Rule
      match: Host(`argocd.${domain_name}`) && Headers(`Content-Type`, `application/grpc`)
      priority: 11
      services:
        - name: argocd-server
          port: 80
          scheme: h2c
  tls: {}
EOF

kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

kubectl exec -it -n argocd $(k get pods -l app.kubernetes.io/name=argocd-server -o name -n argocd) bash

argocd login argocd-server.argocd --insecure --username admin --password ysdspBnfCeXOqIoK

argocd repo add https://gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git --username argo --insecure-skip-server-verification

# Create ArgoCD applications

$ kubectl -n argocd apply -f - <<"EOF"
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kw-mvn
spec:
  destination:
    name: ''
    namespace: deploy
    server: 'https://kubernetes.default.svc'
  source:
    path: .
    repoURL: 'https://gitlab.${domain_name}/argo/kw-mvn-deploy.git'
    targetRevision: main
  sources: []
  project: default
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
EOF

Kiali 

rancher-monitoring:104.0.0+up45.31.1
while :; do curl -s 192.168.122.11:31380/productpage | grep -o "<title>.*</title>"; sleep 0.1; done

Logging

helm repo add grafana https://grafana.github.io/helm-charts

helm repo add kube-logging https://kube-logging.github.io/helm-charts

helm upgrade --install --wait --create-namespace --namespace logging logging-operator kube-logging/logging-operator

helm fetch grafana/loki --version 2.9.1

tar xvf loki-2.9.1.tgz

rm loki/templates/podsecuritypolicy.yaml

helm upgrade -i loki loki -n logging

kubectl -n logging apply -f - <<"EOF"
apiVersion: logging.banzaicloud.io/v1beta1
kind: Output
metadata:
 name: loki-output
spec:
 loki:
   url: http://loki:3100
   configure_kubernetes_labels: true
   buffer:
     timekey: 1m
     timekey_wait: 30s
     timekey_use_utc: true
EOF

kubectl -n logging apply -f - <<"EOF"
apiVersion: logging.banzaicloud.io/v1beta1
kind: Flow
metadata:
  name: loki-flow
spec:
  filters:
    - tag_normaliser: {}
    - parser:
        remove_key_name_field: true
        reserve_data: true
        parse:
          type: nginx
  match:
    - select:
        labels:
          app.kubernetes.io/name: log-generator
  localOutputRefs:
    - loki-output
EOF

kubectl -n logging apply -f - <<"EOF"
apiVersion: logging.banzaicloud.io/v1beta1
kind: Logging
metadata:
  name: default-logging-simple
spec:
  fluentd:
    logLevel: debug
  fluentbit: {}
  controlNamespace: logging
EOF

helm upgrade --install --wait --create-namespace --namespace logging log-generator kube-logging/log-generator



kubectl get secret -n logging default-logging-simple-fluentd-app -o jsonpath='{.data.fluentd\.conf}' | base64 -d

Add Grafana Loki Datasource and Explore log

S3 Log Output
---
apiVersion: v1
data:
  access_key_id: Qjg3MDZBNjlCN0U0MUNFOTc4QUI=
  secret_access_key: N0M0OEJENDFDNjc5OTNBRDhCNjkzQTZCMzM1RUZCNkUyNzkyMUFBNA==
kind: Secret
metadata:
  name: s3-auth
  namespace: logging
type: Opaque
---
apiVersion: logging.banzaicloud.io/v1beta1
kind: Flow
metadata:
  name: app-log-flow
  namespace: ns-app-core-dev
spec:
  filters:
  - parser:
      parse:
        type: json
      remove_key_name_field: false
      reserve_data: true
  localOutputRefs:
  - s3-output
  match:
  - select:
      labels:
        tier: backend
---
apiVersion: logging.banzaicloud.io/v1beta1
kind: Output
metadata:
  name: s3-output
  namespace: logging
spec:
  s3:
    aws_key_id:
      valueFrom:
        secretKeyRef:
          key: access_key_id
          name: s3-auth
    aws_sec_key:
      valueFrom:
        secretKeyRef:
          key: secret_access_key
          name: s3-auth
    buffer:
      timekey: 1m
      timekey_use_utc: true
      timekey_wait: 30s
    force_path_style: "true"
    path: app-log/${tag}/%Y/%m/%d/
    s3_bucket: hro-app-log
    s3_endpoint: https://kr.object.private.fin-ncloudstorage.com
    s3_region: kr-standard
