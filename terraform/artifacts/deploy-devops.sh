#!/bin/bash

echo "==== Start installing devops services ===="

echo "==== 1) Install Harbor ===="

helm repo add harbor https://helm.goharbor.io --force-update

kubectl create ns harbor

kubectl create secret tls harbor-ingress-tls --key artifacts/harbor.key --cert artifacts/harbor.crt -n harbor

cat << EOF > harbor.yaml
expose:
  tls:
    certSource: secret
    secret:
      secretName: "harbor-ingress-tls"
  ingress:
    hosts:
      core: harbor.amc.seoul.kr
externalURL: https://harbor.amc.seoul.kr
EOF

helm upgrade -i harbor harbor/harbor --wait -n harbor -f harbor.yaml

nerdctl login harbor.amc.seoul.kr -u admin -p Harbor12345


echo "==== 2) Install Gitlab ===="

helm repo add gitlab https://charts.gitlab.io --force-update

helm upgrade -i gitlab gitlab/gitlab --wait --timeout 10m \
  --version 8.3.2 \
  --set global.edition=ce \
  --set global.hosts.domain=amc.seoul.kr \
  --set global.ingress.configureCertmanager=false \
  --set global.ingress.provider=traefik \
  --set global.ingress.class=traefik \
  --set certmanager.install=false \
  --set nginx-ingress.enabled=false \
  --set gitlab-runner.install=false \
  --set prometheus.install=false \
  --set registry.enabled=false \
  -n gitlab --create-namespace

kubectl get -n gitlab secret gitlab-gitlab-initial-root-password -ojsonpath='{.data.password}' | base64 -d

kubectl create secret tls gitlab-ingress-tls --key artifacts/gitlab.key --cert artifacts/gitlab.crt -n gitlab

kubectl patch ingress gitlab-webservice-default -n gitlab --type='json' -p='[{"op" : "replace" ,"path" : "/spec/tls/0/secretName" ,"value" : "gitlab-ingress-tls"}]'

kubectl get cm coredns -n kube-system -o yaml | sed 's/ready/ready\n        hosts {\n          192.168.100.1 gitlab.amc.seoul.kr\n          fallthrough\n        }/' | kubectl replace -f -

kubectl rollout restart deploy coredns -n kube-system

echo "==== 3) Prepare Gitlab Runner  ===="

#openssl s_client -showcerts -connect gitlab.amc.seoul.kr:443 -servername gitlab.amc.seoul.kr < /dev/null 2>/dev/null | openssl x509 -outform PEM > gitlab.amc.seoul.kr.crt
#
#kubectl create secret generic gitlab-runner-tls --from-file=gitlab.amc.seoul.kr.crt  -n gitlab
#
#cat << EOF > gitlab-runner-values.yaml
#gitlabUrl: https://gitlab.amc.seoul.kr
#
#runnerToken: glrt-vZuAwYks8JRqx5GULT-f
#rbac:
#  create: true
#
#certsSecretName: gitlab-runner-tls 
#
#runners:
#  config: |
#    [[runners]]
#      [runners.kubernetes]
#        namespace = "{{.Release.Namespace}}"
#        image = "ubuntu:20.04"
#    [[runners.kubernetes.volumes.pvc]]
#      mount_path = "/cache/maven.repository"
#      name = "gitlab-runner-cache-pvc"
#EOF
#
#kubectl -n gitlab apply -f - <<"EOF"
#apiVersion: v1
#kind: PersistentVolumeClaim
#metadata:
#  name: gitlab-runner-cache-pvc
#  namespace: gitlab
#spec:
#  storageClassName: nfs-csi
#  accessModes:
#  - ReadWriteOnce
#  resources:
#    requests:
#      storage: 1Gi
#EOF
#
#echo "==== 4) Import Repository and Install runner  ===="
#
#
#echo "==== Create user argo / abcd!234  ===="
#echo "==== Admin > Setting >  General > Import and Export > Repository by URL  ===="
#echo "==== Import https://github.com/flytux/kw-mvn, kw-mvn-deploy  ===="


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
      match: Host(`argocd.amc.seoul.kr`)
      priority: 10
      services:
        - name: argocd-server
          port: 80
    - kind: Rule
      match: Host(`argocd.amc.seoul.kr`) && Headers(`Content-Type`, `application/grpc`)
      priority: 11
      services:
        - name: argocd-server
          port: 80
          scheme: h2c
  tls: {}
EOF

sleep 10

kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

#kubectl exec -it -n argocd $(k get pods -l app.kubernetes.io/name=argocd-server -o name -n argocd) bash
#
#argocd login argocd-server.argocd --insecure --username admin --password ysdspBnfCeXOqIoK
#
#argocd repo add https://gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git --username argo --insecure-skip-server-verification
#
## Create ArgoCD applications
#
#$ kubectl -n argocd apply -f - <<"EOF"
#apiVersion: argoproj.io/v1alpha1
#kind: Application
#metadata:
#  name: kw-mvn
#spec:
#  destination:
#    name: ''
#    namespace: deploy
#    server: 'https://kubernetes.default.svc'
#  source:
#    path: .
#    repoURL: 'https://gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git'
#    targetRevision: main
#  sources: []
#  project: default
#  syncPolicy:
#    syncOptions:
#      - CreateNamespace=true
#EOF
#
#Kiali 
#
#rancher-monitoring:104.0.0+up45.31.1
#while :; do curl -s 192.168.122.11:31380/productpage | grep -o "<title>.*</title>"; sleep 0.1; done
#
#Logging
#
#helm repo add grafana https://grafana.github.io/helm-charts
#
#helm repo add kube-logging https://kube-logging.github.io/helm-charts
#
#helm upgrade --install --wait --create-namespace --namespace logging logging-operator kube-logging/logging-operator
#
#helm fetch grafana/loki --version 2.9.1
#
#tar xvf loki-2.9.1.tgz
#
#rm loki/templates/podsecuritypolicy.yaml
#
#helm upgrade -i loki loki -n logging
#
#kubectl -n logging apply -f - <<"EOF"
#apiVersion: logging.banzaicloud.io/v1beta1
#kind: Output
#metadata:
# name: loki-output
#spec:
# loki:
#   url: http://loki:3100
#   configure_kubernetes_labels: true
#   buffer:
#     timekey: 1m
#     timekey_wait: 30s
#     timekey_use_utc: true
#EOF
#
#kubectl -n logging apply -f - <<"EOF"
#apiVersion: logging.banzaicloud.io/v1beta1
#kind: Flow
#metadata:
#  name: loki-flow
#spec:
#  filters:
#    - tag_normaliser: {}
#    - parser:
#        remove_key_name_field: true
#        reserve_data: true
#        parse:
#          type: nginx
#  match:
#    - select:
#        labels:
#          app.kubernetes.io/name: log-generator
#  localOutputRefs:
#    - loki-output
#EOF
#
#kubectl -n logging apply -f - <<"EOF"
#apiVersion: logging.banzaicloud.io/v1beta1
#kind: Logging
#metadata:
#  name: default-logging-simple
#spec:
#  fluentd:
#    logLevel: debug
#  fluentbit: {}
#  controlNamespace: logging
#EOF
#
#helm upgrade --install --wait --create-namespace --namespace logging log-generator kube-logging/log-generator
#
#
#
#kubectl get secret -n logging default-logging-simple-fluentd-app -o jsonpath='{.data.fluentd\.conf}' | base64 -d
#
#Add Grafana Loki Datasource and Explore log
#
