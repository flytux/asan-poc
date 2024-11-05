---

- Nutanix Infra에 오픈소스 CI/CD 서비스 설치
- Traefik Ingress Controller, Velero 등 Nutanix 서비스 이용

---

### rke2 클러스터 생성 - manual installation

```
# 마스터 노드 설치
curl -sfL https://get.rke2.io | sh -
systemctl enable rke2-server --now

# KubeConfig 설정
mkdir ~/.kube
cp /etc/rancher/rke2/rke2.yaml ~/.kube/config

# 클러스터 상태 확인
kubectl get nodes
kubectl get pods -A

# 클러스터 토큰 확인
cat /var/lib/rancher/rke2/server/token

# 워커노드 설치
# 워커노드 ssh 접속

# 클러스터 노드 추가용 설정 파일 생성
mkdir -p /etc/rancher/rke2
cat <<EOF >> /etc/rancher/rke2/config.yaml
server: https://마스터노드_IP:9345
token: 클러스터)토큰
EOF

# 클러스터 노드 추가
curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="agent" sh -
systemctl enable rke2-agent --now

# 마스터 노드 접속 후
# 클러스터 상태 확인
kubectl get nodes
kubectl get pods -A
```


### Cert-Manager 설치

```bash

kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.10.0/cert-manager.yaml

```

### Rancher 설치

```bash

helm repo add rancher-latest https://releases.rancher.com/server-charts/latest 
 
helm repo update
 
helm upgrade -i rancher rancher-2.9.1.tgz \
--set hostname=rancher.amc.seoul.kr --set bootstrapPassword=admin \
--set replicas=1 --set global.cattle.psp.enabled=false \
--set auditLog.level=1 \
--create-namespace -n cattle-system

```

### NFS-Server 설치

```bash

dnf install nfs-utils

mkdir -p /mnt/pv
chmod 707 /mnt/pv
chown -R 65534:65534 /mnt/pv 
systemctl start nfs-server
vi /etc/exports
/mnt/pv 192.168.122.11(rw,sync,no_root_squash)
systemctl restart nfs-server
exportfs -v

```

### Storage Class 설치

```bash

curl -skSL https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/v4.5.0/deploy/install-driver.sh | bash -s v4.5.0 --

cat <<EOF > nfs-sc.yml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-csi
provisioner: nfs.csi.k8s.io
parameters:
  server: 192.168.122.11
  share: /mnt/pv
  mountPermissions: "0777"
reclaimPolicy: Retain 
volumeBindingMode: Immediate
mountOptions:
  - nfsvers=4.1
EOF

kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/deploy/example/pvc-nfs-csi-dynamic.yaml
kubectl patch storageclass nfs-csi -n kube-system -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

```

### Harbor 설치

```bash
 
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout harbor.key -out harbor.crt -subj '/CN=harbor.amc.seoul.kr' \
  -addext 'subjectAltName=DNS:harbor.amc.seoul.kr'

kubectl create ns harbor
kubectl create secret tls harbor-ingress-tls --key harbor.key --cert harbor.crt -n harbor

helm repo add harbor https://helm.goharbor.io

cat << EOF > harbor-values.yaml
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

helm upgrade -i harbor harbor/harbor -n harbor -f harbor-values.yaml 

# Ingress Annotations for tls

  traefik.ingress.kubernetes.io/router.entrypoints: websecure
  traefik.ingress.kubernetes.io/router.tls: "true"


scp harbor.key node-01:/etc/pki/ca-trust/source/anchors/
scp harbor.crt node-01:/etc/pki/ca-trust/source/anchors/

ssh node-01 update-ca-trust

ssh node-01

cat << EOF >> /etc/hosts
192.168.122.11 harbor.amc.seoul.kr
EOF

# RKE2 / K3S registry

cat << EOF > /etc/rancher/rke2/registries.yaml
mirrors:
  docker.io:
    endpoint:
      - "https://harbor.amc.seoul.kr"
configs:
  "harbor.amc.seou.kr":
    auth:
      username: admin # this is the registry username
      password: Harbor12345 # this is the registry password
    tls:
      cert_file: /etc/pki/ca-trust/source/anchors/harbor.crt
      key_file: /etc/pki/ca-trust/source/anchors/harbor.key
EOF

# KubeADM RKE2 / K3S registry

cat << EOF > /etc/containerd/containerd.toml
[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
   [plugins."io.containerd.grpc.v1.cri".containerd]
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            SystemdCgroup = true
      [plugins."io.containerd.grpc.v1.cri".registry]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
          [plugins."io.containerd.grpc.v1.cri".registry.mirrors."harbor.amc.seoul.kr"]
            endpoint = ["https://harbor.amc.seoul.kr"]
            [plugins."io.containerd.grpc.v1.cri".registry.configs."harbor.amc.seoul.kr".tls]
              ca_file = "/etc/pki/ca-trust/source/anchors/harbor.crt"
              cert_file = "/etc/pki/ca-trust/source/anchors/harbor.crt"
              key_file = "/etc/pki/ca-trust/source/anchors/harbor.key" 
            [plugins."io.containerd.grpc.v1.cri".registry.configs."harbor.amc.seoul.kr".auth]
              username = "admin"
              password = "Harbor12345"
EOF

```

### Gitlab 설치

```bash

helm repo add gitlab https://charts.gitlab.io

helm upgrade -i gitlab gitlab-8.3.2.tgz \
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

# gitlab 레파지토리 - 브랜치 생성 kw-mvn (main, gradle), kw-mvn-deploy (main) 

git config --global http.sslVerify false

kw-mvn-deploy > main branch > deploy.yml 파일의 이미지 URL을 harbor.asan/library/kw-mvn 로 변경

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
 -keyout gitlab.key -out gitlab.crt -subj '/CN=gitlab.amc.seoul.kr' \
 -addext 'subjectAltName=DNS:gitlab.amc.seoul.kr'	

kubectl create secret tls gitlab-ingress-tls --key gitlab.key --cert gitlab.crt -n gitlab

# Ingress Annotations for tls

  ingress.kubernetes.io/proxy-body-size: "0"
  ingress.kubernetes.io/ssl-redirect: "true"
  traefik.ingress.kubernetes.io/router.entrypoints: websecure
  traefik.ingress.kubernetes.io/router.tls: "true"

kubectl -n gitlab apply -f - <<"EOF"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    ingress.kubernetes.io/proxy-body-size: "0"
    ingress.kubernetes.io/ssl-redirect: "true"
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
  name: gitlab-ingress
  namespace: gitlab
spec:
  ingressClassName: nginx
  rules:
  - host: gitlab.amc.seoul.kr
    http:
      paths:
      - backend:
          service:
            name: gitlab-webservice-default
            port:
              number: 8181
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - gitlab.amc.seoul.kr
    secretName: gitlab-ingress-tls
EOF

cat << EOF | sudo tee -a /etc/hosts
192.168.122.11 gitlab.amc.seoul.kr
EOF

```

### Gitlab-Runner 구성

```

openssl s_client -showcerts -connect gitlab.amc.seoul.kr:443 -servername gitlab.amc.seoul.kr < /dev/null 2>/dev/null | openssl x509 -outform PEM > gitlab.amc.seoul.kr.crt
k create secret generic gitlab-runner-tls --from-file=gitlab.amc.seoul.kr.crt  -n gitlab

CoreDNS 추가
hosts {
      10.10.1.1 gitlab.amc.seoul.kr harbor.amc.seoul.kr # Gitlab Ingress IP 
      fallthrough
}
	 
https://gitlab.amc.seoul.kr/argo/kw-mvn/-/runners/new

# Runner Token 확인

glrt-vZuAwYks8JRqx5GULT-f

cat << EOF > gitlab-runner-values.yaml
gitlabUrl: https://gitlab.amc.seoul.kr

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

helm upgrade -i gitlab-runner -f gitlab-runner-values.yaml gitlab-runner-0.68.1.tgz -n gitlab

```

### ArgoCD 설치

```

kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# argocd insecure 

argocd-cmd-params-cm

	data:
	  server.insecure: "true"

# argocd-ingress-route

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

# Restart argocd pod

# Nginx-ingress

k edit ds -n kube-system rke2-ingress-nginx-controller

# add "--enable-ssl-passthrough" at line 53
  - --watch-ingress-without-class=true
  - --enable-ssl-passthrough
  
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server-ingress
  namespace: argocd
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
spec:
  rules:
  - host: argocd.amc.seoul.kr
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: argocd-server
            port:
              name: https
			  
# Check initial admin password	
		  
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

ysdspBnfCeXOqIoK

https://argocd.amc.seoul.kr/settings/certs?addTLSCert=true

add name gitlab.amc.seoul.kr & paste gitlab.amc.seoul.kr.crt pem file

k exec -it -n argocd $(k get pods -l app.kubernetes.io/name=argocd-server -o name -n argocd) bash

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
    repoURL: 'https://gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git'
    targetRevision: main
  sources: []
  project: default
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
EOF

```

---

### Gitlab CICD Pipelines - Main 브랜치

```

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=/cache/maven.repository"
  IMAGE_URL: "harbor.amc.seoul.kr/library"
  IMAGE: "kw-mvn"
  DEPLOY_REPO_URL: "https://gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git"
  DEPLOY_REPO_CREDENTIALS: "https://argo:abcd!234@gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git"
  REGISTRY_USER_ID: "admin"
  REGISTRY_USER_PASSWORD: "Harbor12345"
  ARGO_URL: "argocd-server.argocd"
  ARGO_USER_ID: "admin"
  ARGO_USER_PASSWORD: "password!@#$"
  ARGO_APP_NAME: "kw-mvn"

stages:
  - maven-jib-build
  - update-yaml
  - sync-argo-app

maven-jib-build:
  image: gcr.io/cloud-builders/mvn:amc
  stage: maven-jib-build
  script:
    - COMMIT_TIME="$(date -d "$CI_COMMIT_TIMESTAMP" +"%Y%m%d-%H%M%S")"
    - "mvn -B \
        -DsendCredentialsOverHttp=true \
        -Djib.allowInsecureRegistries=true \
        -Djib.to.image=$IMAGE_URL/$IMAGE:$COMMIT_TIME-$CI_JOB_ID \
        -Djib.to.auth.username=$REGISTRY_USER_ID \
        -Djib.to.auth.password=$REGISTRY_USER_PASSWORD     \
        compile \
        com.google.cloud.tools:jib-maven-plugin:build"
    - echo "IMAGE_FULL_NAME=$IMAGE_URL/$IMAGE:$COMMIT_TIME-$CI_JOB_ID" >> build.env
    - echo "NEW_TAG=$COMMIT_TIME-$CI_JOB_ID" >> build.env
    - cat build.env
  artifacts:
    reports:
      dotenv: build.env

update-yaml:
  image: alpine/git:v2.26.2
  stage: update-yaml
  script:
    - mkdir deploy && cd deploy
    - git init

    - echo $DEPLOY_REPO_CREDENTIALS > ~/.git-credentials
    - cat ~/.git-credentials
    - git config credential.helper store

    - git remote add origin $DEPLOY_REPO_URL
    - git remote -v

    - git -c http.sslVerify=false fetch --depth 1 origin $CI_COMMIT_BRANCH
    - git -c http.sslVerify=false checkout $CI_COMMIT_BRANCH
    - ls -al

    - echo "updating image to $IMAGE_FULL_NAME"
    - sed -i "s|$IMAGE:.*$|$IMAGE:$NEW_TAG|" deploy.yml
    - cat deploy.yml | grep image

    - git config --global user.email "argo@dev"
    - git config --global user.name "gitlab-runner"
    - git add .
    - git commit --allow-empty -m "[gitlab-runner] updating image to $IMAGE_FULL_NAME"
    - git -c http.sslVerify=false push origin $CI_COMMIT_BRANCH

sync-argocd:
  image: quay.io/argoproj/argocd:v2.12.3
  stage: sync-argo-app
  script:
    - argocd login $ARGO_URL --username $ARGO_USER_ID --password $ARGO_USER_PASSWORD --plaintext

    - argocd app sync $ARGO_APP_NAME --plaintext
    - argocd app wait $ARGO_APP_NAME --sync --health --operation --plaintext

```	

### gradle 브랜치

```
variables:
  MAVEN_OPTS: "-Dmaven.repo.local=/cache/maven.repository"
  IMAGE_URL: "harbor.amc.seoul.kr/library"
  IMAGE: "kw-mvn"
  DEPLOY_REPO_URL: "https://gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git"
  DEPLOY_REPO_CREDENTIALS: "https://argo:abcd!234@gitlab.amc.seoul.kr/argo/kw-mvn-deploy.git"
  REGISTRY_USER_ID: "admin"
  REGISTRY_USER_PASSWORD: "Harbor12345"
  ARGO_URL: "argocd-server.argocd"
  ARGO_USER_ID: "admin"
  ARGO_USER_PASSWORD: "password!@#$"
  ARGO_APP_NAME: "kw-mvn"

stages:
  - gradle-jib-build
  - update-yaml
  - sync-argo-app

gradle-jib-build:
  image: gradle:7.6-jdk11
  stage: gradle-jib-build
  script:
    - COMMIT_TIME="$(date -d "$CI_COMMIT_TIMESTAMP" +"%Y%m%d-%H%M%S")"

    - "gradle jib \
        -Djib.allowInsecureRegistries=true \
        -Djib.to.image=$IMAGE_URL/$IMAGE:$COMMIT_TIME-$CI_JOB_ID-GRADLE \
        -Djib.to.auth.username=$REGISTRY_USER_ID \
        -Djib.to.auth.password=$REGISTRY_USER_PASSWORD"
    
    - echo "IMAGE_FULL_NAME=$IMAGE_URL/$IMAGE:$COMMIT_TIME-$CI_JOB_ID-GRADLE" >> build.env
    - echo "NEW_TAG=$COMMIT_TIME-$CI_JOB_ID-GRADLE" >> build.env
    - cat build.env

  artifacts:
    reports:
      dotenv: build.env

update-yaml:
  image: alpine/git:v2.26.2
  stage: update-yaml
  script:

    - mkdir deploy && cd deploy
    - git init

    - echo $DEPLOY_REPO_CREDENTIALS > ~/.git-credentials
    - cat ~/.git-credentials
    - git config credential.helper store

    - git remote add origin $DEPLOY_REPO_URL
    - git remote -v

    - git -c http.sslVerify=false fetch --depth 1 origin main
    - git -c http.sslVerify=false checkout main
    - ls -al

    - echo "updating image to $IMAGE_FULL_NAME"
    - sed -i "s|$IMAGE:.*$|$IMAGE:$NEW_TAG|" deploy.yml
    - cat deploy.yml | grep image

    - git config --global user.email "argo@dev"
    - git config --global user.name "gitlab-runner"
    - git add .
    - git commit --allow-empty -m "[gitlab-runner] updating image to $IMAGE_FULL_NAME"
    - git -c http.sslVerify=false push origin main

sync-argocd:
  image: quay.io/argoproj/argocd:v2.12.3
  stage: sync-argo-app
  script:
    - argocd login $ARGO_URL --username $ARGO_USER_ID --password $ARGO_USER_PASSWORD --plaintext

    - argocd app sync $ARGO_APP_NAME --plaintext
    - argocd app wait $ARGO_APP_NAME --sync --health --operation --plaintext

```

### 도커이미지 저장

```

nerdctl images | grep -v REPOSITORY | grep -v none | while read line
do
  filename=$( echo "$line" | awk '{print $1":"$2".tar"}' | sed 's|:|@|g ; s|/|+|g' )
  option=$( echo "$line" | awk '{print $1":"$2}' )
  echo "nerdctl save ${option} -o ${filename}"
  nerdctl save "${option}" -o "${filename}"
done

ls *.tar | while read line
do
   filename=$( echo "$line" )
   echo "nerdctl load -i ${filename}"
   nerdctl load -i "${filename}"
done

```
### 도커이미지 Tag & Push

```
mkdir -p /etc/nerdctl

cat << EOF >> /etc/nerdctl/nerdctl.toml
address   = "unix:///run/k3s/containerd/containerd.sock"
namespace = "k8s.io"
EOF


# Create Images txt
nerdctl images --format '{{.Repository}}:{{.Tag}}' | grep -v REPOSITORY | grep -v none >> images.txt

# Create Tag Cmd
cat images.txt | awk '{print "nerdctl tag " $1 " harbor.amc.seoul.kr/"$1}' > tag.txt

# Run Tag Cmd
cat tag.txt | bash -

# Run Push Cmd
nerdctl images --format '{{.Repository}}:{{.Tag}}' | grep harbor.amc | awk '{print "nerdctl push " $1}' | bash -

```
