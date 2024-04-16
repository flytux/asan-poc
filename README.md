## 서울아산병원 PoC 환경 구성

- MGMT 클러스터 (1 node) 와 DEVOPS 클러스터 (3 node) 를 구성한다.
- MGMT 클러스터는 Rancher, Harbor, Minio 등 클러스터 환경 관리 및 공통 정보 저장소를 구성하고
- DEVSOP 클러스터는 GitLab, ArgoCD 등 DEVOPS 툴체인과 애플리케이션 개발 및 배포 환경, DBMS 및 인프라 서비스, 모니터링, 로깅 환경을 구성한다.
  
---
```bash

# selinux disable
$ setenforce 0
$ sed -i --follow-symlinks 's/SELINUX=.*/SELINUX=disabled/g' /etc/sysconfig/selinux

# iptables 설치 확인
```

#### 1. rke2 클러스터 생성 - terraform
```
# tf apply -auto-approve
https://github.com/flytux/terraform-kube

curl -LO https://dl.k8s.io/release/v1.28.8/bin/linux/amd64/kubectl
curl -LO https://github.com/containerd/nerdctl/releases/download/v2.0.0-beta.4/nerdctl-2.0.0-beta.4-linux-amd64.tar.gz
```

## MGMT 클러스터 구성

#### 2. cert-manager 설치
```
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.10.0/cert-manager.yaml
```

#### 3. rancher 설치
```
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest 

helm upgrade -i rancher charts/rancher-2.8.3.tgz \
--set hostname=rancher.asan --set bootstrapPassword=admin \
--set replicas=1 --set global.cattle.psp.enabled=false \
--create-namespace -n cattle-system
```

#### 4. local-path-storage 설치
```
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy/local-path-storage.yaml

```

#### 5. nfs 클라이언트 설치
```
nfs 서버 설치

dnf install nfs-utils # RHEL
apt install nfs-server -y # Ubuntu

systemctl enable nfs-server
mkdir -p /mnt/pv
chmod 707 /mnt/pv
chown -R 65534:65534 /mnt/pv 
systemctl start nfs-server
vi /etc/exports
/mnt/pv 192.168.122.21(rw,sync,no_root_squash)
/mnt/pv 192.168.122.22(rw,sync,no_root_squash)
systemctl restart nfs-server
exportfs -v

helm upgrade -i nfs-client \
     charts/nfs-subdir-external-provisioner-4.0.18.tgz \
     -f nfs-values.yaml -n kube-system

kubectl patch storageclass nfs-client -n kube-system -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

#### 6. harbor 설치
```
# 사설 인증서 생성
$ openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout harbor.key -out harbor.crt -subj '/CN=harbor.asan' \
  -addext 'subjectAltName=DNS:harbor.asan'

$ kubectl create ns harbor
$ kubectl create secret tls harbor-ingress-tls --key harbor.key --cert harbor.crt -n harbor

# harbor 설치
helm upgrade -i harbor charts/harbor-1.14.2.tgz\
     -n harbor -f harbor-values.yaml

# 사설인증서 등록 (워커노드에 전부 적용)
cp harbor.crt harbor.key /etc/pki/ca-trust/source/anchors/ ( /usr/local/share/ca-certificates/ # ubuntu )
update-ca-trust ( update-ca-certificates # ubuntu )

curl -LO https://github.com/containerd/nerdctl/releases/download/v2.0.0-beta.4/nerdctl-2.0.0-beta.4-linux-amd64.tar.gz

# nerdctl 설정
vi /etc/nerdctl/nerdctl.toml

debug          = false
debug_full     = false
address        = "unix:///run/k3s/containerd/containerd.sock"
namespace      = "k8s.io"
snapshotter    = "stargz"
cgroup_manager = "cgroupfs"
hosts_dir      = ["/etc/containerd/certs.d", "/etc/docker/certs.d"]
experimental   = true

# harbor 접속
nerdctl login harbor.asan # admin/Harbor12345

```

#### 7. minio 설치 
```
kubectl apply -f minio.yaml
```

## DEVOPS 클러스터 구성

#### 8. gitlab 설치
```
# Gitlab 설치
$ helm upgrade -i gitlab charts/gitlab-7.10.2.tgz \
--set global.edition=ce \
--set global.hosts.domain=asan \
--set global.ingress.configureCertmanager=false \
--set global.ingress.class=nginx \
--set certmanager.install=false \
--set nginx-ingress.enabled=false \
--set gitlab-runner.install=false \
--set prometheus.install=false \
--set registry.enabled=false \
-n gitlab --create-namespace

# root 사용자 초기 비밀번호 확인
$ k get -n gitlab secret gitlab-gitlab-initial-root-password -ojsonpath='{.data.password}' | base64 -d

# login gitlab.asan as root / %YOUR_INITIAL_PASSWORD%
# https://gitlab.asan/admin/application_settings/general > visibility & access controls > import sources > Repository By URL

# 다음 사용자 계정 생성
# argo / abcd!234 argo@devops

# Import source / deploy repository from github
# Login argo and import projects
- https://github.com/flytux/kw-mvn : Project Name > KW-MVN
- https://github.com/flytux/kw-mvn-deploy : Project Name > KW-MVN-DEPLOY
- main branch > deploy.yml 파일의 이미지 URL을 harbor.asan로 변경

# Delete default ingress gitlab-webservice
$ k delete ingress gitlab-webservice-default -n gitlab

# Gitlab Runner 등록을 위한 사설인증서 생성하여 ingress에 연결
$ openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout gitlab.key -out gitlab.crt -subj '/CN=gitlab.asan' \
  -addext 'subjectAltName=DNS:gitlab.asan'	
$ kubectl create secret tls gitlab-ingress-tls --key gitlab.key --cert gitlab.crt -n gitlab

# Create Ingress 
$ kubectl -n gitlab apply -f - <<"EOF"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: gitlab-ingress
  namespace: gitlab
spec:
  ingressClassName: nginx
  rules:
  - host: gitlab.asan 
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
    - gitlab.asan
    secretName: gitlab-ingress-tls
EOF


# add to /etc/hosts 
cat << EOF | sudo tee -a /etc/hosts
192.168.122.21 gitlab.asan
EOF

# Gitlab Runner 용 사설인증서 생성
$ openssl s_client -showcerts -connect gitlab.asan:443 -servername gitlab.asan < /dev/null 2>/dev/null | openssl x509 -outform PEM > gitlab.asan.crt
$ k create secret generic gitlab-runner-tls --from-file=gitlab.asan.crt  -n gitlab

# add in cluster dns gitlab.asan to coredns
$ k edit cm -n kube-system rke2-coredns-rke2-coredns

data:
  Corefile: |-
    .:53 {
        errors
        health  {
            lameduck 5s
        }
     hosts {
     192.168.122.21 gitlab.asan # Gitlab Ingress IP
     fallthrough
     }
     ready
        kubernetes   cluster.local  cluster.local in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
            ttl 30
        }
        prometheus   0.0.0.0:9153
        forward   . /etc/resolv.conf
        cache   30
        loop
        reload
        loadbalance
    }
    
$ k run -it --rm curl --image curlimages/curl -- sh
/ $ ping gitlab.asan

```

#### 9. gitlab runner 설치
```
# Setup runner and get runner token from KW-MVN project
# https://gitlab.asan/argo/kw-mvn/-/runners/new

# Configuration > Run untagged jobs 체크 > Submit
# Copy token glrt-wb_BLETYwEdVpP6qCyQX

$ cat << EOF > gitlab-runner-values.yaml
gitlabUrl: https://gitlab.asan

runnerToken: glrt-wb_BLETYwEdVpP6qCyQX # 저장한 토큰값 사용
rbac:
  create: true

certsSecretName: gitlab-runner-tls # 생성한 gitlab 인증서/CA기반 secret

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

# create gitlab runner cache pvc
$ kubectl -n gitlab apply -f - <<"EOF"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: gitlab-runner-cache-pvc
  namespace: gitlab
spec:
  storageClassName: nfs-client
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
EOF

# Gitlab Runner 설치
$ helm upgrade -i gitlab-runner -f gitlab-runner-values.yaml charts/gitlab-runner-0.63.0.tgz -n gitlab
```

#### 10. argocd 설치
```
# install argocd
$ kubectl create namespace argocd
$ kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 앞에서 설정한 경우 Skip
# add argocd ssl-passthrough args to ingress-controller
$ k edit ds -n kube-system rke2-ingress-nginx-controller

# add "--enable-ssl-passthrough" at line 53
  - --watch-ingress-without-class=true
  - --enable-ssl-passthrough
# save and qute (:wq)

# add ingress for argocd
$ kubectl -n argocd apply -f - <<"EOF"  
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
  - host: argocd.asan
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: argocd-server
            port:
              name: https
EOF

# get argocd initial password
$ kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# add gitlab ca-cert (self-signed)
- https://argocd.asan/settings/certs?addTLSCert=true
- add name gitlab.asan & paste gitlab.asan.crt pem file

$ cat gitlab.asan.crt

# add argocd app 

$ kn argocd
$ k exec -it $(k get pods -l app.kubernetes.io/name=argocd-server -o name) bash

# check argocd user id and password
$ argocd login argocd-server.argocd --insecure --username admin --password e3m7VS-JpcpczVcq
$ argocd repo add https://gitlab.asan/argo/kw-mvn-deploy.git --username argo --insecure-skip-server-verification
# enter gitlab password : abcd!234

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
    repoURL: 'https://gitlab.asan/argo/kw-mvn-deploy.git'
    targetRevision: main
  sources: []
  project: default
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
EOF
```

#### 11. SAMPLE 빌드 파이프라인 구성

```
variables:
  MAVEN_OPTS: "-Dmaven.repo.local=/cache/maven.repository"
  IMAGE_URL: "10.128.0.5:30005/kw-mvn"
  DEPLOY_REPO_URL: "https://gitlab.kw01/argo/kw-mvn-deploy.git"
  DEPLOY_REPO_CREDENTIALS: "https://argo:abcd!234@gitlab.kw01/argo/kw-mvn-deploy.git"
  REGISTRY_USER_ID: "admin"
  REGISTRY_USER_PASSWORD: "1"
  ARGO_URL: "argocd-server.argocd"
  ARGO_USER_ID: "admin"
  ARGO_USER_PASSWORD: "CWJjH2Fb278mmuDx"
  ARGO_APP_NAME: "kw-mvn"


stages:
  - maven-jib-build
  - update-yaml
  - sync-argo-app

maven-jib-build: 
  image: gcr.io/cloud-builders/mvn@sha256:57523fc43394d6d9d2414ee8d1c85ed7a13460cbb268c3cd16d28cfb3859e641
  stage: maven-jib-build
  script:
    - COMMIT_TIME="$(date -d "$CI_COMMIT_TIMESTAMP" +"%Y%m%d-%H%M%S")"
    - "mvn -B \
        -DsendCredentialsOverHttp=true \
        -Djib.allowInsecureRegistries=true \
        -Djib.to.image=$IMAGE_URL:$COMMIT_TIME-$CI_JOB_ID \
        -Djib.to.auth.username=$REGISTRY_USER_ID \
        -Djib.to.auth.password=$REGISTRY_USER_PASSWORD     \
        compile \
        com.google.cloud.tools:jib-maven-plugin:build"
    - echo "IMAGE_FULL_NAME=$IMAGE_URL:$COMMIT_TIME-$CI_JOB_ID" >> build.env
    - echo "NEW_TAG=$IMAGE_URL:$COMMIT_TIME-$CI_JOB_ID" >> build.env
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
    - sed -i "s|$IMAGE_URL:.*$|$IMAGE_FULL_NAME|" deploy.yml
    - cat deploy.yml | grep image
    
    - git config --global user.email "argo@dev"
    - git config --global user.name "gitlab-runner"
    - git add .
    - git commit --allow-empty -m "[gitlab-runner] updating image to $IMAGE_FULL_NAME"
    - git -c http.sslVerify=false push origin $CI_COMMIT_BRANCH

sync-argocd:
  image: quay.io/argoproj/argocd:v2.4.8
  stage: sync-argo-app
  script:
    - argocd login $ARGO_URL --username $ARGO_USER_ID --password $ARGO_USER_PASSWORD --insecure

    - argocd app sync $ARGO_APP_NAME --insecure
    - argocd app wait $ARGO_APP_NAME --sync --health --operation --insecure
```

#### 12. longhorn 설치
```
$ yum --setopt=tsflags=noscripts install iscsi-initiator-utils
$ echo "InitiatorName=$(/sbin/iscsi-iname)" > /etc/iscsi/initiatorname.iscsi
$ systemctl enable iscsid
$ systemctl start iscsid

# apt -y install open-iscsi # Ubuntu

$ k create -f minio-secret.yaml

$ helm install longhorn \
    charts/longhorn-1.6.1.tgz \
    --namespace longhorn-system \
    --create-namespace \
    --values longhorn-values.yaml
```

#### 13. rancher 모니터링 설치

```
# Rancher 로그인 > Cluster Tools > Monitoring 설치
```

#### 14. loki stack 설치

```
$ helm upgrade -i loki loki-stack-2.10.2.tgz -n loki --create-namespace

# 그라파나 로그인 admin / prom-operator
# Loki 데이터 소스 추가 (http://loki.loki:3100)
# Explorer Log (https://rancher.asan/api/v1/namespaces/cattle-monitoring-system/services/http:rancher-monitoring-grafana:80/proxy/explore)
```

#### 15. elasticsearch 설치

```
# Elasticsearch operator 설치 (crd, operator)
$ kubectl create -f https://download.elastic.co/downloads/eck/2.11.1/crds.yaml
$ kubectl apply -f https://download.elastic.co/downloads/eck/2.11.1/operator.yaml

# elasticsearch 설치
$ cat <<EOF | kubectl apply -f -
apiVersion: elasticsearch.k8s.elastic.co/v1
kind: Elasticsearch
metadata:
  name: quickstart
spec:
  version: 8.13.2
  nodeSets:
  - name: default
    count: 1
    config:
      node.store.allow_mmap: false
EOF

# check elastic search
$ kubectl get elasticsearch

# install kibana

$ cat <<EOF | kubectl apply -f -
apiVersion: kibana.k8s.elastic.co/v1
kind: Kibana
metadata:
  name: quickstart
spec:
  version: 8.13.2
  count: 1
  elasticsearchRef:
    name: quickstart
EOF

$ kubectl get secret quickstart-es-elastic-user -o=jsonpath='{.data.elastic}' | base64 --decode; echo

$ cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kibana
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
    nginx.ingress.kubernetes.io/proxy-ssl-verify: 'false'
  namespace: elastic-system
spec:
  ingressClassName: nginx
  rules:
    - host: kibana.asan
      http:
        paths:
          - backend:
              service:
                name: quickstart-kb-http
                port:
                  number: 5601
            path: /
            pathType: ImplementationSpecific
EOF
```

#### 16. logging operator 설치

```
# logging operatopr 설치
$ helm upgrade -i logging-operator -n logging charts/logging-operator-4.6.0.tgz --create-namespace

# logging 생성 - 로그 관리 단위
$ kubectl -n logging apply -f - <<"EOF"
apiVersion: logging.banzaicloud.io/v1beta1
kind: Logging
metadata:
  name: default-logging-simple
spec:
  fluentd: {}
  fluentbit: {}
  controlNamespace: logging
EOF

# elastic-user secret 생성
$ k get secret -n elastic-system quickstart-es-elastic-user -o yaml |  sed  '/^  namespace:.*/d' | k apply -f -

# create ouput
$ kubectl -n logging apply -f - <<"EOF"
apiVersion: logging.banzaicloud.io/v1beta1
kind: Output
metadata:
  name: es-output
spec:
  elasticsearch:
    host: quickstart-es-http.elastic-system
    port: 9200
    scheme: https
    ssl_verify: false
    ssl_version: TLSv1_2
    user: elastic
    password:
      valueFrom:
        secretKeyRef:
          name: quickstart-es-elastic-user
          key: elastic
    buffer:
      timekey: 1m
      timekey_wait: 30s
      timekey_use_utc: true
EOF

# create flow
$ kubectl -n logging apply -f - <<"EOF"
apiVersion: logging.banzaicloud.io/v1beta1
kind: Flow
metadata:
  name: es-flow
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
    - es-output
EOF

# install log-generator
$ helm upgrade -i log-generator -n logging charts/log-generator-0.7.0.tgz

# login elasticsearch (https://kibana.asan/)
# Discover > Create data view > fluentd index 선택택
```

#### 17. velero 설치

```
# external snapshotter 설치
$ k create -f charts/external-snapshotter/config/crd/
$ k create -f charts/external-snapshotter/deploy/kubernetes/snapshot-controller/

# volume snapshot class 생성
$ kubectl -n kube-system apply -f - <<"EOF"
kind: VolumeSnapshotClass
apiVersion: snapshot.storage.k8s.io/v1
metadata:
  name: longhorn-snapshot-vsc
  labels:
    velero.io/csi-volumesnapshot-class: "true"
driver: driver.longhorn.io
deletionPolicy: Delete
parameters:
  type: bak
EOF

$ cp charts/velero /usr/local/bin

# credential 생성
$ cat << EOF >> credential-velero
[default]
aws_access_key_id = minio
aws_secret_access_key = minio123
EOF

$ velero install --provider velero.io/aws \
 --bucket velero --image velero/velero:v1.11.0 \
 --plugins velero/velero-plugin-for-aws:v1.7.0,velero/velero-plugin-for-csi:v0.4.0 \
 --backup-location-config region=minio-default,s3ForcePathStyle="true",s3Url=http://minio.minio:9000 \
 --features=EnableCSI --snapshot-location-config region=minio-default \
 --use-volume-snapshots=true --secret-file=./credential-velero

$ k apply -f nginx-example.yaml
$ k run --rm -it curly --image=curlimages/curl sh
$ curl -v my-nginx.nginx-example

$ k delete ns nginx-example

$ velero restore create --from-backup nginx
$ kn nginx-example
$ k exec -it $(k get pods -l app=nginx -o name) cat /var/log/nginx/access.log
```

#### 18. mariadb 설치


#### 19. postgresql 설치


#### 20. kafka 설치


#### 21. NATS 설치

