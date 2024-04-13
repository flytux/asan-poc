## 서울아산병원 PoC 환경 구성

---
```bash
# RHEL의 경우 selinux 해제
$ selinux disable
$ setenforce 0
$sed -i --follow-symlinks 's/SELINUX=.*/SELINUX=disabled/g' /etc/sysconfig/selinux

#iptables 설치 확인
```

#### 1. rke2 클러스터 생성 - terraform

#### 2. cert-manager 설치
```
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.10.0/cert-manager.yaml
```

### 3. rancher 설치
```
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest 

helm upgrade -i rancher charts/rancher-2.8.3.tgz \
--set hostname=rancher.asan --set bootstrapPassword=admin \
--set replicas=1 --set global.cattle.psp.enabled=false \
--create-namespace -n cattle-system
```

### 4. local-path-storage 설치
```
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy/local-path-storage.yaml
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

### 5. minio 설치 (mgmt 클러스터)
```
kubectl apply -f minio.yaml
```

### 6. nfs 클라이언트 설치
```
nfs 서버 설치

dnf install nfs-util
sysemctl enable nfs-server
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
```

### 7. gitlab
```
helm repo add gitlab https://charts.gitlab.io
$ helm upgrade -i gitlab gitlab/gitlab \
--set global.edition=ce \
--set global.hosts.domain=kw01 \
--set global.ingress.configureCertmanager=false \
--set global.ingress.class=nginx \
--set certmanager.install=false \
--set nginx-ingress.enabled=false \
--set gitlab-runner.install=false \
--set prometheus.install=false \
-n gitlab --create-namespace

# get root initial password
$ k get -n gitlab secret gitlab-gitlab-initial-root-password -ojsonpath='{.data.password}' | base64 -d

# login gitlab.kw01 as root / %YOUR_INITIAL_PASSWORD%
# https://gitlab.kw01/admin/application_settings/general > visibility & access controls > import sources > Repository By URL

# create User with YOUR ID / PASSWD
# argo / abcd!234 argo@devops

# approve YOUR ID with root account admin menu
# Login root and approve argo account

# Import source / deploy repository from gitlab
# Login argo and import projects
- https://github.com/flytux/kw-mvn : Project Name > KW-MVN
- https://github.com/flytux/kw-mvn-deploy : Project Name > KW-MVN-DEPLOY
- main branch > deploy.yml 파일의 이미지 URL을 VM1:30005로 변경합니다.
- docker.vm01 > 10.128.0.5:30005 로 변경 # VM1 IP:30005


# Create CA certs for CA Issuer
$ openssl genrsa -out ca.key 2048
$ openssl req -new -x509 -days 3650 -key ca.key -subj "/C=KR/ST=SE/L=SE/O=Kubeworks/CN=KW Root CA" -out ca.crt
$ kubectl create secret tls gitlab-ca --key ca.key --cert ca.crt -n gitlab

# Create CA Issuer
$ kubectl -n gitlab apply -f - <<"EOF"
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: gitlab-ca-issuer
  namespace: gitlab
spec:
  ca:
    secretName: gitlab-ca
EOF

# Delete default ingress gitlab-webservice
$ k delete ingress gitlab-webservice-default -n gitlab

# Create Ingress 
$ kubectl -n gitlab apply -f - <<"EOF"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/issuer: gitlab-ca-issuer
  name: gitlab-web-ingress
  namespace: gitlab
spec:
  ingressClassName: nginx
  rules:
  - host: gitlab.kw01
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
    - gitlab.kw01
    secretName: gitlab-web-tls
EOF


# Add selfsigned CA crt to gitlab runner via secret
# add to /etc/hosts 
cat << EOF | sudo tee -a /etc/hosts
10.128.0.5 gitlab.kw01
EOF

$ openssl s_client -showcerts -connect gitlab.kw01:443 -servername gitlab.kw01 < /dev/null 2>/dev/null | openssl x509 -outform PEM > gitlab.kw01.crt
# Custom CA 인증서를 추가합니다.
$ cat ca.crt >> gitlab.kw01.crt
$ k create secret generic gitlab-runner-tls --from-file=gitlab.kw01.crt  -n gitlab

# add in cluster dns gitlab.kw01 to coredns
$ k edit cm -n kube-system rke2-coredns-rke2-coredns

data:
  Corefile: |-
    .:53 {
        errors
        health  {
            lameduck 5s
        }
     hosts {
     10.128.0.5 gitlab.kw01
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
/ $ ping gitlab.kw01

```

### 8. longhorn 설치
```
helm install longhorn \
    charts/longhorn-1.6.0.tgz \
    --namespace longhorn-system \
    --create-namespace \
    --values longhorn-values.yaml
```

### 9. harbor 설치
```
helm upgrade -i harbor charts/harbor-1.14.2.tgz\
     -n harbor --create-namespace \
     -f harbor-values.yaml

# 사설인증서 등록
kubectl get secrets harbor-ingress -o jsonpath="{.data['ca\.crt']}" | base64 -d > harbor.crt
kubectl get secrets harbor-ingress -o jsonpath="{.data['tls\.crt']}" | base64 -d >> harbor.crt

cp harbor.crt /etc/pki/ca-trust/source/anchors/ ( /usr/local/share/ca-certificates/ # ubuntu )
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
```

### 10. docker registry 설치
```
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout example.key -out example.crt -subj '/CN=example.com' \
  -addext 'subjectAltName=DNS:example.com,DNS:example.net'

openssl req -in domain.csr -text -noout

$mkdir docker_reg_auth
$docker run -it --entrypoint htpasswd \
-v $PWD/docker_reg_auth:/auth \
-w /auth registry:2 -Bbc /auth/htpasswd admin password


nerdctl run -d -p 5000:5000 --restart=always --name registry \
-v $PWD/docker_reg_certs:/certs -v /reg:/var/lib/registry \
-e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
-e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
-e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm"\
-e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
-e REGISTRY_AUTH=htpasswd registry:2
```

### 10. rancher 모니터링 설치

11. logging operator 설치

12. loki stack 설치

13. elasticsearch 설치

14. velero 설치

15. mariadb 설치

16. postgresql 설치

17. kafka 설치

### 18. argocd 설치
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
  - host: argocd.kw01
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
- https://argocd.kw01/settings/certs?addTLSCert=true
- add name gitlab.kw01 & paste gitlab.kw01.crt pem file

$ cat gitlab.kw01.crt

# add argocd app 

$ kn argocd
$ k exec -it $(k get pods -l app.kubernetes.io/name=argocd-server -o name) bash

# check argocd user id and password
$ argocd login argocd-server.argocd --insecure --username admin --password e3m7VS-JpcpczVcq
$ argocd repo add https://gitlab.kw01/argo/kw-mvn-deploy.git --username argo --insecure-skip-server-verification
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
    repoURL: 'https://gitlab.kw01/argo/kw-mvn-deploy.git'
    targetRevision: main
  sources: []
  project: default
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
EOF
```

### 19. gitlab runner 설치
```
# Setup runner and get runner token from KW-MVN project

# https://gitlab.kw01/argo/kw-mvn/-/runners/new

# Configuration > Run untagged jobs 체크 > Submit
# Copy token glrt-wb_BLETYwEdVpP6qCyQX

$ cat << EOF > gitlab-runner-values.yaml
gitlabUrl: https://gitlab.kw01

runnerToken: glrt-wb_BLETYwEdVpP6qCyQX
rbac:
  create: true

certsSecretName: gitlab-runner-tls

runners:
  config: |
    [[runners]]
      [runners.kubernetes]
        namespace = "{{.Release.Namespace}}"
        image = "ubuntu:16.04"
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
  storageClassName: local-path
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
EOF

# Gitlab Runner 설치
$ helm upgrade -i gitlab-runner -f gitlab-runner-values.yaml gitlab/gitlab-runner
```

20. sample 빌드 파이프라인 구성
