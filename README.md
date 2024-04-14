## 서울아산병원 PoC 환경 구성

---
```bash

# selinux disable
$ setenforce 0
$ sed -i --follow-symlinks 's/SELINUX=.*/SELINUX=disabled/g' /etc/sysconfig/selinux

#iptables 설치 확인
```

#### 1. rke2 클러스터 생성 - terraform
```
# tf apply -auto-approve
https://github.com/flytux/terraform-kube

curl -LO https://dl.k8s.io/release/v1.28.8/bin/linux/amd64/kubectl
curl -LO https://github.com/containerd/nerdctl/releases/download/v2.0.0-beta.4/nerdctl-2.0.0-beta.4-linux-amd64.tar.gz
```

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

dnf install nfs-utils
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
```

### 7. gitlab 설치
```
helm repo add gitlab https://charts.gitlab.io
$ helm upgrade -i gitlab gitlab/gitlab \
--set global.edition=ce \
--set global.hosts.domain=asan \
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
    secretName: gitlab-web-tls
EOF


# Add selfsigned CA crt to gitlab runner via secret
# add to /etc/hosts 
cat << EOF | sudo tee -a /etc/hosts
10.128.0.5 gitlab.asan
EOF

$ openssl s_client -showcerts -connect gitlab.kw01:443 -servername gitlab.kw01 < /dev/null 2>/dev/null | openssl x509 -outform PEM > gitlab.kw01.crt
# Custom CA 인증서를 추가합니다.
$ cat ca.crt >> gitlab.asan.crt
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
     10.128.0.5 gitlab.asan
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
$ yum --setopt=tsflags=noscripts install iscsi-initiator-utils
$ echo "InitiatorName=$(/sbin/iscsi-iname)" > /etc/iscsi/initiatorname.iscsi
$ systemctl enable iscsid
$ systemctl start iscsid

# apt -y install open-iscsi # Ubuntu

$ helm install longhorn \
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
hosts_dir      = ["/etc/containerd/certs.d",행
