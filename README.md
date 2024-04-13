## 서울아산병원 PoC 환경 구성

---
```bash
$ selinux disable
$ setenforce 0
$sed -i --follow-symlinks 's/SELINUX=.*/SELINUX=disabled/g' /etc/sysconfig/selinux

#iptables 확인
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

### 7. gitlab, gitlab-runner 설치
```
helm repo add gitlab https://charts.gitlab.io
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

18. argocd 설치

19. sample 빌드 파이프라인 구성
