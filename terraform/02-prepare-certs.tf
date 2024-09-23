resource "terraform_data" "prepare_certs" {

  provisioner "local-exec" {
   command = <<-EOD
     openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout harbor.key -out harbor.crt -subj '/CN=harbor.${var.domain_name}' \
      -addext 'subjectAltName=DNS:harbor.${var.domain_name}'

     cat << EOF > containerd.toml
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

     openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout gitlab.key -out gitlab.crt -subj '/CN=gitlab.${var.domain_name}' \
      -addext 'subjectAltName=DNS:gitlab.${var.domain_name}'
	
     mv *.key *.crt *.toml artifacts
 
   EOD 
  }
}

resource "terraform_data" "copy_certs" {
  depends_on = [terraform_data.prepare_certs]
  for_each = var.kubernetes_nodes
  connection {
    host        = "${each.value.ip}"
    user        = "root"
    type        = "ssh"
    private_key = file("${var.ssh_key_root}/.ssh-default/id_rsa.key")
    timeout     = "2m"
  }

  provisioner "file" {
    source      = "artifacts"
    destination = "/root"
  }

  provisioner "remote-exec" {
    inline = [<<EOD

       echo "==== 1) Add harbor dns ===="

       echo "${var.ingress_ip}  harbor.${var.domain_name}" >> /etc/hosts
       echo "${var.ingress_ip}  gitlab.${var.domain_name}" >> /etc/hosts

       echo "==== 2) Add certs ===="

       cp artifacts/harbor.* /etc/pki/ca-trust/source/anchors/
       cp artifacts/gitlab.* /etc/pki/ca-trust/source/anchors/

       update-ca-trust

       echo "==== 3) Add harbor registy & restart containerd ===="

       cp artifacts/containerd.toml /etc/containerd/containerd.toml

       systemctl restart containerd

       sleep 10

    EOD
    ]
  }

}
