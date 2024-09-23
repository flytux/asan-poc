resource "local_file" "deploy_devops" {
  content     = templatefile("${path.module}/artifacts/templates/deploy-devops.sh", {
                master_ip = var.master_ip
                ingress_ip = var.ingress_ip
                nfs_pvc_root = var.nfs_pvc_root
                domain_name =  var.domain_name
              })
  filename = "${path.module}/artifacts/deploy-devops.sh"
}

resource "terraform_data" "deploy_devops" {
  depends_on = [terraform_data.deploy_outer]
  connection {
    host        = "${var.master_ip}"
    user        = "root"
    type        = "ssh"
    private_key = file("${var.ssh_key_root}/.ssh-default/id_rsa.key")
    timeout     = "1m"
  }

  provisioner "file" {
    source      = "artifacts"
    destination = "/root"
  }

  provisioner "remote-exec" {
    inline = [<<EOF
      chmod +x artifacts/deploy-devops.sh
      artifacts/deploy-devops.sh
    EOF
    ]
  }
}
