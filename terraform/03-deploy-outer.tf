resource "local_file" "deploy_outer" {
  content     = templatefile("${path.module}/artifacts/templates/deploy-outer.sh", {
                master_ip = var.master_ip
                nfs_pvc_root = var.nfs_pvc_root
                domain_name =  var.domain_name
              })
  filename = "${path.module}/artifacts/deploy-outer.sh"
}

resource "terraform_data" "deploy_outer" {
  depends_on = [local_file.deploy_outer]
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
      chmod +x artifacts/deploy-outer.sh
      artifacts/deploy-outer.sh
    EOF
    ]
  }
}
