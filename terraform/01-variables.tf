variable "master_ip" { default = "192.168.122.11" }

variable "ingress_ip" { default = "192.168.100.1" }

variable "nfs_pvc_root" { default = "/mnt/nfs/pvc" }

variable "ssh_key_root" { default = "/root/works/terraform-kube/kvm" }

variable "domain_name" { default = "amc.seoul.kr" }

variable "kubernetes_nodes" {

  type = map(object({ role = string, ip = string }))
  default = {
    master1  = { role = "master-init",  ip = "192.168.122.11" },
    #master2  = { role = "master-member",ip = "192.168.122.12" },
    #worker2  = { role = "worker",       ip = "192.168.122.13" },
  }
}

