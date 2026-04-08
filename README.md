# Kubernetes + eBPF Networking — Deep Dive Lab

A hands-on project building a Kubernetes cluster from scratch and progressively
replacing the networking stack with eBPF programs written in C.

## Environment
- Host: Ubuntu 24.04 LTS (AMD Ryzen 5 3600)
- VMs: 3x Ubuntu 24.04 (KVM/QEMU via Vagrant + libvirt)
- Cluster: kubeadm (1 control-plane + 2 workers)
- eBPF: C with libbpf / CO-RE

## Phases
| Phase | Topic | Status |
|-------|-------|--------|
| 01 | Cluster Setup — Vagrant + kubeadm | ✅ Complete |
| 02 | Kubernetes Networking Internals    | ✅ Complete |
| 03 | eBPF Fundamentals                  | ✅ Complete |
| 04 | Cilium — eBPF CNI in Practice | 🔨 In Progress |
| 05 | Custom eBPF CNI from Scratch | ⏳ Pending |
