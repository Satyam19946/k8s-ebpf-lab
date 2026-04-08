# Phase 01 — Cluster Setup

## What this phase builds
A 3-node Kubernetes cluster on KVM/QEMU VMs using Vagrant and kubeadm.
No CNI is installed yet — the cluster is deliberately left in a NotReady
state to observe exactly what the CNI contract provides.

## Topology
| Node    | IP             | Role          |
|---------|----------------|---------------|
| ctrl    | 192.168.56.10  | control-plane |
| worker1 | 192.168.56.11  | worker        |
| worker2 | 192.168.56.12  | worker        |

## Key decisions and why
- `--skip-phases=addon/kube-proxy` — intentionally omitted so we can
  observe a cluster with no Service routing, then add Cilium as a
  full kube-proxy replacement in Phase 04
- `--pod-network-cidr=10.244.0.0/16` — reserved for flannel (Phase 01
  baseline) and later Cilium (Phase 04)
- Static IPs on eth1 — cluster traffic isolated from Vagrant management
  network on eth0

## What NotReady looks like and why
After kubeadm init + worker joins, all nodes show NotReady:
- kubelet checks /etc/cni/net.d/ for CNI config — directory is empty
- Node condition: NetworkPluginNotReady
- CoreDNS pods stuck in Pending — need a Ready node to schedule on
- New pods cannot start — kubelet cannot set up their network namespace

## Reproducing this cluster
```bash
vagrant up
# On ctrl:
sudo kubeadm init --apiserver-advertise-address=192.168.56.10 \
  --pod-network-cidr=10.244.0.0/16 --node-name=ctrl \
  --skip-phases=addon/kube-proxy
# On workers: run the kubeadm join command from init output
```
