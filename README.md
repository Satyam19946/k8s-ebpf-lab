# Kubernetes + eBPF Networking — Deep Dive Lab

A progressive, hands-on project building a Kubernetes cluster from scratch
and replacing the networking stack with eBPF programs written in C.

The goal is not just to use existing tools but to understand every layer —
from how packets cross nodes in a VXLAN overlay, to how Cilium replaces
iptables with BPF hash maps, to writing the XDP and TC programs that do
the same thing from scratch.

## Environment

| Component | Details |
|---|---|
| Host OS | Ubuntu 24.04 LTS |
| CPU | AMD Ryzen 5 3600 |
| Virtualization | KVM/QEMU via Vagrant + libvirt |
| Cluster nodes | 3x Ubuntu 24.04 VMs (1 ctrl + 2 workers) |
| Kubernetes | kubeadm v1.31, containerd |
| CNI (baseline) | Flannel (VXLAN) |
| CNI (reference) | Cilium v1.19.1, kubeProxyReplacement=true |
| BPF toolchain | clang 18, libbpf, bpftool |
| BPF language | C |

## Phases

| Phase | Title | Status |
|---|---|---|
| 01 | Cluster Bootstrapping | ✅ Complete |
| 02 | Kubernetes Networking Internals | ✅ Complete |
| 03 | eBPF Fundamentals — VM, Maps, Verifier, Program Types | ✅ Complete |
| 04 | BPF Programming | ✅ Complete |
| 05 | Custom eBPF CNI from Scratch | 🔄 In progress |

## Repository structure

```
k8s-ebpf-lab/
├── README.md
├── 01-cluster-setup/
│   ├── Vagrantfile
│   └── README.md
├── 02-networking-internals/
│   └── README.md
├── 03-ebpf-fundamentals/
│   └── README.md
├── 04-bpf-programming/
│   └── README.md          ← links to companion bpf_code repo
└── 05-custom-cni/
    └── README.md          ← in progress
```

BPF programs from Phase 04 live in a companion repository:
**[bpf_code](https://github.com/satyamakgec/bpf_code)**

## Phase summaries

### Phase 01 — Cluster Bootstrapping

Stood up a 3-node Kubernetes cluster using Vagrant + libvirt on KVM/QEMU.
kubeadm v1.31, containerd as the CRI, kube-proxy intentionally skipped.
Significant debugging around the KVM2 driver (minikube abandoned), flannel
bootstrap failures due to the missing kube-proxy ClusterIP, and the CNI
chicken-and-egg problem.

Key outcome: fully healthy 3-node cluster, all nodes Ready, flannel running
with VXLAN overlay, correct pod subnet routes on all nodes.

### Phase 02 — Kubernetes Networking Internals

Deep inspection of every layer of Kubernetes networking. Analyzed `ip link show`
and `ip route show` output field by field, traced a full cross-node packet walk
from pod veth through the cni0 bridge, VXLAN encapsulation at flannel.1, FDB
lookup, UDP/8472 on the wire, decap at the remote VTEP, and delivery to the
destination pod. Verified with `tcpdump` hex output.

Covered kube-proxy iptables chain mechanics (KUBE-SVC, KUBE-SEP, DNAT) and
why O(n) chain traversal doesn't scale. Migrated from Flannel to Cilium —
documented every failure mode (CIDR mismatch, leftover flannel state, IPv6
sysctl, stuck Helm release, cilium_vxlan in wrong netns). Inspected Cilium's
BPF lb maps (`lb4_services`, `lb4_backends`, `lb4_reverse_nat`) via raw
`bpftool` hex output. Verified cross-node pod connectivity and Service
routing via Cilium BPF maps.

Key outcome: Cilium v1.19.1 installed in kube-proxy-free mode, all nodes
healthy, cross-node pod-to-pod verified (0% loss), Service routing via BPF
hash maps verified.

### Phase 03 — eBPF Fundamentals

Conceptual foundation for everything in Phase 04 and 05. Covered the BPF VM
(11 registers, 512-byte stack, fixed instruction encoding, JIT compilation),
map internals (`struct bpf_map` / vtable dispatch, pre-allocation model, each
map type's memory layout), the verifier (abstract interpretation, two-pass
analysis, register type tracking, the mandatory NULL-check rule, bounds
checking model), and all program types relevant to CNI work (XDP, TC, cgroup,
kprobe/tracepoint).

Key outcome: complete mental model of the BPF execution environment before
writing a single line of code.

### Phase 04 — BPF Programming

Six BPF programs written from scratch in C on the local machine, each
introducing one new concept. See the companion
[bpf_code](https://github.com/satyamakgec/bpf_code) repository and
[04-bpf-programming/README.md](04-bpf-programming/README.md) for full details.

| Program | Core concept |
|---|---|
| `hello` | XDP attach, trace_pipe, ELF structure |
| `packet_inspect` | Packet parsing, verifier bounds checking |
| `packet_counter` | Hash maps, atomic increments, map iteration |
| `connection_tracker` | Struct keys, padding discipline, `__be32` |
| `mytcpdump` | Ringbuf, mmap, epoll, shared headers |
| `xdp_dnat` | Map lookup, packet rewrite, checksum update, `bpf_redirect` |

Key outcome: working XDP DNAT verified end-to-end — packet observed with
rewritten destination IP on the wire inside a backend network namespace.

### Phase 05 — Custom eBPF CNI (in progress)

Building a minimal but functional eBPF CNI that replaces kube-proxy:

- CNI binary — called by kubelet on pod create/delete, sets up veth pairs
  and IP assignment via netlink
- XDP service load balancer — `xdp_dnat` from Phase 04 extended with
  dynamic map population and multi-backend support
- TC SNAT — egress program on veth host-end rewrites reply source back
  to the VIP
- Conntrack map — LRU hash tracking connection state
- Control plane daemon — watches Kubernetes API, keeps BPF maps in sync

## Key concepts by phase

**Phase 01:** kubeadm bootstrap, CNI chicken-and-egg, containerd as CRI,
static IPs for cluster stability, kube-proxy intentional omission.

**Phase 02:** veth pairs, cni0 bridge, VXLAN/VTEP/FDB, the `onlink` route
flag, VXLAN 50-byte overhead, kube-proxy O(n) iptables vs Cilium O(1) BPF
maps, Cilium's three-map load balancer architecture, `sk_buff` internals,
XDP hook placement relative to NAPI.

**Phase 03:** BPF as a hosted ISA, 11-register calling convention, 512-byte
stack, fixed 8-byte instruction encoding, JIT compilation, `bpf_map_ops`
vtable dispatch, pre-allocation model, verifier abstract interpretation,
`PTR_TO_PACKET` vs `PTR_TO_MAP_VALUE` type system, BTF and CO-RE.

**Phase 04:** Two-file structure, ELF sections, bounds checking pattern,
struct key padding, atomic counters, ringbuf zero-copy model, mmap and page
table entries, incremental checksum update, `bpf_redirect`, verifier error
reading.

## Running the cluster

```bash
cd 01-cluster-setup
vagrant up
```

Requires: libvirt, vagrant-libvirt plugin, KVM/QEMU on the host.

## References

- [Kernel BPF documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
- [Cilium source — bpf/bpf_lxc.c](https://github.com/cilium/cilium/blob/main/bpf/bpf_lxc.c)
- [Cilium source — bpf/lib/lb.h](https://github.com/cilium/cilium/blob/main/bpf/lib/lb.h)
- [XDP in practice — Cloudflare](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)