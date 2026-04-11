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
| 05 | Custom eBPF CNI from Scratch | ✅ Complete |

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
    ├── README.md
    ├── makefile
    ├── setup.sh
    ├── tc_drop/
    ├── tc_drop_map/
    ├── xdp_lb/
    ├── mycni/
    └── tc_policy/
```

BPF programs from Phase 04 live in a companion repository:
**[bpf_code](https://github.com/satyam19946/bpf_code)**

## Phase summaries

### Phase 01 — Cluster Bootstrapping

Stood up a 3-node Kubernetes cluster using Vagrant + libvirt on KVM/QEMU.
kubeadm v1.31, containerd as the CRI, kube-proxy intentionally skipped.
Significant debugging around the KVM2 driver (minikube abandoned), flannel
bootstrap failures due to the missing kube-proxy ClusterIP, and the CNI
chicken-and-egg problem resolved by passing `--kube-api-url` directly to
flannel with a hostPath-mounted kubeconfig.

Key outcome: fully healthy 3-node cluster, all nodes Ready, flannel running
with VXLAN overlay, correct pod subnet routes on all nodes.

### Phase 02 — Kubernetes Networking Internals

Deep inspection of every layer of Kubernetes networking. Analyzed `ip link`,
`ip route`, and `bridge fdb` output field by field. Traced a full cross-node
packet walk from pod veth through the cni0 bridge, VXLAN encapsulation at
flannel.1, FDB lookup, UDP/8472 on the wire, decap at the remote VTEP, and
delivery to the destination pod. Verified with `tcpdump` hex output.

Covered kube-proxy iptables chain mechanics (KUBE-SVC, KUBE-SEP, DNAT) and
why O(n) chain traversal does not scale. Migrated from Flannel to Cilium —
documented every failure mode encountered: CIDR mismatch, leftover flannel
kernel state, IPv6 sysctl conflicts, stuck Helm release, `cilium_vxlan` in
wrong netns. Inspected Cilium's BPF lb maps (`lb4_services`, `lb4_backends`,
`lb4_reverse_nat`) via raw `bpftool` hex output. Verified cross-node pod
connectivity and Service routing via Cilium BPF maps.

Key outcome: Cilium v1.19.1 installed in kube-proxy-free mode, all nodes
healthy, cross-node pod-to-pod verified (0% loss), Service routing via BPF
hash maps confirmed.

### Phase 03 — eBPF Fundamentals

Conceptual foundation for Phases 04 and 05. Covered the BPF VM (11 registers,
512-byte stack, fixed 8-byte instruction encoding, JIT compilation to native
x86-64), map internals (`struct bpf_map` vtable dispatch, pre-allocation
model, each map type's memory layout), the verifier (abstract interpretation,
two-pass analysis, register type tracking, the mandatory NULL-check rule,
bounds checking model), and all program types relevant to CNI work (XDP, TC,
cgroup, kprobe/tracepoint).

Key outcome: complete mental model of the BPF execution environment before
writing a single line of C.

### Phase 04 — BPF Programming

Six BPF programs written from scratch in C, each introducing one new concept.
All programs live in the companion
[bpf_code](https://github.com/satyam19946/bpf_code) repository.

| Program | Core concept introduced |
|---|---|
| `hello` | XDP attach, `bpf_printk`, trace_pipe, ELF sections |
| `packet_inspect` | Ethernet + IPv4 parsing, verifier bounds checking pattern |
| `packet_counter` | `BPF_MAP_TYPE_HASH`, atomic increment, `bpf_map_get_next_key` iteration |
| `connection_tracker` | Struct map keys, padding discipline, `__be32` endianness |
| `mytcpdump` | `BPF_MAP_TYPE_RINGBUF`, shared headers, TCP/UDP port parsing |
| `xdp_dnat` | Map-driven packet rewrite, incremental checksum update, `bpf_redirect` |

Key outcome: working XDP DNAT verified end-to-end with packet rewrite
confirmed via tcpdump inside a backend network namespace.

### Phase 05 — Custom eBPF CNI from Scratch

Built a minimal but functional eBPF CNI consisting of five programs. See
[05-custom-cni/README.md](05-custom-cni/README.md) for full details.

| Program | Role |
|---|---|
| `tc_drop` | First TC program — hardcoded IP drop, clsact qdisc |
| `tc_drop_map` | Map-driven policy, hit counters, map pinning |
| `xdp_lb` | XDP service load balancer — ClusterIP DNAT |
| `mycni` | CNI binary — kubelet entry point, veth lifecycle, IP allocation |
| `tc_policy` | Per-pod policy enforcer — policy map, conntrack, ringbuf monitor |

The final integrated flow: `tc_policy_loader` runs as a daemon, loads the
BPF program, and pins it to `/sys/fs/bpf/`. When kubelet calls `mycni ADD`,
the binary creates the veth pair, sets up the pod network namespace, retrieves
the pinned program via `bpf_obj_get`, attaches it to the new veth (ingress +
egress), and writes the pod's policy entry into the pinned `policy_map`. The
daemon streams policy decisions (ALLOWED, DROPPED, CT_HIT) to stdout in real
time via the ringbuf.

Key outcome: complete CNI loop verified — `mycni ADD` sets up pod networking
and attaches policy enforcement automatically, conntrack allows established
connection replies without policy map re-lookup, `mycni DEL` detaches programs
and tears down the veth cleanly.

## Key concepts by phase

**Phase 01:** kubeadm bootstrap, CNI chicken-and-egg problem, containerd as
CRI, kube-proxy intentional omission, Vagrant + libvirt networking.

**Phase 02:** veth pairs, cni0 bridge, VXLAN/VTEP/FDB, the `onlink` route
flag, 50-byte VXLAN overhead, kube-proxy O(n) iptables vs Cilium O(1) BPF
maps, Cilium's three-map load balancer architecture, XDP hook placement
relative to NAPI poll loop.

**Phase 03:** BPF as a hosted ISA, 11-register calling convention, 512-byte
stack, fixed 8-byte instruction encoding, JIT compilation, `bpf_map_ops`
vtable dispatch, pre-allocation model, verifier abstract interpretation,
`PTR_TO_PACKET` vs `PTR_TO_MAP_VALUE` type system, BTF and CO-RE.

**Phase 04:** Two-file program structure, ELF sections and SEC() macros,
bounds checking pattern, struct key padding, atomic counters, ringbuf
zero-copy model, incremental ones-complement checksum update, verifier error
reading (instruction-level annotation, reference leak detection).

**Phase 05:** TC vs XDP attachment points and their trade-offs, `clsact`
qdisc, generic vs native XDP on virtual interfaces, CNI spec protocol,
`nsenter` for netns access by path, BPF program and map pinning for
cross-process sharing, `LRU_HASH` for automatic CT entry eviction,
ringbuf reservation lifetime rules enforced by the verifier.

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
- [Cloudflare — XDP in practice](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)
- [man bpf(2)](https://man7.org/linux/man-pages/man2/bpf.2.html)
- [man tc-bpf(8)](https://man7.org/linux/man-pages/man8/tc-bpf.8.html)