# Phase 02 — Kubernetes Networking Internals

## What this phase covers

Deep inspection of every layer of Kubernetes networking on the 3-node cluster built in Phase 01. Starting from raw `ip link show` output and working down to VXLAN packet bytes on the wire, then replacing flannel with Cilium as a full kube-proxy replacement. Every concept was verified against live cluster output rather than taken on faith.

---

## Cluster state entering this phase

| Node    | IP (cluster) | Pod subnet      | CNI     |
|---------|-------------|-----------------|---------|
| ctrl    | 192.168.56.10 | 10.244.0.0/24 | flannel |
| worker1 | 192.168.56.11 | 10.244.1.0/24 | flannel |
| worker2 | 192.168.56.12 | 10.244.2.0/24 | flannel |

---

## Part 1 — Interface anatomy

### What `ip link show` reveals

Every interface on a Kubernetes node has a distinct role. On ctrl:

```
lo          — loopback, 127.0.0.1, not relevant to cluster traffic
eth0        — Vagrant management/NAT network (192.168.121.x), default route exits here
eth1        — dedicated cluster network (192.168.56.10), all Kubernetes traffic uses this
flannel.1   — VXLAN tunnel endpoint (VTEP), MTU 1450, state UNKNOWN (normal for VXLAN)
cni0        — Linux bridge, default gateway for all pods on this node (10.244.0.1)
vethXXXXXX  — host-side ends of veth pairs, one per running pod, enslaved to cni0
```

Key observations:
- `flannel.1` state `UNKNOWN` is not a fault — VXLAN devices have no physical carrier to detect
- `cni0` MTU 1450 = 1500 minus 50 bytes VXLAN overhead (8B VXLAN + 8B UDP + 20B outer IP + 14B outer Ethernet)
- Each `vethXXXX@if2` means the peer end is interface index 2 inside the pod's network namespace; `link-netns` tells you which netns

### What `ip route show` reveals

```
default via 192.168.121.1 dev eth0          ← internet / management traffic
10.244.0.0/24 dev cni0 src 10.244.0.1       ← local pods (this node)
10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink   ← worker1 pods
10.244.2.0/24 via 10.244.2.0 dev flannel.1 onlink   ← worker2 pods
192.168.56.0/24 dev eth1 src 192.168.56.10  ← cluster network (direct)
```

The `onlink` flag is critical: it tells the kernel to treat the next-hop (e.g. `10.244.1.0`) as directly reachable on `flannel.1` even though it is not in any connected subnet. Without `onlink` the kernel would reject the route as unreachable.

### Two-network node design

Each node has two IPs serving different purposes:

| Interface | IP             | Purpose                          |
|-----------|---------------|----------------------------------|
| eth0      | 192.168.121.x | Management, SSH, internet access |
| eth1      | 192.168.56.x  | All Kubernetes cluster traffic   |

This is a deliberate architectural separation. The cluster network (`192.168.56.0/24`) is not advertised to any external router — it is "private" purely because the routing infrastructure has no knowledge of it, not because anything actively blocks it. In production, this separation is enforced at the switch level with VLANs.

Verify which interface a packet exits from:
```bash
ip route get 8.8.8.8           # exits eth0, src 192.168.121.x
ip route get 192.168.56.11     # exits eth1, src 192.168.56.10
```

---

## Part 2 — The VXLAN overlay

### Why VXLAN exists

The Kubernetes networking contract (flat networking model) requires: every pod can reach every other pod directly by IP, no NAT, no port mapping, source IP preserved end-to-end. Pods on different nodes need to behave as if they are on the same L2 network. But the actual nodes are connected by an L3 network (a router sits between them).

VXLAN solves this by encapsulating L2 Ethernet frames inside UDP packets. The physical network routes the outer UDP packet between nodes; the inner pod-to-pod packet rides untouched inside. Pod B always sees Pod A's real IP as the source — no translation anywhere.

### Three-lookup chain for cross-node packets

When a pod on ctrl sends to `10.244.1.5` on worker1:

```
1. Route table:
   10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink
   → next hop is VTEP address 10.244.1.0, exit via flannel.1

2. Neighbour table (ip neigh):
   10.244.1.0 dev flannel.1 lladdr f2:78:f7:2f:f4:b1 PERMANENT
   → VTEP address maps to VTEP MAC (written statically by flannel)

3. FDB (bridge fdb show dev flannel.1):
   f2:78:f7:2f:f4:b1 dst 192.168.56.11 self permanent
   → VTEP MAC maps to worker1's physical IP (outer UDP destination)
```

`PERMANENT` entries are written by flannel when it learns about peer nodes via the Kubernetes API. `REACHABLE` entries (on the cni0 side) are learned dynamically via ARP.

### The 50-byte VXLAN overhead

Every cross-node packet adds 50 bytes of encapsulation headers:

| Header         | Size   | Key fields                              |
|----------------|--------|-----------------------------------------|
| Outer Ethernet | 14 B   | dst/src MAC of physical NICs            |
| Outer IP       | 20 B   | src: node eth1 IP, dst: remote node eth1 IP |
| UDP            | 8 B    | dst port 8472 (VXLAN), src: ephemeral   |
| VXLAN          | 8 B    | flags (0x08 = VNI valid), VNI (24-bit overlay ID) |

The inner Ethernet + IP packet (with pod IPs) rides unchanged inside. This was verified by reading raw hex from `tcpdump -r /tmp/vxlan.pcap -XX`:

```
Outer: 52:54:00:ce:9e:29 → 52:54:00:21:e5:90  (node MACs)
       192.168.56.10 → 192.168.56.11           (node IPs)
       UDP dst: 0x2118 = 8472
       VXLAN flags: 0x08, VNI: 0x000004
Inner: 10.244.0.66 → 10.244.1.213              (pod IPs, untouched)
```

### flannel configuration fix

Flannel auto-detected `eth0` (the NAT/management interface) for VXLAN traffic. Fixed by editing the flannel DaemonSet to add `--iface=eth1`:

```yaml
args:
  - --ip-masq
  - --kube-subnet-mgr
  - --iface=eth1
```

After restart, FDB entries correctly showed `192.168.56.11` and `192.168.56.12` as tunnel destinations instead of `192.168.121.x` addresses.

---

## Part 3 — kube-proxy and Services (theory)

kube-proxy was intentionally skipped during cluster bootstrap (`--skip-phases=addon/kube-proxy`). The cluster had no Service routing at this point — ClusterIPs were virtual addresses that existed only in the API server, with nothing in the dataplane to honor them.

### What kube-proxy would have written

For a ClusterIP Service, kube-proxy writes iptables chains in the `nat` table:

```
KUBE-SERVICES → match ClusterIP:port → jump to KUBE-SVC-XXXX
KUBE-SVC-XXXX → probabilistic load balance → jump to KUBE-SEP-YYYY
KUBE-SEP-YYYY → DNAT destination to pod IP:port
```

The ClusterIP never exists on any interface — it is purely a match condition in iptables rules. Every packet destined for a Service traverses these chains linearly. With 10,000 Services this becomes O(n) per connection — the fundamental scaling bottleneck that Cilium replaces with O(1) BPF hash map lookups.

kube-proxy runs a reconciliation loop (default 30s) that re-syncs iptables rules from the API server. Manual rule modifications are overwritten on the next sync cycle.

---

## Part 4 — Migrating from flannel to Cilium

### Why migrate

Flannel provides basic overlay networking but has no network policy enforcement and relies on kube-proxy (iptables) for Service routing. Cilium replaces both — it handles pod networking via its own VXLAN implementation and replaces kube-proxy entirely with BPF maps.

### Lessons learned from the migration

This migration encountered several real-world failure modes worth documenting:

**Wrong pod CIDR:** Cilium defaulted to `10.0.0.0/8` instead of the cluster's `10.244.0.0/16`. Fixed by passing CIDR explicitly:
```bash
cilium install \
  --set ipam.mode=cluster-pool \
  --set ipam.operator.clusterPoolIPv4PodCIDRList=10.244.0.0/16 \
  --set ipam.operator.clusterPoolIPv4MaskSize=24
```

**Stale CiliumNode objects:** `cilium uninstall` removes the Helm release but leaves `CiliumNode` CRD objects in etcd. These preserved old IPAM allocations across reinstalls. Fix: delete them explicitly before reinstalling:
```bash
kubectl delete ciliumnode --all
kubectl delete ciliumendpoints --all -A
kubectl delete ciliumidentities --all
helm uninstall cilium -n kube-system --no-hooks
```

**IPv6 sysctl read-only:** KVM/QEMU VMs had `/proc/sys/net/ipv6` mounted read-only. Cilium tried to enable IPv6 forwarding at startup and crashed. Fix:
```bash
cilium install \
  --set ipv6.enabled=false \
  --set enableIPv6Masquerade=false
```

**Leftover flannel kernel state:** Deleting the flannel DaemonSet removes the pods but does not clean up kernel interfaces or routes. After flannel pods are deleted, manually clean each node:
```bash
sudo ip link delete cni0
sudo ip link delete flannel.1
sudo rm -f /etc/cni/net.d/10-flannel.conflist
```
Routes disappear automatically when interfaces are deleted.

**`cilium_vxlan` in wrong network namespace:** A remnant of the messy migration left worker1's `cilium_vxlan` device inside a pod netns instead of the root netns. The Cilium agent couldn't program its FDB, causing asymmetric packet loss (worker1→worker2 failed, worker2→worker1 worked). Identified by:
```bash
ip link show | grep cilium_vxlan
# showed link-netns entries — should show none
bridge fdb show dev cilium_vxlan
# empty — confirmed the problem
```
Fixed by deleting and allowing the DaemonSet to recreate the Cilium agent pod.

### Final Cilium install command

```bash
cilium install \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=192.168.56.10 \
  --set k8sServicePort=6443 \
  --set ipam.mode=cluster-pool \
  --set ipam.operator.clusterPoolIPv4PodCIDRList=10.244.0.0/16 \
  --set ipam.operator.clusterPoolIPv4MaskSize=24 \
  --set ipv6.enabled=false \
  --set enableIPv6Masquerade=false
```

---

## Part 5 — Cilium's datapath internals

### How Cilium differs from flannel architecturally

| | flannel | Cilium |
|---|---|---|
| Pod gateway | `cni0` Linux bridge | `cilium_host` veth |
| Cross-node tunnel | `flannel.1` VXLAN device | `cilium_vxlan` VXLAN device |
| Service routing | kube-proxy iptables chains | BPF hash map lookups |
| Policy enforcement | none | TC BPF programs on each veth |
| Same-node pod traffic | L2 bridge switching | BPF program on veth host-end |

Cilium eliminates the bridge entirely. BPF programs attach to the TC hook on each veth host-end and handle routing, policy, and load balancing without any L2 bridge involved.

### Route table comparison

Flannel:
```
10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink   ← remote pods
10.244.0.0/24 dev cni0 src 10.244.0.1               ← local pods via bridge
```

Cilium:
```
10.244.0.0/24 via 10.244.0.229 dev cilium_host       ← local pods (no bridge)
10.244.1.0/24 via 10.244.0.229 dev cilium_host mtu 1450  ← remote
10.244.2.0/24 via 10.244.0.229 dev cilium_host mtu 1450  ← remote
```

Everything routes through `cilium_host` — both local and remote — because the BPF datapath is the single entry point for all pod traffic regardless of destination.

### Cilium's three BPF maps for Service load balancing

```
cilium_lb4_services (id 36) — slot table
  key: (ClusterIP, port, proto, slot)
  value: (backend_id, count, revnat_id, flags)
  slot 0 = metadata (count + revnat_id, no real backend)
  slot N = backend_id reference

cilium_lb4_backends (id 37) — backend table
  key: backend_id
  value: (pod_ip, pod_port, proto)

cilium_lb4_revnat (id 38) — reverse NAT table
  key: revnat_id
  value: (ClusterIP, port)
```

Forward path (DNAT): packet arrives for ClusterIP → look up slot 0 (get count + revnat_id) → hash(5-tuple) % count + 1 → look up that slot (get backend_id) → look up backend_id (get pod IP) → rewrite destination → store revnat_id in conntrack.

Reply path (SNAT): reply arrives from pod IP → conntrack hit → look up revnat_id → get ClusterIP → rewrite source back to ClusterIP.

Three BPF map lookups, all O(1), versus O(n) iptables chain traversal.

### Reading the raw BPF map — verified output

Services map (id 36), CoreDNS TCP/53 decoded:
```
key: 0a 60 00 0a  00 35  00 00  06  → 10.96.0.10:53/TCP slot=0
value: 00 00 00 00  02 00  00 03    → backend_id=0, count=2, revnat_id=3

key: 0a 60 00 0a  00 35  01 00  06  → slot=1
value: 09 00 00 00  00 00  00 03    → backend_id=9, revnat_id=3

key: 0a 60 00 0a  00 35  02 00  06  → slot=2
value: 0a 00 00 00  00 00  00 03    → backend_id=10, revnat_id=3
```

Backends map (id 37):
```
id 9  → TCP://10.244.1.155   (CoreDNS on worker1)
id 10 → TCP://10.244.2.87    (CoreDNS on worker2)
```

Reverse NAT map (id 38):
```
key: 00 03  → value: 0a 60 00 0a  00 35 → 10.96.0.10:53
```

REVNAT_ID is a per-service auto-increment counter — independent of backend count. TCP and UDP for the same ClusterIP:port get separate REVNAT_IDs because they are separate service entries.

---

## Part 6 — Linux networking stack

### Packet ingress path (NIC to application)

```
NIC PHY       signal on wire → bytes
MAC filter    dst MAC check in hardware — non-matching frames dropped before DMA
FCS check     CRC-32 validation in hardware — corrupt frames dropped silently
DMA           NIC writes frame directly to RX ring buffer in kernel memory (no CPU)
IRQ           NIC raises hardware interrupt once — CPU wakes up
NAPI poll     driver drains ring buffer in batches (budget=64), disables further IRQs
sk_buff       metadata wrapper allocated — points to DMA buffer, never copies bytes
XDP hook      earliest BPF intercept — raw DMA memory, before sk_buff overhead
TC ingress    BPF hook — Cilium policy, NAT, load balancing
netfilter     PREROUTING → routing decision → INPUT (or FORWARD)
TCP/UDP       demux by 4-tuple to socket
read()        only copy — payload bytes from kernel to userspace
```

### sk_buff is a pointer struct, not a data copy

`sk_buff` contains:
- `head` — 8-byte pointer to DMA buffer start
- `data` — 8-byte pointer to current packet start (advances as headers stripped)
- `mac_header` — u16 offset from head to Ethernet header (not a full pointer)
- `network_header` — u16 offset from head to IP header
- `transport_header` — u16 offset from head to TCP/UDP header

u16 offsets (not full pointers) because the maximum packet size is 65535 bytes — same limit as IP's own total length field. Saves 6 bytes per field across millions of concurrent socket buffers.

The packet bytes written by DMA never move until `read()` copies the payload to userspace. "Stripping" a header means advancing the `data` pointer. All header processing is pointer arithmetic, not copying.

### Why XDP is faster than iptables

XDP intercepts after NAPI poll but before sk_buff allocation. For a packet being dropped or redirected:
- XDP: reads raw DMA bytes, returns decision — ~40ns per packet
- iptables: sk_buff allocated, Ethernet processed, IP parsed, routing decided, netfilter chain walked — ~300ns per packet

For a CNI doing forwarding and policy enforcement, sk_buff overhead is unnecessary. XDP and TC BPF programs work on the same raw memory the NIC wrote — no struct initialisation, no cache pollution from bookkeeping fields that will never be used.

---

## Phase 2 deliverables

- [x] Every interface in `ip link show` understood and explained
- [x] Full cross-node packet walk traced: veth → cni0 → flannel.1 → FDB → wire → remote VTEP → pod
- [x] VXLAN 50-byte overhead decoded field-by-field from real tcpdump hex output
- [x] kube-proxy iptables chain mechanics understood (KUBE-SVC, KUBE-SEP, DNAT)
- [x] Flannel → Cilium migration completed with all failure modes documented
- [x] Cilium BPF lb three-map architecture decoded from raw bpftool hex output
- [x] Linux NIC ingress path understood: DMA, NAPI, sk_buff, XDP hook placement
- [x] Cross-node pod-to-pod connectivity verified (0% packet loss, all node pairs)
- [x] Service connectivity via Cilium BPF lb verified (nginx 3-pod deployment)

## Commands reference

```bash
# interface inspection
ip link show
ip route show
ip neigh show dev flannel.1
bridge fdb show dev flannel.1

# live packet capture
sudo tcpdump -i eth1 -n udp port 8472
sudo tcpdump -r /tmp/vxlan.pcap -XX

# Cilium BPF map inspection
kubectl exec -n kube-system <cilium-pod> -- cilium-dbg bpf lb list
kubectl exec -n kube-system <cilium-pod> -- cilium-dbg bpf lb list --backends
kubectl exec -n kube-system <cilium-pod> -- cilium-dbg bpf lb list --revnat
kubectl exec -n kube-system <cilium-pod> -- bpftool map show
kubectl exec -n kube-system <cilium-pod> -- bpftool map dump id <ID>

# Cilium diagnostics
cilium status
kubectl exec -n kube-system <cilium-pod> -- cilium node list
kubectl exec -n kube-system <cilium-pod> -- cilium-dbg bpf nodeid list
kubectl exec -n kube-system <cilium-pod> -- cilium-dbg bpf ipcache list
kubectl exec -n kube-system <cilium-pod> -- cilium-dbg monitor --type drop
```

## Key concepts learned

**Flat networking** — pods communicate without NAT; source IP is always the real pod IP end-to-end. VXLAN achieves this by tunnelling L2 frames over L3 infrastructure.

**VTEP** — Virtual Tunnel EndPoint. The device (`flannel.1`, `cilium_vxlan`) that encapsulates/decapsulates at the mouth of the tunnel. Not a router — purely a translation layer between overlay and underlay addressing.

**onlink** — kernel route flag meaning "treat this next-hop as directly reachable on this interface even though it's not in a connected subnet." Used by flannel so the kernel accepts routes whose next-hop is a remote VTEP address.

**REVNAT_ID** — Cilium's per-service identifier used to link the forward DNAT path to the reply SNAT path via the conntrack table. Auto-incremented per service; independent of backend count.

**DMA** — Direct Memory Access. The NIC writes frames to kernel memory independently over PCIe without CPU involvement. The CPU only wakes up via IRQ after the write completes.

**NAPI** — New API. Linux interrupt mitigation: one IRQ fires, interrupts are disabled, a softirq polls the ring buffer in batches. Prevents interrupt storms at line rate.
