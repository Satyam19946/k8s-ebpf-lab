# Phase 05 — Custom eBPF CNI from Scratch

Building a minimal but functional eBPF-based CNI that handles pod networking,
service load balancing, and network policy enforcement — all without iptables
or kube-proxy.

## Architecture

Two long-running components and one short-lived binary:

```
tc_policy_loader (daemon)
  │  loads tc_policy.bpf.o once at node startup
  │  pins program and maps to /sys/fs/bpf/
  │  polls ringbuf — streams policy events to stdout
  │
mycni (binary — called by kubelet on pod create/delete)
  │  ADD: allocates IP, creates veth pair, sets up pod netns,
  │       attaches tc_policy to new veth, writes policy entry
  │  DEL: detaches tc_policy, tears down veth, releases IP
  │
xdp_lb_loader (daemon)
     loads xdp_lb.bpf.o, attaches to physical NIC
     pre-populates service_map with ClusterIP → backend entries
     handles XDP DNAT for Service traffic
```

## Programs

### `tc_drop/`

First TC program. Hardcoded source IP drop on TC ingress. Introduces the
`clsact` qdisc, `TC_ACT_SHOT`, and the libbpf TC attachment API
(`bpf_tc_hook_create`, `bpf_tc_attach`).

**Key concepts:** TC vs XDP hook placement, `struct __sk_buff` vs
`struct xdp_md`, `direct-action` mode, `clsact` qdisc.

### `tc_drop_map/`

Map-driven version of `tc_drop`. Blocked IPs and protocols stored in a
`BPF_MAP_TYPE_HASH` keyed on `{src_ip, proto}`. Loader pre-populates
the map; BPF program looks up the key and drops on hit.

**Key concepts:** Map-driven policy vs hardcoded values, `__sync_fetch_and_add`
for atomic hit counters, map pinning to `/sys/fs/bpf/` for persistence across
loader restarts, `BPF_NOEXIST` / `BPF_EXIST` / `BPF_ANY` flag semantics.

### `xdp_lb/`

XDP service load balancer. Intercepts packets destined for a ClusterIP,
looks up the real backend in `service_map`, rewrites destination IP and port
(DNAT), and fixes IP and TCP checksums via incremental update.

**Key concepts:** XDP DNAT, `BPF_MAP_TYPE_HASH` keyed on `{vip, port, proto}`,
incremental ones-complement checksum update, XDP vs TC for service LB,
generic vs native XDP on veth interfaces.

Map definition:
```c
struct service_key { __be32 vip; __be16 port; __u8 proto; __u8 pad; };
struct backend     { __be32 ip;  __be16 port; __u8 pad[2]; };
```

### `mycni/`

The CNI binary — called by kubelet via the CNI spec protocol. Reads
`CNI_COMMAND`, `CNI_NETNS`, `CNI_IFNAME`, `CNI_CONTAINERID` from the
environment and network config from stdin.

On `ADD`:
1. Allocates a pod IP from a file-based pool (`/var/lib/mycni/allocations`)
2. Creates a veth pair — host-end stays in host netns, pod-end moves into pod netns
3. Assigns IP, brings interfaces up, adds routes in both namespaces
4. Attaches `tc_policy` BPF program to the veth host-end (ingress + egress)
5. Writes a policy entry for the pod into the pinned `policy_map`
6. Returns CNI result JSON to stdout

On `DEL`:
1. Detaches `tc_policy` from the veth
2. Deletes the veth (peer inside pod netns deleted automatically)
3. Releases the pod IP

**Key concepts:** CNI spec protocol (env vars + stdin/stdout), `nsenter --net=`
for executing commands in a network namespace by path, file-based IPAM,
`bpf_obj_get` to retrieve pinned program fd, veth lifecycle.

### `tc_policy/`

The core CNI policy enforcer. A TC BPF program attached to every veth pair
(ingress + egress) that enforces NetworkPolicy using three maps:

- `policy_map` (`BPF_MAP_TYPE_HASH`) — `{src_ip, dst_ip, dst_port, proto}` →
  `{action}`. Written by the daemon or mycni. Default deny — if key absent,
  packet is dropped.
- `ct_map` (`BPF_MAP_TYPE_LRU_HASH`) — connection tracking. On first allowed
  packet, both forward and reply CT entries are inserted. Subsequent packets
  hit CT and bypass the policy map entirely.
- `monitor_rb` (`BPF_MAP_TYPE_RINGBUF`) — structured event stream. Emits a
  `monitor_event` for every policy decision (CT_HIT, ALLOWED, DROPPED).

Per-packet logic:
```
1. Parse Ethernet → IPv4 → TCP (non-TCP passes through)
2. CT lookup — if established connection, TC_ACT_OK immediately
3. Policy lookup — if allowed, insert CT entries (forward + reply), TC_ACT_OK
4. Default deny — TC_ACT_SHOT
```

**Key concepts:** Stateless policy vs connection tracking, `LRU_HASH` for
automatic eviction of stale CT entries, ringbuf reserve/submit pattern,
verifier reference tracking (unreleased ringbuf slot = load failure),
`PTR_TO_PACKET` rejection for map keys, struct padding discipline.

Map key structs:
```c
struct policy_key { __be32 src_ip; __be32 dst_ip; __be16 dst_port; __u8 proto; __u8 pad; };
struct ct_key     { __be32 src_ip; __be32 dst_ip; __be16 src_port; __be16 dst_port; __u8 proto; __u8 pad[3]; };
```

Shared header `tc_monitor.h` is included by both the BPF program and the
loader — the canonical definition of `struct monitor_event` lives there.

## File structure

```
05-custom-cni/
├── makefile
├── setup.sh                       ← restores node network state after reboot
├── tc_drop/
│   ├── tc_drop.bpf.c
│   └── tc_drop_loader.c
├── tc_drop_map/
│   ├── tc_drop_map.bpf.c
│   └── tc_drop_map_loader.c
├── xdp_lb/
│   ├── xdp_lb.bpf.c
│   └── xdp_lb_loader.c
├── mycni/
│   ├── mycni.h
│   └── mycni.c
└── tc_policy/
    ├── tc_monitor.h               ← shared between bpf.c and loader
    ├── tc_policy.bpf.c
    └── tc_policy_loader.c
```

## Building

```bash
# build all programs
make

# build individually
make tc_drop
make tc_drop_map
make xdp_lb
make tc_policy
make mycni
```

## Running

### Node setup (after reboot)

```bash
sudo ./setup.sh
```

Recreates the test veth pair, testpod namespace, gateway IP, routes, and
proxy ARP. Does not reattach BPF programs — those are handled by the daemons.

### Start the policy daemon

```bash
sudo ./tc_policy/tc_policy_loader
```

Loads `tc_policy.bpf.o`, pins program and all maps to `/sys/fs/bpf/`, and
starts streaming policy events. Must be running before `mycni ADD` is called.

### Simulate pod create (kubelet ADD)

```bash
sudo ip netns add testpod

export CNI_COMMAND=ADD
export CNI_CONTAINERID=abc123def456
export CNI_NETNS=/var/run/netns/testpod
export CNI_IFNAME=eth0
sudo -E ./mycni/mycni

# add gateway IP to the veth mycni created
sudo ip addr add 10.244.1.1/32 dev vethabc123de
sudo sysctl -w net.ipv4.conf.vethabc123de.proxy_arp=1
```

### Test policy enforcement

```bash
# allowed — port 8080
nc -l 8080 &
sudo ip netns exec testpod nc 10.244.1.1 8080

# blocked — port 22 (default deny, no policy entry)
sudo ip netns exec testpod nc 10.244.1.1 22
```

Watch the policy daemon terminal — `ALLOWED`, `CT_HIT`, and `DROPPED` events
appear in real time.

### Simulate pod delete (kubelet DEL)

```bash
export CNI_COMMAND=DEL
export CNI_CONTAINERID=abc123def456
sudo -E ./mycni/mycni
```

Detaches TC programs, deletes the veth, releases the IP.

### XDP service load balancer

```bash
# attach to loopback for local testing
sudo ip route add 10.96.0.10/32 dev lo
sudo ./xdp_lb/xdp_lb_loader lo

# listener on backend
sudo ip netns exec testpod nc -l 8080

# connect to VIP — XDP rewrites to backend
nc 10.96.0.10 80
```

## Debugging

```bash
# verify TC attachment
bpftool net show
tc filter show dev <iface> ingress
tc filter show dev <iface> egress

# inspect policy map
bpftool map dump pinned /sys/fs/bpf/policy_map

# inspect CT map
bpftool map dump pinned /sys/fs/bpf/ct_map

# raw kernel debug output (bpf_printk)
cat /sys/kernel/debug/tracing/trace_pipe

# verify pinned objects
ls -la /sys/fs/bpf/
```

## Key lessons

**TC vs XDP for CNI work.** XDP fires before SKB allocation — fastest possible
hook but ingress only, no locally generated traffic. TC fires after SKB
allocation — slightly slower but has ingress and egress hooks, sees all
traffic including pod-generated packets. Real CNIs (Cilium) use XDP on the
physical NIC for north-south service LB and TC on veth pairs for per-pod
policy.

**Generic XDP on veths.** Veths do not support native XDP. Generic XDP on a
veth fires after the kernel routing code has already processed the packet —
too late for DNAT to be effective on forwarded traffic. This is why TC is
used for per-pod work and XDP is reserved for physical NICs.

**Map keys must be deterministic.** Struct padding bytes between fields are
uninitialized unless you explicitly zero them. Use `struct foo key = {}` to
zero-initialize, then set individual fields. Two keys with identical logical
values but different padding bytes will fail both the hash and the bytewise
equality check.

**Ringbuf reservations must always be settled.** Every `bpf_ringbuf_reserve`
that returns non-NULL must be followed by either `bpf_ringbuf_submit` or
`bpf_ringbuf_discard` on every code path before program exit. The verifier
tracks this as a reference and rejects programs with leaked reservations.

**Pinning separates lifetime from process lifetime.** A BPF map or program
pinned to `/sys/fs/bpf/` survives the process that created it. The pin is
just a name — the kernel holds the real reference. `bpf_obj_get(path)` opens
the pinned object from a different process. This is the mechanism that lets
`mycni` (short-lived) use maps and programs loaded by `tc_policy_loader`
(long-running).