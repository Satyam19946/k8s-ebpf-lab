# Phase 3 — eBPF Fundamentals

No cluster changes in this phase. Pure conceptual and reference work covering the eBPF VM, maps, the verifier, and program types. This document is the primary reference for Phases 4 and 5.

---

## 1. The eBPF VM

### Architecture

The BPF virtual machine is a **register-based, in-kernel bytecode interpreter** with JIT compilation to native machine code. It is deliberately constrained — no arbitrary memory access, no unbounded loops, no calling arbitrary kernel functions. These constraints are enforced statically by the verifier before any program executes.

**11 registers, each 64-bit:**

| Register | Role |
|---|---|
| `r0` | Return value from helpers; final return value of the program |
| `r1`–`r5` | Helper function arguments — **clobbered after every helper call** |
| `r6`–`r9` | Callee-saved general purpose — preserved across helper calls |
| `r10` | Read-only frame pointer — base of the 512-byte stack |

`r1` always receives the program context on entry (e.g. `struct xdp_md *` for XDP programs). If you need a value to survive a helper call, spill it from `r1`–`r5` into `r6`–`r9` first.

**Stack:** exactly 512 bytes. Access via negative offsets from `r10` (e.g. `r10 - 8`). No dynamic allocation. Stack memory is the only place you can legally form a pointer to pass into a helper.

**Instruction encoding:** all instructions are fixed **8 bytes wide**. Each encodes: class (3 bits), opcode, dst register, src register, 16-bit offset, 32-bit immediate. Fixed width makes the verifier's linear scan and JIT translation predictable.

### From C to running code

```
xdp_prog.c
    │
    │  clang -O2 -g -target bpf -c xdp_prog.c -o xdp_prog.o
    ▼
xdp_prog.o          ← ELF with SEC()-named sections
    │
    │  bpf() syscall — BPF_PROG_LOAD
    ▼
Verifier            ← safety checks (types, bounds, reachability)
    │
    ▼
JIT compiler        ← BPF bytecode → native x86_64
    │
    ▼
Running in kernel   ← called at the hook point
```

The `SEC()` macro names sections in the ELF — `SEC("xdp")`, `SEC("tc")`, etc. libbpf reads these and calls the appropriate `bpf()` syscall.

### JIT

JIT is enabled by default on x86_64:

```bash
cat /proc/sys/net/core/bpf_jit_enable   # 1 = enabled
```

Inspect JIT output:

```bash
bpftool prog dump jited id <id>    # native x86_64
bpftool prog dump xlated id <id>  # pre-JIT BPF bytecode
```

---

## 2. BPF Maps

### What a map is

A BPF map is a **kernel object with a file descriptor** — a key-value store accessible from both kernel-side BPF programs and userspace. Maps are the only persistent state a BPF program has between invocations, and the only channel for kernel↔userspace communication.

Every map is backed by `struct bpf_map`:

```c
struct bpf_map {
    const struct bpf_map_ops *ops;  // vtable: lookup, update, delete, alloc...
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    // ... refcount, name, BTF info, etc.
};
```

Each concrete map type (hash, array, etc.) embeds `struct bpf_map` as its **first member**, enabling C-style polymorphism via pointer casting. The `ops` vtable points to a `static const struct bpf_map_ops` declared per map type at compile time — never heap-allocated.

### Map declaration in BPF C

```c
// Declare a map using BTF-style (libbpf, CO-RE)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);         // e.g. IPv4 VIP
    __type(value, struct backend);
} service_map SEC(".maps");
```

### The core API

**From kernel-side BPF C:**

```c
// Lookup — returns pointer or NULL (must be null-checked)
void *bpf_map_lookup_elem(void *map, const void *key);

// Update — flags: BPF_ANY (upsert), BPF_NOEXIST (insert only), BPF_EXIST (update only)
long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags);

// Delete
long bpf_map_delete_elem(void *map, const void *key);
```

**From userspace (libbpf):**

```c
bpf_map__lookup_elem(map, &key, sizeof(key), &val, sizeof(val), 0);
bpf_map__update_elem(map, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
bpf_map__delete_elem(map, &key, sizeof(key), 0);
```

**Critical:** `bpf_map_lookup_elem` returns `PTR_TO_MAP_VALUE_OR_NULL`. The verifier **rejects any dereference without a preceding null check**:

```c
struct backend *b = bpf_map_lookup_elem(&service_map, &vip);
if (!b)                // MANDATORY — verifier enforces this
    return XDP_PASS;
// now safe to use b->ip, b->port
```

### Map types

| Type | Lookup mechanism | Null on miss | Pre-allocated | Use in Phase 5 |
|---|---|---|---|---|
| `BPF_MAP_TYPE_ARRAY` | pointer arithmetic (`base + idx * value_size`) | No (slot always exists) | Yes, contiguous block | stats counters |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | same, per-CPU copy via `this_cpu_ptr` | No | Yes, one copy per CPU | packet counters (no atomics) |
| `BPF_MAP_TYPE_HASH` | jhash → bucket walk, per-bucket spinlock | Yes | Yes, element pool | service VIP → backend map |
| `BPF_MAP_TYPE_LRU_HASH` | same as HASH + LRU list, evicts LRU on full | Yes | Yes | conntrack table |
| `BPF_MAP_TYPE_RINGBUF` | no lookup — reserve/submit queue | — | Power-of-2 ring | packet event monitor |
| `BPF_MAP_TYPE_PROG_ARRAY` | array of BPF prog fds — used for tail calls | — | — | processing pipeline stages |

**Why pre-allocation:** BPF programs run in softirq/atomic context — `kmalloc(GFP_KERNEL)` can sleep and is forbidden. Pre-allocation means inserts claim from a pool with no allocator call at runtime. Failure mode moves to map creation time, in userspace, where it can be handled cleanly.

**RINGBUF reserve/submit pattern:**

```c
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) return XDP_PASS;    // ring full — drop event, not packet
e->src_ip   = ip->saddr;
e->dst_port = tcp->dest;
bpf_ringbuf_submit(e, 0);   // zero-copy — userspace reads from same pages
```

**Tail call via PROG_ARRAY:**

```c
// Jump to program at index PROG_IPV4 — does not return if successful
bpf_tail_call(ctx, &jmp_table, PROG_IPV4);
// reaching here means the tail call failed (index not populated)
return XDP_PASS;
```

---

## 3. The Verifier

### What it does

When you load a BPF program via `bpf(BPF_PROG_LOAD, ...)`, the kernel runs it through the verifier before any execution. The verifier statically proves the program cannot harm the kernel — no matter what inputs it receives.

**Two passes:**

**Pass 1 — DAG check:** control flow graph has no unreachable instructions and no unbounded back edges.

**Pass 2 — Abstract interpretation:** walks every possible execution path, tracking the type and known value range of every register at every instruction. Only if every path is provably safe does the program load.

### Register types the verifier tracks

```
NOT_INIT                  — uninitialized, cannot be read
SCALAR_VALUE              — a number, possibly with known bounds
PTR_TO_CTX                — pointer to program context (xdp_md, __sk_buff...)
PTR_TO_MAP_KEY            — pointer to a map key on the stack
PTR_TO_MAP_VALUE          — pointer into a map value (non-null, safe to deref)
PTR_TO_MAP_VALUE_OR_NULL  — result of lookup — must be null-checked before deref
PTR_TO_PACKET             — pointer into packet data
PTR_TO_PACKET_END         — the data_end boundary
PTR_TO_STACK              — pointer into the BPF stack frame
```

### The three rules it enforces

**1. Pointer validity and bounds — packet data:**

```c
void *data     = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

struct ethhdr *eth = data;

// REJECTED — eth+sizeof(ethhdr) might exceed data_end
return eth->h_proto;

// ACCEPTED — bounds check narrows the valid range
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
return eth->h_proto;    // verifier: eth..eth+14 is within data..data_end
```

**2. No uninitialized reads:**

```c
int key;    // uninitialized — on BPF stack, type is NOT_INIT
bpf_map_lookup_elem(&map, &key);    // REJECTED — key is NOT_INIT
```

**3. Helper call validity:** each helper has a defined signature. Passing a scalar where a pointer is expected, or calling a helper unavailable to your program type, causes rejection at load time.

### Branching — how null checks work

The verifier forks register state at each branch and explores both paths independently:

```c
val = bpf_map_lookup_elem(&map, &key);
// r0 type: PTR_TO_MAP_VALUE_OR_NULL

if (!val) return XDP_PASS;
// null path: returns, safe

// non-null path: r0 type is now PTR_TO_MAP_VALUE
*val = 1;   // ACCEPTED — verifier knows val is non-null on this path
```

### Complexity limit

The verifier has a hard limit of **1 million simulated instructions** across all paths. This is not 1M instructions in your program — it is the total steps taken exploring all branches. Programs with many nested conditionals or long loop bodies can hit this limit even when the source looks small. Tail calls are the escape hatch.

### Bounded loops (kernel ≥ 5.3)

```c
// ACCEPTED — verifier unrolls, proves terminates in ≤ 10 iterations
for (int i = 0; i < 10; i++) { ... }

// REJECTED — verifier cannot prove termination (i's initial value is unknown)
int i = some_map_value;
while (i > 0) { i--; }
```

### Verbose verifier output

```c
// In your userspace loader
struct bpf_object_open_opts opts = {
    .sz = sizeof(opts),
};
// or via bpftool:
bpftool prog load xdp_prog.o /sys/fs/bpf/xdp_prog type xdp 2>&1 | head -50
```

Or set log level to 2 for full register state dump after every instruction — shows exactly which type each register holds at the point of rejection.

### The mandatory packet parsing pattern

Every XDP/TC program that reads packet headers uses this pattern. The verifier requires a bounds check before every header access:

```c
void *data     = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// Layer 2
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end) return XDP_PASS;

// Layer 3
struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end) return XDP_PASS;

// Layer 4
struct tcphdr *tcp = (void *)(ip + 1);
if ((void *)(tcp + 1) > data_end) return XDP_PASS;

// Now safe: eth, ip, tcp fields all verified in-bounds
__u32 src = ip->saddr;
__u16 dport = tcp->dest;
```

---

## 4. Program Types

### Overview

A BPF program does nothing until attached to a hook. The hook determines: what context you receive, which helpers are available, what return values mean, and where in the packet path you fire.

**Packet path — where each type attaches:**

```
NIC hardware → DMA
    │
    ├── [XDP]          ← before SKB allocation (NAPI poll loop)
    │
    │   SKB allocated
    │
    ├── [TC ingress]   ← after SKB, traffic control layer
    │
    │   netfilter / routing
    │
    ├── [TC egress]    ← on the way out, sees local traffic too
    │
    ▼
socket / userspace
    │
    └── [cgroup/sock]  ← at connect() / bind() / socket() syscalls
```

---

### XDP — `BPF_PROG_TYPE_XDP`

**SEC keyword:** `SEC("xdp")`

**Fires:** before SKB allocation, in NAPI poll loop. Ingress only.

**Context struct:**

```c
struct xdp_md {
    __u32 data;               // offset to start of packet data
    __u32 data_end;           // offset to end of packet data
    __u32 data_meta;          // offset to metadata area (before data)
    __u32 ingress_ifindex;    // interface index packet arrived on
    __u32 rx_queue_index;     // RX queue index
};
```

**Accessing packet data:**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // safe to read ip->saddr, ip->daddr, ip->protocol
    return XDP_PASS;
}
```

**Return values:**

```c
XDP_PASS      // hand to kernel networking stack — normal path
XDP_DROP      // drop here, before SKB allocation — cheapest drop
XDP_TX        // retransmit out the same interface — used for DNAT/LB
XDP_REDIRECT  // send to different interface or CPU — via bpf_redirect()
XDP_ABORTED   // drop with error trace — debugging only
```

**Key helpers:**

```c
// Adjust the packet headroom (add/remove headers)
long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta);

// Adjust the packet tail
long bpf_xdp_adjust_tail(struct xdp_md *ctx, int delta);

// Redirect to interface
long bpf_redirect(u32 ifindex, u64 flags);

// Map lookup (service table, policy map)
void *bpf_map_lookup_elem(void *map, const void *key);

// Checksum helpers
u16 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed);

// FIB (forwarding information base) lookup for routing
long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags);
```

**Attachment modes:**

```bash
# Native (fastest — runs in NAPI poll, requires driver support)
ip link set dev eth0 xdp obj xdp_prog.o sec xdp

# Generic (slower — works on any driver, SKB still allocated)
ip link set dev eth0 xdpgeneric obj xdp_prog.o sec xdp

# Detach
ip link set dev eth0 xdp off
```

**Cannot:** access socket metadata, see egress traffic, see locally generated traffic.

---

### TC — `BPF_PROG_TYPE_SCHED_CLS`

**SEC keyword:** `SEC("tc")` or `SEC("tc/ingress")` / `SEC("tc/egress")`

**Fires:** after SKB allocation, at the traffic control layer. Both ingress and egress. Sees locally generated traffic on egress.

**Context struct:**

```c
struct __sk_buff {
    __u32 len;              // total packet length
    __u32 pkt_type;         // PACKET_HOST, PACKET_BROADCAST, etc.
    __u32 mark;             // skb->mark — used for policy marks
    __u32 ifindex;          // interface the packet is on
    __u32 ingress_ifindex;  // original ingress interface
    __u32 protocol;         // ETH_P_IP, ETH_P_IPV6, etc. (network byte order)
    __u32 cb[5];            // control buffer — scratch space, preserved across calls
    // ... many more fields
};
```

**Accessing packet data:**

```c
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // same bounds-check pattern as XDP
    return TC_ACT_OK;
}
```

**Return values:**

```c
TC_ACT_OK       // continue processing normally
TC_ACT_SHOT     // drop the packet — NetworkPolicy deny
TC_ACT_REDIRECT // redirect to another interface — via bpf_redirect()
TC_ACT_UNSPEC   // fall through to next filter in the chain
TC_ACT_STOLEN   // program consumed the SKB (queued it) — do not free
```

**Key helpers:**

```c
// In-place packet rewriting (TC only — not available in XDP)
long bpf_skb_store_bytes(struct __sk_buff *skb, u32 offset,
                          const void *from, u32 len, u64 flags);

// Recompute L3 (IP) checksum after header modification
long bpf_l3_csum_replace(struct __sk_buff *skb, u32 offset,
                           u64 from, u64 to, u64 flags);

// Recompute L4 (TCP/UDP) checksum
long bpf_l4_csum_replace(struct __sk_buff *skb, u32 offset,
                           u64 from, u64 to, u64 flags);

// Load bytes from packet into a buffer (safe, bounds-checked)
long bpf_skb_load_bytes(const struct __sk_buff *skb, u32 offset,
                         void *to, u32 len);

// Clone and redirect SKB
long bpf_clone_redirect(struct __sk_buff *skb, u32 ifindex, u64 flags);

// Set packet mark (used to communicate between TC programs)
// Access via skb->mark directly

// Map operations — same as XDP
void *bpf_map_lookup_elem(void *map, const void *key);
long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags);

// Send event to ringbuf
void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags);
void bpf_ringbuf_submit(void *data, u64 flags);
```

**Attachment (requires clsact qdisc):**

```bash
# Create clsact qdisc on the interface (once per interface)
tc qdisc add dev eth0 clsact

# Attach BPF on ingress
tc filter add dev eth0 ingress bpf obj tc_prog.o sec tc direct-action

# Attach BPF on egress
tc filter add dev eth0 egress bpf obj tc_prog.o sec tc direct-action

# List attached filters
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

# Remove
tc filter del dev eth0 ingress
```

**Can do that XDP cannot:** modify SKB fields, access egress, see locally generated traffic, call richer rewriting helpers.

---

### cgroup/sock_addr — `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`

**SEC keyword:** `SEC("cgroup/connect4")` (IPv4 TCP), `SEC("cgroup/connect6")` (IPv6), `SEC("cgroup/sendmsg4")`, etc.

**Fires:** at `connect()`, `bind()`, `sendmsg()`, `recvmsg()` syscalls for processes in the attached cgroup.

**Context struct:**

```c
struct bpf_sock_addr {
    __u32 user_family;      // address family (AF_INET, AF_INET6)
    __u32 user_ip4;         // IPv4 destination (writable — rewrite here for LB)
    __u32 user_ip6[4];      // IPv6 destination (writable)
    __u32 user_port;        // destination port (writable)
    __u32 family;           // socket family
    __u32 type;             // SOCK_STREAM, SOCK_DGRAM
    __u32 protocol;         // IPPROTO_TCP, IPPROTO_UDP
    __u32 msg_src_ip4;      // source IP (sendmsg)
    __u32 msg_src_ip6[4];
    struct bpf_sock *sk;    // the socket
};
```

**Socket-level load balancing pattern:**

```c
SEC("cgroup/connect4")
int sock_lb(struct bpf_sock_addr *ctx)
{
    // ctx->user_ip4 and ctx->user_port are the destination the process requested
    struct backend *b = bpf_map_lookup_elem(&service_map, &ctx->user_ip4);
    if (!b)
        return 1;   // 1 = allow, unmodified

    // Rewrite destination before any packet is sent
    ctx->user_ip4 = b->ip;
    ctx->user_port = b->port;
    return 1;       // allow the (now-rewritten) connect
}
```

**Return values:**

```c
1   // allow the operation (connect, bind, sendmsg...)
0   // deny — syscall returns EPERM
```

**Attachment:**

```c
// Userspace — attach to a cgroup fd
int cgroup_fd = open("/sys/fs/cgroup/unified", O_DIRECTORY | O_RDONLY);
bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET4_CONNECT, 0);
```

**Why more efficient than XDP DNAT:** rewrites the destination at `connect()` time — no DNAT, no SNAT, no conntrack entry needed. Replies come back directly from the backend IP.

---

### CGROUP_SKB — `BPF_PROG_TYPE_CGROUP_SKB`

**SEC keyword:** `SEC("cgroup_skb/ingress")` / `SEC("cgroup_skb/egress")`

**Fires:** on ingress/egress for all packets belonging to sockets in the attached cgroup.

**Context:** `struct __sk_buff *` (same as TC).

**Return values:** `1` (allow) / `0` (deny/drop).

**Use:** per-cgroup bandwidth policy, traffic isolation between cgroup subtrees.

---

### KPROBE / KRETPROBE — `BPF_PROG_TYPE_KPROBE`

**SEC keyword:** `SEC("kprobe/FUNCTION_NAME")` / `SEC("kretprobe/FUNCTION_NAME")`

**Fires:** at kernel function entry (kprobe) or return (kretprobe).

**Context struct:**

```c
struct pt_regs *ctx   // CPU register state at the probe point
```

**Accessing function arguments:**

```c
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    // PT_REGS_PARM1..PARM5 for arguments 1-5
    // PT_REGS_RC for return value (kretprobe only)

    bpf_printk("tcp_connect called\n");
    return 0;   // tracing programs always return 0
}
```

**Return values:** always `0` — tracing programs are observers, return value is ignored.

**Caveat:** unstable ABI — kernel function names and signatures can change across versions. Prefer tracepoints for stable hooks.

---

### TRACEPOINT — `BPF_PROG_TYPE_TRACEPOINT`

**SEC keyword:** `SEC("tracepoint/CATEGORY/NAME")` e.g. `SEC("tracepoint/net/netif_receive_skb")`

**Fires:** at static kernel tracepoints — stable, documented hooks.

**Common networking tracepoints:**

```c
SEC("tracepoint/net/netif_receive_skb")   // packet received by a device
SEC("tracepoint/net/net_dev_xmit")        // packet transmitted
SEC("tracepoint/skb/kfree_skb")           // SKB dropped (with drop reason)
SEC("tracepoint/sock/inet_sock_set_state") // TCP state transitions
```

**Return values:** always `0`.

**Prefer over kprobe:** stable ABI, lower overhead, explicit argument structs per tracepoint (no PT_REGS needed).

---

## 5. Phase 5 CNI — program type decision map

| Job | Program type | SEC keyword | Return on deny | Why |
|---|---|---|---|---|
| ClusterIP DNAT on ingress | XDP on `eth0` | `SEC("xdp")` | `XDP_PASS` (not our VIP) | Before SKB — cheapest intercept. `XDP_TX` bounces DNAT'd packet back. |
| NetworkPolicy — pod ingress | TC ingress on veth | `SEC("tc")` | `TC_ACT_SHOT` | Per-pod granularity. Full SKB for L4 fields. |
| NetworkPolicy — pod egress | TC egress on veth | `SEC("tc")` | `TC_ACT_SHOT` | Sees locally generated traffic. XDP can't. |
| Packet event monitor | TC + RINGBUF | `SEC("tc")` | — | `bpf_ringbuf_reserve/submit` streams events to userspace. |
| Local process connect() LB | CGROUP_SOCK_ADDR | `SEC("cgroup/connect4")` | `1` (allow) | Rewrites at `connect()` — no DNAT/SNAT/conntrack. |
| Debugging / tracing | TRACEPOINT | `SEC("tracepoint/...")` | `0` | Stable hooks, no packet modification. |

---

## 6. Toolchain reference

```bash
# Install (Ubuntu 24.04)
apt install clang llvm libbpf-dev bpftool linux-headers-$(uname -r) \
            linux-tools-$(uname -r)

# Verify BTF support (required for CO-RE)
ls /sys/kernel/btf/vmlinux

# Compile a BPF program
clang -O2 -g -target bpf \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c xdp_prog.c -o xdp_prog.o

# Generate libbpf skeleton
bpftool gen skeleton xdp_prog.o > xdp_prog.skel.h

# Load and attach XDP
ip link set dev eth0 xdp obj xdp_prog.o sec xdp

# Inspect loaded programs
bpftool prog list
bpftool prog dump xlated id <id>    # BPF bytecode
bpftool prog dump jited id <id>     # native x86_64

# Inspect maps
bpftool map list
bpftool map dump id <id>

# Read kernel debug output from bpf_printk()
cat /sys/kernel/debug/tracing/trace_pipe
```
