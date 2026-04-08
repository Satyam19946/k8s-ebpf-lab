# Phase 04 — BPF Programming

## What this phase covers

Hands-on BPF programming in C on a local Ubuntu 24.04 machine — completely
outside of Kubernetes. Six programs written from scratch, each introducing
one new concept, building toward the XDP load balancer that forms the core
of the Phase 05 CNI.

The goal of this phase: get comfortable with the BPF development loop
(compile → load → attach → observe → debug verifier errors) before applying
the same patterns inside a CNI where mistakes are harder to isolate.

All programs live in the companion repository:
[bpf_code](https://github.com/satyamakgec/bpf_code)

---

## Environment

- Host: Ubuntu 24.04 LTS (AMD Ryzen 5 3600) — local machine, no VMs
- Kernel: 6.8.x
- Toolchain: clang 18, libbpf, bpftool, llvm-objdump

---

## The two-file structure

Every BPF program in this phase follows the same structure:

```
<name>/
├── <name>.bpf.c      # kernel-side — compiled to BPF bytecode with clang -target bpf
├── <name>_loader.c   # userspace — compiled to x86_64, loads and attaches the program
└── <name>.h          # shared structs (where needed)
```

The kernel side and userspace side target different execution environments
and cannot be compiled into one binary. The kernel side has no libc, no
heap allocation, no unbounded loops — only the BPF helper functions the
kernel explicitly exposes. The userspace loader is normal C that calls
the kernel via the `bpf()` syscall through libbpf.

---

## Programs written

### 1. hello

**New concept:** the complete BPF development loop.

An XDP program attached to loopback that calls `bpf_printk` on every
incoming packet. Output appears in `/sys/kernel/debug/tracing/trace_pipe`.

Key things learned:
- `SEC("xdp")` places the function in the `xdp` ELF section — libbpf reads
  this to determine program type and permitted helpers
- The `GPL` license section is a capability gate — not a legal statement.
  Helpers like `bpf_trace_printk` are only available to GPL-licensed programs
- `bpf_object__load()` is where the `bpf()` syscall happens — the verifier
  runs and the JIT compiler converts BPF bytecode to native x86_64
- BPF programs persist in the kernel after the loader exits unless explicitly
  detached — `bpf_xdp_detach()` must be called on exit
- `llvm-objdump -d hello.bpf.o` shows the actual BPF instructions —
  hello world compiles to exactly 5 instructions
- `bpftool btf dump file hello.bpf.o` shows type information embedded by
  the compiler — what makes `bpftool map dump` show field names

---

### 2. packet_inspect

**New concept:** packet parsing and the verifier's bounds checking requirement.

Parses Ethernet and IPv4 headers, prints source IP, destination IP, and
protocol for every IPv4 packet.

Key things learned:
- `ctx->data` and `ctx->data_end` are `__u32` offsets, not raw pointers.
  The JIT compiler rewrites accesses to load from `xdp_buff->data` — the
  actual 64-bit pointer. The C cast `(void *)(long)ctx->data` is for the
  verifier's type system, not a description of the generated machine code
- The mandatory bounds check pattern — before reading any header field:
  ```c
  if ((void *)(ptr + 1) > data_end)
      return XDP_PASS;
  ```
  `ptr + 1` uses C pointer arithmetic: advances by `sizeof(*ptr)` bytes.
  After this check, the verifier permits reads of all fields in the struct
- `bpf_ntohs` vs `ntohs` — libc doesn't exist in kernel-side BPF. `bpf_ntohs`
  is a macro that expands to `__builtin_bswap16()` — one inline instruction
- Network byte order values in equality comparisons don't need conversion —
  only convert when comparing against host-order constants or doing arithmetic
- `__be32` is semantically `__u32` in network byte order — same bits, but
  documents intent and catches misuse with sparse

---

### 3. packet_counter

**New concept:** `BPF_MAP_TYPE_HASH` — the kernel-userspace shared memory model.

Counts packets per IP protocol number. The kernel side increments counters
atomically; the userspace side iterates the map every 2 seconds.

Key things learned:
- BTF-based map declaration — the `__uint`/`__type` macros encode map
  parameters into ELF type information rather than runtime values.
  `__uint(type, BPF_MAP_TYPE_HASH)` expands to `int (*type)[1]` —
  the array dimension carries the enum value into the type system.
  libbpf reads this at load time and calls `bpf(BPF_MAP_CREATE, ...)`
- `bpf_map_lookup_elem` returns `PTR_TO_MAP_VALUE_OR_NULL` — a pointer
  directly into map memory (not a copy). The verifier rejects any
  dereference without a NULL check on every code path
- `__sync_fetch_and_add` compiles to `lock xadd` — multiple CPU cores
  run XDP programs concurrently and can race on the same map value
- `BPF_NOEXIST` for safe concurrent insert — between lookup returning NULL
  and your insert executing, another core may have inserted the same key.
  `BPF_NOEXIST` makes your insert a no-op in that race
- Map pre-allocation: `max_entries` is committed at `bpf(BPF_MAP_CREATE)` —
  no allocation happens at packet time. Inserting beyond `max_entries`
  returns `-E2BIG`
- `bpf_map_get_next_key` for userspace iteration — cursor-based, pass NULL
  for the first key, returns `-ENOENT` when done

---

### 4. connection_tracker

**New concept:** struct map keys and the padding discipline.

Tracks per-connection packet and byte counts. Key is `{src_ip, dst_ip, proto}`,
value is `{packets, bytes}`.

Key things learned:
- **The padding rule** — the BPF map hashes all bytes of the key struct
  including implicit compiler padding. Uninitialized padding bytes contain
  stack garbage — two identical connections hash to different buckets and
  a new entry is silently created on every packet:
  ```c
  struct conn_key {
      __be32 src_ip;
      __be32 dst_ip;
      __u8   proto;
      __u8   pad[3];  // explicit — without this, 3 bytes of garbage
  };
  struct conn_key key = {};  // zero ALL bytes before field assignments
  ```
- **Stack pointer rule** — `bpf_map_lookup_elem` requires `PTR_TO_STACK`
  for the key pointer. `&ip->saddr` is `PTR_TO_PACKET` — rejected by the
  verifier. Always copy packet fields to a local stack variable first
- `ip->tot_len` not `data_end - data` for packet length — DMA buffers
  can have trailing hardware padding beyond the actual IP packet
- `__be32` for IP addresses stored directly from packet headers — no
  conversion needed for map lookups, only for arithmetic and printing

---

### 5. mytcpdump

**New concept:** `BPF_MAP_TYPE_RINGBUF` — zero-copy event streaming.

A tcpdump-equivalent that streams structured packet events to userspace
in real time. Parses Ethernet, IPv4, TCP, and UDP — prints proto, src:port,
dst:port, and length as each packet arrives.

Key things learned:
- **Ringbuf memory model** — `bpf_object__load()` calls `bpf(BPF_MAP_CREATE)`
  which allocates physical pages in the kernel. `ring_buffer__new()` calls
  `mmap()` twice — once for the consumer metadata page (read/write pointer
  state) and once for the data pages (ring contents). Both kernel and userspace
  map to the same physical pages — zero copy between kernel write and userspace
  read
- `bpf_ringbuf_reserve` — atomically claims bytes in the ring, returns a
  pointer directly into the ring's memory. You write into it directly.
  Must be followed by either `bpf_ringbuf_submit` or `bpf_ringbuf_discard`
- `ring_buffer__poll` uses `epoll_wait` internally — blocks until
  `bpf_ringbuf_submit` sends a wakeup, then drains all pending events,
  calling the handler callback once per event. Event-driven, not timer-driven
- **Struct size for ringbuf** — `bpf_ringbuf_reserve` requires size to be
  a multiple of 8 bytes. Design event structs accordingly and verify with
  `sizeof()`
- **Shared header pattern** — `mytcpdump.h` defines `struct packet_event`
  used by both the BPF program and the loader. Both compilation units
  must use identical struct definitions or map reads are corrupted
- `goto submit` — once a ringbuf slot is reserved you're committed. If
  a subsequent bounds check fails, `goto submit` with partial data is
  better than `bpf_ringbuf_discard` which loses the IP-level information
- `ip->ihl * 4` for the transport header offset — the IP header length
  field is in 32-bit words. Hardcoding 20 bytes silently misparsed packets
  with IP options
- `<linux/in.h>` for `IPPROTO_TCP`/`IPPROTO_UDP` in kernel-side BPF code —
  `<netinet/in.h>` is a userspace libc header unavailable in the kernel

---

### 6. xdp_dnat

**New concept:** packet rewriting, checksum update, `bpf_redirect`.

A Destination NAT program — the kernel-side core of a Kubernetes Service
load balancer. Intercepts packets at XDP, looks up destination IP:port in
a service map, rewrites destination to a backend IP:port, updates checksums,
and redirects to the backend interface.

This is structurally what Cilium's `cil_from_netdev` does for ClusterIP
service routing — without iptables, without conntrack, O(1) lookup.

```
packet arrives → parse Ethernet + IPv4 + TCP/UDP
              → build key {dst_ip, dst_port, proto}
              → lookup service_map
              → if found: rewrite dst_ip, dst_port
                          update IP checksum (IP header only)
                          update TCP/UDP checksum (pseudo-header includes IPs)
                          rewrite Ethernet header MACs
                          bpf_redirect(backend_ifindex, 0)
              → if not found: XDP_PASS
```

Key things learned:
- **Incremental checksum update** — `csum_update(old_csum, old_val, new_val)`
  is O(1). No need to re-checksum the entire header on every packet.
  A `__be32` IP address is two 16-bit words — requires two `csum_update` calls
- **TCP/UDP checksum covers the pseudo-header** — src IP, dst IP, proto,
  and length are included in the TCP/UDP checksum even though they're not
  in the TCP/UDP header. Changing `ip->daddr` breaks both the IP checksum
  and the TCP checksum
- **Ethernet header rewrite before `bpf_redirect`** — packets coming from
  `lo` have a loopback Ethernet header. When redirecting to a real Ethernet
  interface (`veth`), the frame must have valid MACs for the destination
  interface or the veth driver discards it silently
- **`bpf_redirect` vs `XDP_TX`** — `XDP_TX` bounces the packet back out
  the same interface. `bpf_redirect(ifindex, 0)` sends it to a specific
  different interface
- **XDP-redirected packets are invisible to tcpdump** — `bpf_redirect`
  injects below the `AF_PACKET` capture point. Capture on the receiving
  interface (e.g. `veth1` inside the backend namespace) to observe
  redirected packets
- **Verifier: uninitialized variables** — a variable not initialized on
  all code paths reaching its use is rejected with `!read_ok`. Initialize
  at declaration even if you "know" every path writes it — the verifier
  reasons structurally, not semantically
- **Null-initialized pointers for protocol dispatch** — initializing
  `struct tcphdr *tcp = NULL` and `struct udphdr *udp = NULL` allows
  correct `if (tcp)` / `if (udp)` guards. Initializing to `(void *)ip`
  makes both checks always true — both branches execute regardless of
  protocol

### Test setup (local, no cluster needed)

```bash
# create backend namespace
sudo ip netns add backend
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns backend
sudo ip addr add 10.244.1.1/24 dev veth0
sudo ip link set veth0 up
sudo ip netns exec backend ip addr add 10.244.1.5/24 dev veth1
sudo ip netns exec backend ip link set veth1 up
sudo ip netns exec backend ip route add default via 10.244.1.1 dev veth1

# add VIP to loopback
sudo ip addr add 10.96.0.10/32 dev lo

# start backend listener
sudo ip netns exec backend python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 9999))
while True:
    data, addr = s.recvfrom(1024)
    print(f'from {addr}: {data.decode().strip()}')
"

# attach DNAT program
sudo ./xdp_dnat/xdp_dnat_loader lo

# send test packet — observe it arrive at backend with dst 10.244.1.5
echo "hello" | nc -u 10.96.0.10 9999

# capture on veth1 to see the rewritten packet
sudo ip netns exec backend tcpdump -i veth1 -n
# shows: 10.96.0.10.XXXXX > 10.244.1.5.9999: UDP
```

---

## Key debugging workflow

When the verifier rejects a program:

```bash
# get the full verifier log
sudo bpftool prog load <program>.bpf.o /sys/fs/bpf/test 2>&1 | head -60
sudo rm -f /sys/fs/bpf/test

# cross-reference instruction numbers with source
llvm-objdump -d <program>.bpf.o
```

Read the verifier log from the bottom up:
1. Find the failing instruction and error message
2. Note the register that failed and its type/range (`r=0` means no bounds proven)
3. Trace that register backward through the log to find where it lost its valid range
4. The missing bounds check is between that point and the failing instruction

---

## Phase 4 deliverables

- [x] XDP attach/detach loop working
- [x] Packet header parsing with correct verifier-satisfying bounds checks
- [x] BPF hash map — kernel increment, userspace iteration
- [x] Struct map keys with correct padding discipline
- [x] Ringbuf event streaming — zero-copy, epoll-driven
- [x] Shared header pattern for kernel/userspace struct definitions
- [x] TCP/UDP port parsing including variable-length IP header
- [x] XDP DNAT — map lookup, IP/port rewrite, dual checksum update, redirect
- [x] Verifier error reading and debugging
- [x] End-to-end DNAT verified: packet observed with rewritten destination on wire

---

## What Phase 5 adds

The `xdp_dnat` program is the forward path of a CNI service load balancer.
Phase 5 completes the picture:

- **TC egress SNAT** — a TC program on the veth host-end that rewrites
  source IP:port on reply packets back to the VIP, so the client receives
  replies from the address it connected to
- **CNI binary** — the executable kubelet calls on pod create/delete.
  Sets up veth pairs, assigns IPs from a pool, configures routes via netlink
- **Control plane daemon** — watches the Kubernetes API for Service and
  Endpoint changes, populates the BPF maps dynamically
- **Conntrack map** — `BPF_MAP_TYPE_LRU_HASH` tracking connection state
  so reply packets bypass the policy check