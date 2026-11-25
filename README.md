# Aether Runtime (`aether-runtime`)

**Scale stateful Linux processes to 0% CPU and ~95% evicted DRAM without dropping open TCP or WebSocket connections.**

Aether Runtime freezes unmodified stateful Linux servers (`Python`, `Node.js`, `Go`, `C++`) during idle periods, evicts their physical memory pages out of RAM using `userfaultfd` + Zstandard compression, and wakes them straight from the Linux kernel via **eBPF (`cgroup_skb/ingress` + `BPF_MAP_TYPE_RINGBUF`)** in sub-millisecond time when the next TCP packet arrives—with **zero userspace network proxy**.

---

## Architecture

```text
  Client TCP/WebSocket Packet (port 8765)
         │
         ▼
  ┌────────────────────────────────────────────────────────┐
  │ Linux Kernel (Zero-Proxy Network Path)                 │
  │  └─ eBPF cgroup_skb/ingress (aether_wake.bpf.c)        │
  │       ├─ Active: updates last_pkt_ns in BPF array map  │
  │       └─ Sleeping: emits event via BPF_MAP_TYPE_RINGBUF│
  └──────────────────────────┬─────────────────────────────┘
                             │ 0.038 - 0.140 ms kernel wakeup
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Aether Runtime Daemon (aether_runtime.c)               │
  │  ├─ Blocks in ring_buffer__poll() at 0.0% CPU          │
  │  ├─ Wake: kill(pid, SIGCONT) immediately               │
  │  └─ Freeze (>5s idle):                                 │
  │       1. UNIX socket EVICT -> libaether_mem.so         │
  │       2. kill(pid, SIGSTOP)                            │
  └──────────────────────────┬─────────────────────────────┘
                             │ LD_PRELOAD
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Unmodified Target Process (e.g. stateful_ws_server.py) │
  │  └─ libaether_mem.so (aether_mem.c)                    │
  │       ├─ Scans anonymous rw-p VMAs (>= 16 MB)          │
  │       ├─ Compresses 4 KB pages via libzstd -> disk     │
  │       ├─ Incremental writeback via mincore()           │
  │       ├─ Drops physical DRAM via madvise(MADV_DONTNEED)│
  │       └─ On wake: userfaultfd serves only touched 4 KB │
  │          pages on demand (microsecond latency)         │
  └────────────────────────────────────────────────────────┘
```

---

## Measured Benchmarks (Ubuntu 22.04 LTS, Kernel `5.15.0-27-generic`)

Tested against [examples/stateful_ws_server.py](examples/stateful_ws_server.py) with **400 MB** of committed in-memory state and **no system swap enabled (`Swp: 0K/0K`)**:

| Metric | Measured Result |
| :--- | :--- |
| **Active Physical Memory (`VmRSS`)** | `422.0 MB` |
| **Frozen Physical Memory (`VmRSS`)** | `22.7 MB` (`401.6 MB` evicted via `madvise(MADV_DONTNEED)`) |
| **Zstd Disk Footprint (`libzstd.so.1`)** | `2.6 MB` (`154.5x` compression ratio on test heap) |
| **Incremental Re-Evict (`mincore()`)** | `3.5 ms` – `4.0 ms` |
| **Frozen CPU Usage (`htop` state `T`)** | `0.0%` |
| **Kernel eBPF RingBuf -> `SIGCONT` Wake** | `0.077 ms` – `0.140 ms` (`SIGCONT`: `0.038 ms` – `0.075 ms`) |
| **100 Concurrent Open WebSockets** | **100/100 survived (`0` dropped)** after 6.5s full freeze |
| **100-Socket Thundering-Herd Wake Burst** | `18.82 ms` total (`p50: 13.21 ms`, `p95: 16.30 ms`, `max: 16.62 ms`) |

---

## Repository Layout

```text
aether-runtime/
├── src/
│   ├── bpf/aether_wake.bpf.c         # eBPF cgroup_skb/ingress + ringbuf wake trigger
│   ├── runtime/aether_runtime.c      # C runtime orchestrator (libbpf + SIGSTOP/SIGCONT)
│   └── mem/aether_mem.c              # LD_PRELOAD userfaultfd + Zstd + mincore paging engine
├── examples/
│   └── stateful_ws_server.py         # 400 MB stateful WebSocket server example
├── benchmarks/
│   └── bench_100_ws.py               # 100-connection concurrency & freeze/wake benchmark
├── Makefile
└── LICENSE
```

---

## Quick Start (Ubuntu 22.04+ / Kernel >= 5.10 with BTF & userfaultfd)

### 1. Prerequisites
```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev libzstd1 python3-pip
pip3 install websockets
sudo sysctl -w vm.unprivileged_userfaultfd=1
```

### 2. Build & Run
```bash
make
sudo ./build/aether_runtime 8765 examples/stateful_ws_server.py
```

### 3. Run the 100-WebSocket Freeze/Wake Benchmark
In a second terminal:
```bash
make bench
```

---

## License

- Userspace runtime, memory engine, examples, and benchmarks: **Apache License 2.0** — see [LICENSE](LICENSE).
- Kernel eBPF bytecode (`src/bpf/*.bpf.c`): **Dual MIT/GPL** (required by the Linux kernel BPF verifier for GPL-only helpers such as `bpf_ringbuf_reserve`).
