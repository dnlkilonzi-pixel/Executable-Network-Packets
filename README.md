<div align="center">

# ⚡ Executable Network Packets (ENP)

### *Code that travels — logic that executes at every hop*

[![Protocol Version](https://img.shields.io/badge/Protocol-ENP%20v3-blueviolet?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0tMiAxNWwtNS01IDEuNDEtMS40MUwxMCAxNC4xN2w3LjU5LTcuNTlMMTkgOGwtOSA5eiIvPjwvc3ZnPg==)](docs/ENP-SPEC-v3.md)
[![Language](https://img.shields.io/badge/Language-C11-00599C?style=for-the-badge&logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Runtime](https://img.shields.io/badge/Runtime-WebAssembly%20%2F%20wasm3-654FF0?style=for-the-badge&logo=webassembly)](https://github.com/wasm3/wasm3)
[![Transport](https://img.shields.io/badge/Transport-UDP-orange?style=for-the-badge)](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)](CMakeLists.txt)

<br/>

> **ENP** is a research-grade **programmable network execution fabric**.  
> Instead of moving data between fixed server functions, ENP embeds  
> **executable WebAssembly logic directly inside the packet** — so the  
> computation travels *with* the data, executing at every node it passes through.

<br/>

**Created and designed by [Daniel Kimeu](https://github.com/dnlkilonzi-pixel)**

</div>

---

## 📖 Table of Contents

- [What is ENP?](#-what-is-enp)
- [Architecture Overview](#-architecture-overview)
- [Wire Format](#-wire-format-at-a-glance)
- [Quick Start](#-quick-start)
- [Live Demo — Multi-Hop Execution](#-live-demo--multi-hop-stateful-exec-chain)
- [Packet Lifecycle](#-packet-lifecycle)
- [Capability & Budget Model](#-capability--budget-model)
- [Observability & Tracing](#-observability--tracing)
- [Security Model](#-security-model)
- [Repository Layout](#-repository-layout)
- [Building from Source](#-building-from-source)
- [Protocol Specification](#-protocol-specification)
- [Research Layer](#-research-layer)
- [Credits](#-credits)

---

## 🌐 What is ENP?

Traditional networks move **data** to **functions** — a packet arrives at a server, which runs some hardcoded logic, and replies.

ENP inverts this model: the **function travels with the packet**.

```
Traditional:   Data ──────────────► Fixed Server Function
                                           │
                                        result

ENP:           [Data + WASM Code] ──► Node A executes ──► Node B executes ──► Node C executes ──► Originator
                                        (mutates state)     (mutates state)     (mutates state)
```

Each ENP packet carries:

| Field | Purpose |
|-------|---------|
| **Payload** (up to 256 bytes) | The data being processed |
| **WASM bytecode** (up to 512 bytes) | The function to execute at each hop |
| **State buffer** (128 bytes) | Cross-hop mutable state, carried in the packet |
| **Capability token** | What opcodes and resources this packet is allowed to use |
| **Compute budget** | Maximum WASM executions remaining across all hops |
| **Hop table** | Source-routed path (up to 4 nodes) |

### Use Cases

| Domain | How ENP helps |
|--------|---------------|
| **Edge Computing** | Function migrates with the packet; no deployment step needed |
| **IoT / Mesh Networks** | Drones and sensors receive instructions inside the packet — no cloud round-trip |
| **Self-Healing Fabrics** | `ENP_ROUTE_DECIDE` lets WASM choose to forward, drop, or clone at each hop |
| **Distributed Computation** | A value is progressively transformed as it hops through a pipeline |
| **Research & Protocol Design** | Clean formal model for studying programmable networking |

---

## 🏗 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENP Node (enp_server.c)                         │
│                                                                          │
│  UDP Receive                                                             │
│      │                                                                   │
│      ▼                                                                   │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────────────┐    │
│  │  Deserialize │───►│   Validate   │───►│  Capability Check        │    │
│  │  (wire bytes)│    │  (version,   │    │  allowed_ops bitmask     │    │
│  └─────────────┘    │   lengths)   │    │  cap_max_hops ceiling    │    │
│                      └──────────────┘    │  cap_max_compute ceiling │    │
│                                          └────────────┬─────────────┘    │
│                                                       │                  │
│                                          ┌────────────▼─────────────┐    │
│                                          │   Budget Check           │    │
│                                          │   compute_budget > 0?    │    │
│                                          └────────────┬─────────────┘    │
│                                                       │                  │
│                              ┌────────────────────────▼───────────────┐  │
│                              │         Opcode Dispatch                │  │
│                              │  ENP_FORWARD   ENP_EXEC  ENP_ROUTE_DECIDE│ │
│                              │  (echo)        (WASM    (WASM decides   │  │
│                              │                execute)  fwd/drop)      │  │
│                              └────────────────────────┬───────────────┘  │
│                                                       │                  │
│                              ┌────────────────────────▼───────────────┐  │
│                              │   State Mutation + Hop Routing         │  │
│                              │   state[0]++  │  hop_index++           │  │
│                              │   budget--    │  forward or reply      │  │
│                              └────────────────────────┬───────────────┘  │
│                                                       │                  │
│                              ┌────────────────────────▼───────────────┐  │
│                              │   TRACE Emit (enp_trace_log)           │  │
│                              │   exec_us · budget · state diff · action│ │
│                              └────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Node Properties (ENP v3 Core Invariants)

| Property | Guarantee |
|----------|-----------|
| **Determinism** | `S(P₁) = S(P₂) ⟹ S(process(N, P₁)) = S(process(N, P₂))` |
| **Budget monotonicity** | `compute_budget` is strictly non-increasing across hops |
| **Stateless nodes** | Node output is a pure function of the input packet — no cross-packet state |
| **Capability enforcement** | `allowed_ops`, `cap_max_hops`, `cap_max_compute` checked at every hop |
| **Sequential execution** | Hops execute in strict index order along a single path |

---

## 📦 Wire Format at a Glance

ENP v3 uses a **194-byte fixed header** followed by variable-length payload and WASM code sections.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┬───────────────────────────────┤
│    version    │    opcode     │             flags             │ ← 4 bytes
├───────────────────────────────┴───────────────────────────────┤
│                          src (IPv4)                           │ ← 4 bytes
├───────────────────────────────────────────────────────────────┤
│                          dst (IPv4)                           │ ← 4 bytes
├───────────────────────────────────────────────────────────────┤
│                         packet_id (u64)                       │
│                                                               │ ← 8 bytes
├───────────────────────────────────────────────────────────────┤
│                        timestamp (u64)                        │
│                                                               │ ← 8 bytes
├───────────────────────────┬───────────────────────────────────┤
│        payload_len        │           code_len                │ ← 4 bytes
├───────────┬───────────────┴───┬───────────────────────────────┤  ╮
│ hop_count │    hop_index      │  ← v2 routing header          │  │
├───────────┴───────────────────┴───────────────────────────────┤  │ v2
│              hops[4]  (4 × u32 IPv4 addresses)                │  │ 154
├───────────────────────────────────────────────────────────────┤  │ bytes
│              hop_ports[4]  (4 × u16 UDP ports)                │  │
├───────────────────────────────────────────────────────────────┤  │
│                   state[128]  (cross-hop buffer)              │  │
│                             ...                               │  │
├───────────────────────────────────────────────────────────────┤  ╯
│                    allowed_ops  (u32 bitmask)                  │  ╮
├───────────────────────────┬───────────────────────────────────┤  │ v3
│      cap_max_hops (u8)    │    cap_max_compute (u8)           │  │ 8
├───────────────────────────┴───────────────────────────────────┤  │ bytes
│                   compute_budget  (u16)                        │  │
├───────────────────────────────────────────────────────────────┤  ╯
│              payload  (0–256 bytes, variable)                 │
├───────────────────────────────────────────────────────────────┤
│              WASM code  (0–512 bytes, variable)               │
└───────────────────────────────────────────────────────────────┘
        Total fixed header: 194 bytes   │   Max packet: 962 bytes
```

### Protocol Evolution

| Version | Header size | Key addition |
|---------|-------------|-------------|
| v1 | 32 bytes | Base packet identity + payload |
| v2 | 186 bytes | Multi-hop routing + 128-byte state buffer |
| **v3** | **194 bytes** | **Capability token + compute budget** |

---

## 🚀 Quick Start

### Option A — Zero-dependency simulator (recommended first step)

```sh
# Clone and build the in-process simulator — no wasm3, no sockets needed
git clone https://github.com/dnlkilonzi-pixel/Executable-Network-Packets.git
cd Executable-Network-Packets

make sim
./build/enp_sim
```

**Expected output:**

```
[INFO]  ENP v3 Reference Simulator
[INFO]  ── Scenario 1: Multi-hop ENP_EXEC chain (budget=3, 3 hops) ──
TRACE pkt=1 hop=1/3 op=EXEC input=5 output=10 exec_us=12 budget=3→2 action=FORWARDED state=[00]→[01]
TRACE pkt=1 hop=2/3 op=EXEC input=10 output=20 exec_us=9  budget=2→1 action=FORWARDED state=[01]→[02]
TRACE pkt=1 hop=3/3 op=EXEC input=20 output=40 exec_us=11 budget=1→0 action=REPLIED   state=[02]→[03]
[INFO]  Final result: 40  (expected 40) ✓
[INFO]  ── Determinism check: S(run_A) = S(run_B) at every hop ──
[INFO]  All determinism assertions passed ✓
[INFO]  ── Scenario 2: Budget exhaustion ──
[INFO]  Budget correctly enforced ✓
[INFO]  ── Scenario 3: Capability denial (ENP_EXEC blocked) ──
[INFO]  CAP_DENIED correctly returned ✓
[INFO]  ── Scenario 4: ENP_ROUTE_DECIDE (WASM drops packet) ──
[INFO]  Packet dropped by routing decision ✓
[INFO]  All checks passed.
```

---

### Option B — Live node with real WASM execution

```sh
# Step 1: fetch the wasm3 interpreter (requires git)
make wasm3-fetch

# Step 2: build the full ENP node binary
make ENP_WITH_WASM3=1
```

```sh
# Terminal 1 — start an ENP node on port 9000
./build/enp server 9000
```

```
[INFO]  ENP node listening on port 9000
```

```sh
# Terminal 2 — send a single-hop ENP_EXEC packet
./build/enp client 127.0.0.1 9000
```

```
[INFO]  Sending ENP_EXEC packet: process(5)
[INFO]  Response received: result = 10  ✓
```

---

### Option C — Two-node multi-hop pipeline

```sh
# Terminal 1
./build/enp server 9000

# Terminal 2
./build/enp server 9001

# Terminal 3 — routes through both nodes: 3 → 6 (Node A) → 12 (Node B)
./build/enp multihop 127.0.0.1 9000 127.0.0.1 9001
```

```
[INFO]  Multi-hop result: 12   (3 → 6 → 12)  ✓
```

---

### Option D — Programmable routing demo

```sh
# Send ENP_ROUTE_DECIDE: WASM drops packets with value > 63
./build/enp route 127.0.0.1 9000
```

```
[INFO]  Route decision: FORWARD (input was 5 ≤ 63)
```

---

### CMake (cross-platform / Windows)

```sh
cmake -B build -DENP_WITH_WASM3=ON
cmake --build build
```

---

## 🔬 Live Demo — Multi-Hop Stateful EXEC Chain

The canonical demonstration chains **three nodes** in sequence. WASM `process(x) = x * 2` executes at each hop; the state buffer tracks hop progress; the compute budget counts down to zero.

```
  Originator
      │  packet: input=5, budget=3, state=[0,0,…]
      │
      ▼
 ╔═══════════╗
 ║  Node A   ║  WASM: process(5) = 10    budget: 3→2   state[0]: 0→1
 ║  hop 1/3  ║  Action: FORWARDED ──────────────────────────────────────┐
 ╚═══════════╝                                                          │
                                                                        ▼
                                                                   ╔═══════════╗
                                                                   ║  Node B   ║  WASM: process(10) = 20   budget: 2→1   state[0]: 1→2
                                                                   ║  hop 2/3  ║  Action: FORWARDED ───────────────────────────────────┐
                                                                   ╚═══════════╝                                                       │
                                                                                                                                       ▼
                                                                                                                                  ╔═══════════╗
                                                                                                                                  ║  Node C   ║  WASM: process(20) = 40   budget: 1→0   state[0]: 2→3
                                                                                                                                  ║  hop 3/3  ║  Action: REPLIED
                                                                                                                                  ╚═══════════╝
                                                                                                                                       │
                                                                                                                                       ▼
                                                                                                                                  Originator
                                                                                                                                  result = 40 ✓
```

**TRACE log output** (one line per hop, emitted in real time):

```
TRACE pkt=100 hop=1/3 op=EXEC input=5  output=10 route_action=0 exec_us=14 budget=3→2 action=FORWARDED state=[00 00 00 00 00 00 00 00]→[01 00 00 00 00 00 00 00]
TRACE pkt=100 hop=2/3 op=EXEC input=10 output=20 route_action=0 exec_us=11 budget=2→1 action=FORWARDED state=[01 00 00 00 00 00 00 00]→[02 00 00 00 00 00 00 00]
TRACE pkt=100 hop=3/3 op=EXEC input=20 output=40 route_action=0 exec_us=13 budget=1→0 action=REPLIED   state=[02 00 00 00 00 00 00 00]→[03 00 00 00 00 00 00 00]
```

| Hop | Node | Input | WASM (`x × 2`) | Output | Budget | `state[0]` | Action |
|-----|------|-------|----------------|--------|--------|------------|--------|
| 1 | Node A | 5 | 5 × 2 | **10** | 3 → 2 | 0 → 1 | `FORWARDED` |
| 2 | Node B | 10 | 10 × 2 | **20** | 2 → 1 | 1 → 2 | `FORWARDED` |
| 3 | Node C | 20 | 20 × 2 | **40** | 1 → 0 | 2 → 3 | `REPLIED` |

After the chain completes, the simulator runs the same scenario twice and asserts:

```
S(process(N, P₁)) = S(process(N, P₂))   ∀ hops   ✓
```

This proves the **§15.2 determinism invariant**: identical input packets always produce identical output packets.

---

## 🔄 Packet Lifecycle

Every packet processed by an ENP node passes through this exact pipeline:

```
                   ┌─────────────────┐
   UDP datagram ──►│  Deserialize    │  Parse wire bytes into enp_packet_t
                   └────────┬────────┘
                            │ fail → silent discard
                   ┌────────▼────────┐
                   │    Validate     │  Check version, opcode, lengths
                   └────────┬────────┘
                            │ fail → silent discard
                   ┌────────▼────────┐
                   │ Capability      │  Enforce allowed_ops, cap_max_hops,
                   │ Enforcement     │  cap_max_compute
                   └────────┬────────┘
                            │ fail → CAP_DENIED error response
                   ┌────────▼────────┐
                   │  Budget Check   │  Reject WASM execution if budget = 0
                   └────────┬────────┘
                            │ fail → BUDGET_EXHAUSTED error response
                   ┌────────▼────────┐
                   │ Opcode Dispatch │  FORWARD / EXEC / ROUTE_DECIDE
                   └────────┬────────┘
                            │ EXEC/ROUTE_DECIDE: decrement compute_budget
                   ┌────────▼────────┐
                   │  State Mutation │  state[0]++ (hop counter)
                   └────────┬────────┘
                            │ overflow at 255 → silent drop
                   ┌────────▼────────┐
                   │    Routing      │  Forward to next hop  OR  reply to originator
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  TRACE Emit     │  Structured log: timing, budget, state diff, action
                   └─────────────────┘
```

### Opcode Reference

| Opcode | Value | Description |
|--------|-------|-------------|
| `ENP_FORWARD` | `0` | Echo packet unchanged to next hop / originator |
| `ENP_EXEC` | `1` | Execute embedded WASM `process(input) → output`; replace payload |
| `ENP_ROUTE_DECIDE` | `2` | Execute WASM `route_decide(input) → {FORWARD, DROP, CLONE}` |

### Flag Reference

| Flag | Bit | Meaning |
|------|-----|---------|
| `ENP_FLAG_RESPONSE` | 0 | Packet is a response travelling back to originator |
| `ENP_FLAG_ERROR` | 1 | Processing error occurred |
| `ENP_FLAG_MULTIHOP` | 2 | Packet is source-routed |
| `ENP_FLAG_BUDGET_EXHAUSTED` | 3 | Compute budget was fully consumed |
| `ENP_FLAG_CAP_DENIED` | 4 | Capability check failed |

---

## 🔐 Capability & Budget Model

ENP v3 introduces a **per-packet capability token** — a lightweight, object-capability-inspired security model that constrains what any given packet is allowed to do, enforced independently at every node.

```
  Packet capability token (8 bytes in v3 header):
  ┌─────────────────────────────────┬───────────────┬────────────────┐
  │  allowed_ops  (u32 bitmask)     │ cap_max_hops  │ cap_max_compute│
  │  bit 0 = ENP_FORWARD permitted  │  (u8)         │ (u8)           │
  │  bit 1 = ENP_EXEC permitted     │  0 = no limit │ 0 = no limit   │
  │  bit 2 = ENP_ROUTE_DECIDE perm. │               │                │
  │  0x00000000 = all permitted     │               │                │
  └─────────────────────────────────┴───────────────┴────────────────┘
                                         +
  ┌──────────────────────────────────────┐
  │  compute_budget  (u16)               │
  │  0xFFFF = unlimited (never checked)  │
  │  0      = exhausted (WASM refused)   │
  │  N      = N executions remaining     │
  └──────────────────────────────────────┘
```

### Capability Enforcement Examples

| Scenario | `allowed_ops` | Node behaviour |
|----------|---------------|----------------|
| Only forwarding allowed | `0x00000001` (bit 0) | Rejects any `ENP_EXEC` or `ENP_ROUTE_DECIDE` packet |
| EXEC allowed, routing blocked | `0x00000002` (bit 1) | Permits WASM execution; rejects routing decisions |
| All operations allowed | `0x00000000` | No opcode restriction |
| Budget of 2 across 3 hops | `compute_budget=2` | Third WASM hop returns `BUDGET_EXHAUSTED` |

### Budget State Machine

```
  compute_budget:

  0xFFFF ──────────── UNLIMITED ──────────────────────────────────►
  (never decremented; WASM always executes if capability permits)

  N > 0 ──► [WASM executes] ──► N-1
             │
             └─ (if N-1 == 0) ──► next node returns BUDGET_EXHAUSTED
                                   if WASM opcode is attempted
```

---

## 📊 Observability & Tracing

Every packet handled by an ENP node — regardless of outcome — produces exactly one structured **TRACE** log line, emitted at `INFO` level immediately after processing.

```
TRACE pkt=<packet_id> hop=<index>/<count> op=<OPCODE>
      input=<i32> output=<i32> route_action=<0|1|2>
      exec_us=<microseconds> budget=<before>→<after>
      action=<REPLIED|FORWARDED|DROPPED|ERROR|BUDGET_EXHAUSTED>
      state=[<8 hex bytes before>]→[<8 hex bytes after>]
```

**Example — successful 3-hop exec chain:**

```
TRACE pkt=100 hop=1/3 op=EXEC input=3 output=6   exec_us=14  budget=3→2 action=FORWARDED state=[00 00 00 00 00 00 00 00]→[01 00 00 00 00 00 00 00]
TRACE pkt=100 hop=2/3 op=EXEC input=6 output=12  exec_us=11  budget=2→1 action=FORWARDED state=[01 00 00 00 00 00 00 00]→[02 00 00 00 00 00 00 00]
TRACE pkt=100 hop=3/3 op=EXEC input=12 output=24 exec_us=9   budget=1→0 action=REPLIED   state=[02 00 00 00 00 00 00 00]→[03 00 00 00 00 00 00 00]
```

**Example — capability denial:**

```
TRACE pkt=200 hop=1/1 op=EXEC input=5 output=0 exec_us=0 budget=5→5 action=ERROR state=[00…]→[00…]
# (ENP_FLAG_CAP_DENIED set; response returned to originator)
```

**Example — budget exhaustion:**

```
TRACE pkt=300 hop=3/3 op=EXEC input=20 output=0 exec_us=0 budget=0→0 action=BUDGET_EXHAUSTED state=[02…]→[02…]
```

### TRACE Record Fields

| Field | Type | Description |
|-------|------|-------------|
| `packet_id` | `u64` | Unique packet identifier |
| `hop_index` | `u8` | Position of this node in the hop table |
| `hop_count` | `u8` | Total hops declared in the packet |
| `opcode` | `u8` | Dispatched opcode (0/1/2) |
| `input` | `i32` | i32 extracted from payload on entry |
| `output` | `i32` | i32 result from WASM (0 if not EXEC) |
| `exec_us` | `u32` | WASM execution time in microseconds |
| `budget_before` | `u16` | `compute_budget` on entry |
| `budget_after` | `u16` | `compute_budget` after this hop |
| `action` | `u8` | Final action taken |
| `state_before[0..7]` | `u8[8]` | First 8 bytes of state on entry |
| `state_after[0..7]` | `u8[8]` | First 8 bytes of state on exit |

---

## 🛡 Security Model

ENP v3 is a **zero-trust-per-packet** system. Each node validates and enforces constraints independently, with no inter-node coordination.

### Threat Mitigations

| Threat | Mitigation |
|--------|-----------|
| Malicious WASM — infinite loop | `SIGALRM` 2-second execution timeout (POSIX) |
| Malicious WASM — memory bomb | 256 KiB linear memory hard limit |
| WASM sandbox escape | wasm3 interpreter isolation; no host function imports |
| Oversized packets | `payload_len` and `code_len` validated against hard maxima before any copy |
| Routing loops | `state[0]` hop counter; packet silently dropped at overflow (255) |
| Unauthorized opcode use | `allowed_ops` bitmask enforced per-hop, independently |
| Compute abuse (multi-hop WASM spam) | `compute_budget` decremented per execution |
| Excessive hop count | `cap_max_hops` ceiling enforced per-hop |
| Budget inflation attempt | `cap_max_compute` ceiling enforced per-hop |

### Trust Model

```
  ┌─────────────────────────────────────────────────────────┐
  │  Trusted:  nodes within the same administrative domain  │
  │            (honest-node model)                          │
  │                                                         │
  │  Untrusted: the originator's claimed capabilities;      │
  │             enforced but not authenticated              │
  │                                                         │
  │  Not addressed in v3:                                   │
  │   • Packet authentication (no signatures)               │
  │   • Multi-tenant isolation                              │
  │   • Byzantine fault tolerance                           │
  └─────────────────────────────────────────────────────────┘
```

See [`docs/ENP-RESEARCH-AXES.md`](docs/ENP-RESEARCH-AXES.md) for the formal analysis of Byzantine extension options.

---

## 🗂 Repository Layout

```
Executable-Network-Packets/
│
├── 📄 main.c                    CLI entry point (server / client / multihop / route)
├── 📄 Makefile                  Linux / macOS build (make sim, make ENP_WITH_WASM3=1)
├── 📄 CMakeLists.txt            Cross-platform build (Windows / MSVC)
│
├── 📁 include/
│   ├── enp_packet.h             Packet structure, wire-format constants, serialization API
│   ├── enp_wasm.h               WASM execution API (enp_wasm_exec, enp_wasm_exec_route)
│   ├── enp_net.h                Network server/client API
│   ├── enp_trace.h              Observability: trace record structure + emit API
│   └── enp_logger.h             Levelled timestamped logger API
│
├── 📁 core/
│   └── enp_packet.c             Serialization · deserialization · validation
│
├── 📁 net/
│   ├── enp_server.c             UDP node server: full handle_packet pipeline
│   └── enp_client.c             UDP client: single-hop and multi-hop packet construction
│
├── 📁 wasm/
│   └── enp_wasm.c               wasm3 integration: exec with timeout + memory limits
│
├── 📁 utils/
│   ├── enp_trace.c              Structured per-hop TRACE log emission
│   └── enp_logger.c             INFO / WARN / ERR / DBG logger with timestamps
│
├── 📁 sim/
│   └── enp_sim.c               ⭐ Reference simulator: in-process node chain,
│                                   canonical demo, determinism check, no dependencies
│
└── 📁 docs/
    ├── ENP-SPEC-v3.md           📋 Formal protocol specification (v3) — 18 sections
    └── ENP-RESEARCH-AXES.md     🔬 Research layer: composability, scalability, Byzantine
```

---

## 🔧 Building from Source

### Prerequisites

| Tool | Required for |
|------|-------------|
| `gcc` or `clang` (C11) | All targets |
| `make` | Linux / macOS build |
| `git` | Fetching wasm3 (`make wasm3-fetch`) |
| CMake 3.14+ | Cross-platform / Windows build |

### Build Targets

```sh
# In-process simulator (no dependencies)
make sim
./build/enp_sim

# Fetch wasm3 v0.5.0
make wasm3-fetch

# Full node binary with live WASM
make ENP_WITH_WASM3=1
./build/enp server 9000

# Clean all build artifacts
make clean

# CMake (cross-platform)
cmake -B build -DENP_WITH_WASM3=ON
cmake --build build
```

### Constants Reference

| Constant | Value | Meaning |
|----------|-------|---------|
| `ENP_VERSION` | `3` | Protocol version |
| `ENP_HEADER_SIZE` | `194` | Fixed header size (bytes) |
| `ENP_PAYLOAD_MAX_LEN` | `256` | Maximum payload section |
| `ENP_CODE_MAX_LEN` | `512` | Maximum WASM code section |
| `ENP_MAX_PACKET_SIZE` | `962` | Maximum total serialized packet |
| `ENP_MAX_HOPS` | `4` | Maximum entries in the hop table |
| `ENP_STATE_LEN` | `128` | State buffer size (bytes) |
| `ENP_BUDGET_UNLIMITED` | `0xFFFF` | Sentinel: unlimited budget |
| `ENP_DEFAULT_PORT` | `9000` | Default UDP port |
| `ENP_WASM_EXEC_TIMEOUT_MS` | `2000` | WASM execution timeout (POSIX) |

---

## 📋 Protocol Specification

The complete formal specification for ENP v3 is in [`docs/ENP-SPEC-v3.md`](docs/ENP-SPEC-v3.md).

**Contents:**

| Section | Topic |
|---------|-------|
| §1 | Introduction and positioning |
| §2 | Terminology |
| §3 | Wire format (194-byte fixed header + variable body) |
| §4 | Opcodes (FORWARD / EXEC / ROUTE_DECIDE) |
| §5 | Flag bits |
| §6 | Packet lifecycle (receive → validate → cap → budget → dispatch → route → trace) |
| §7 | Capability model (`allowed_ops`, `cap_max_hops`, `cap_max_compute`) |
| §8 | Execution budgeting (`compute_budget` states, decrement rule) |
| §9 | WASM execution contract (ABI, timeouts, memory limits) |
| §10 | Multi-hop routing (hop table layout, forwarding rules, return path) |
| §11 | State buffer (layout, `state[0]` hop counter, overflow) |
| §12 | Network semantics (node definition, delivery guarantees, CLONE model) |
| §13 | Security model (trust boundary, mitigations, remaining attack surface) |
| §14 | Failure modes (all defined error outcomes) |
| §15 | **Determinism guarantees** (WASM, node, network levels) |
| §16 | Observability (TRACE format, all fields) |
| §17 | Versioning and compatibility |
| §18 | Constants reference |

---

## 🔬 Research Layer

[`docs/ENP-RESEARCH-AXES.md`](docs/ENP-RESEARCH-AXES.md) formalizes the open theoretical questions that inform ENP v4 design.

| Axis | Question |
|------|---------|
| **Composability** | How do invariants (I1–I6) behave when a packet transits multiple administrative domains? Which are preserved automatically vs. require a signed capability attenuation protocol? |
| **Scalability & Abstraction Collapse** | When does the O(N) per-packet model break down? Formally: when `process(N, Pᵢ) = f(Pᵢ, σ_N)` — node output depends on prior packet history. |
| **Byzantine Fault Tolerance** | Enumerates 5 unmodeled adversarial threats (mutation, budget inflation, replay, silent drop, forged WASM output) and compares three defense strategies (HMAC, signed receipts, multipath BFT). |

---

## 👤 Credits

<div align="center">

---

### Designed, engineered, and authored by

# Daniel Kimeu

*Research-grade networking protocol design · WebAssembly execution fabrics · Formal protocol verification*

[![GitHub](https://img.shields.io/badge/GitHub-dnlkilonzi--pixel-181717?style=for-the-badge&logo=github)](https://github.com/dnlkilonzi-pixel)

---

| Component | Author |
|-----------|--------|
| ENP v3 Protocol Design | **Daniel Kimeu** |
| Wire format specification (v1 → v2 → v3) | **Daniel Kimeu** |
| Capability & budget security model | **Daniel Kimeu** |
| Reference C implementation | **Daniel Kimeu** |
| In-process reference simulator | **Daniel Kimeu** |
| Formal protocol specification (ENP-SPEC-v3.md) | **Daniel Kimeu** |
| Research axes document (ENP-RESEARCH-AXES.md) | **Daniel Kimeu** |
| TRACE observability system | **Daniel Kimeu** |
| WASM hand-assembled bytecode modules | **Daniel Kimeu** |

---

**Third-party components**

| Component | License | Used for |
|-----------|---------|----------|
| [wasm3](https://github.com/wasm3/wasm3) v0.5.0 | MIT | WebAssembly interpreter (optional build dependency) |

---

*ENP is a research project. The formal specification, implementation, and research layer are original work by Daniel Kimeu.*

</div>
