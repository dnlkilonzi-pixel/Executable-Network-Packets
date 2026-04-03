# ENP v3 – Programmable Network Execution Fabric: Formal Protocol Specification

**Status:** Informational  
**Version:** 3  
**Date:** 2026-04-03  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Wire Format](#3-wire-format)
   - 3.1 [Fixed Header (194 bytes)](#31-fixed-header-194-bytes)
   - 3.2 [Variable-Length Body](#32-variable-length-body)
   - 3.3 [Field Encoding](#33-field-encoding)
   - 3.4 [Packet Size Constraints](#34-packet-size-constraints)
4. [Opcodes](#4-opcodes)
   - 4.1 [ENP_FORWARD (0)](#41-enp_forward-0)
   - 4.2 [ENP_EXEC (1)](#42-enp_exec-1)
   - 4.3 [ENP_ROUTE_DECIDE (2)](#43-enp_route_decide-2)
5. [Flag Bits](#5-flag-bits)
6. [Packet Lifecycle](#6-packet-lifecycle)
   - 6.1 [Receive and Parse](#61-receive-and-parse)
   - 6.2 [Structural Validation](#62-structural-validation)
   - 6.3 [Capability Enforcement](#63-capability-enforcement)
   - 6.4 [Budget Check](#64-budget-check)
   - 6.5 [Opcode Dispatch](#65-opcode-dispatch)
   - 6.6 [State Mutation](#66-state-mutation)
   - 6.7 [Routing Decision](#67-routing-decision)
   - 6.8 [Response Generation](#68-response-generation)
7. [Capability Model](#7-capability-model)
   - 7.1 [Opcode Mask (`allowed_ops`)](#71-opcode-mask-allowed_ops)
   - 7.2 [Hop Count Ceiling (`cap_max_hops`)](#72-hop-count-ceiling-cap_max_hops)
   - 7.3 [Compute Ceiling (`cap_max_compute`)](#73-compute-ceiling-cap_max_compute)
   - 7.4 [Capability Denial Response](#74-capability-denial-response)
8. [Execution Budgeting](#8-execution-budgeting)
   - 8.1 [Budget States](#81-budget-states)
   - 8.2 [Decrement Rule](#82-decrement-rule)
   - 8.3 [Budget Exhaustion Response](#83-budget-exhaustion-response)
9. [WASM Execution Contract](#9-wasm-execution-contract)
   - 9.1 [Runtime Constraints](#91-runtime-constraints)
   - 9.2 [Function Signatures](#92-function-signatures)
   - 9.3 [Payload Encoding](#93-payload-encoding)
   - 9.4 [Execution Failure Handling](#94-execution-failure-handling)
10. [Multi-Hop Routing](#10-multi-hop-routing)
    - 10.1 [Hop Table Layout](#101-hop-table-layout)
    - 10.2 [Forwarding Rules](#102-forwarding-rules)
    - 10.3 [Return Path](#103-return-path)
11. [State Buffer](#11-state-buffer)
    - 11.1 [Layout and Reserved Fields](#111-layout-and-reserved-fields)
    - 11.2 [Hop Counter Overflow](#112-hop-counter-overflow)
12. [Network Semantics](#12-network-semantics)
    - 12.1 [Node Definition](#121-node-definition)
    - 12.2 [Delivery Guarantees](#122-delivery-guarantees)
    - 12.3 [Packet Splitting and Merging](#123-packet-splitting-and-merging)
    - 12.4 [Execution Order Across Hops](#124-execution-order-across-hops)
13. [Security Model](#13-security-model)
    - 13.1 [Trust Boundary](#131-trust-boundary)
    - 13.2 [Threat Mitigations](#132-threat-mitigations)
    - 13.3 [Remaining Attack Surface](#133-remaining-attack-surface)
14. [Failure Modes](#14-failure-modes)
15. [Determinism Guarantees](#15-determinism-guarantees)
    - 15.1 [WASM Execution Determinism](#151-wasm-execution-determinism)
    - 15.2 [Node Processing Determinism](#152-node-processing-determinism)
    - 15.3 [Network-Level Non-Determinism](#153-network-level-non-determinism)
    - 15.4 [Testability Contract](#154-testability-contract)
16. [Observability](#16-observability)
17. [Versioning and Compatibility](#17-versioning-and-compatibility)
18. [Constants Reference](#18-constants-reference)

---

## 1. Introduction

ENP (Executable Network Packet) is a **programmable network execution fabric**. Unlike conventional networking where data moves between fixed functions, ENP embeds executable logic — as WebAssembly (WASM) bytecode — directly inside the packet. Each network node that receives an ENP packet **executes the logic it carries**, then forwards the mutated packet (with updated state and a decremented compute budget) to the next node or returns it to the originator.

This document provides the formal specification for ENP **protocol version 3**, covering:

- The wire format and all header fields
- Opcode semantics and the packet lifecycle at each node
- The capability and budgeting security model
- Network semantics: what a node is, what is guaranteed, and what is not
- Determinism: the conditions under which identical inputs produce identical outputs

The reference implementation is in C and targets POSIX/Linux and Windows platforms. All normative behaviors described in this document are directly implemented in the reference code.

**Positioning.** ENP is positioned as:

- **Edge Compute Runtime** — computation is transport-native, not server-bound. Unlike AWS Lambda@Edge or Cloudflare Workers, the function migrates with the packet; no deployment step is needed.
- **IoT Swarm Execution Layer** — packets carry instructions to drones, sensors, and mesh nodes; no cloud round-trip for processing decisions.
- **Self-Healing Network Fabric** — packets carry their own routing logic; `ENP_ROUTE_DECIDE` lets the WASM inside the packet choose to forward, drop, or clone itself at each hop, enabling autonomic rerouting around failures.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Packet** | A serialized ENP datagram: a fixed 194-byte header followed by a variable-length payload and WASM code section. |
| **Node** | A process running `enp_server_run()` on a UDP port. It receives, validates, executes, and routes ENP packets. |
| **Originator** | The sender of an ENP packet; the entity that populates `hops[0]/hop_ports[0]` as the return address. |
| **Hop** | A single transit through a node. Each hop increments `hop_index` and decrements `compute_budget` (if applicable). |
| **WASM module** | The bytecode in `pkt.code[]`. It is loaded fresh per packet per node; there is no persistent module state between hops. |
| **Capability** | A per-packet set of constraints (`allowed_ops`, `cap_max_hops`, `cap_max_compute`) enforced by every node before dispatch. |
| **Budget** | `compute_budget`: a 16-bit counter decremented by 1 for each WASM-executing hop. Prevents runaway multi-hop WASM chains. |
| **State buffer** | `pkt.state[0..127]`: 128 bytes carried across all hops and mutated by nodes. `state[0]` is the reserved hop counter. |
| **Route action** | The integer returned by `route_decide()`: `0=FORWARD`, `1=DROP`, `2=CLONE` (prototype). |
| **MUST / SHALL** | Normative requirement. An implementation that violates this is non-conformant. |
| **SHOULD** | Recommended behavior. Deviation is allowed only with good reason. |
| **MAY** | Optional behavior. |

---

## 3. Wire Format

### 3.1 Fixed Header (194 bytes)

All multi-byte fields are **big-endian** (network byte order). The header is always exactly 194 bytes; a packet with fewer bytes in the datagram MUST be rejected.

```
Offset  Len  Type      Field
------  ---  --------  -----
  0      1   u8        version         (MUST be 3)
  1      1   u8        opcode          (0=FORWARD, 1=EXEC, 2=ROUTE_DECIDE)
  2      2   u16       flags           (see §5)
  4      4   u32       src             (originator IPv4, host byte order)
  8      4   u32       dst             (destination IPv4, host byte order)
 12      8   u64       packet_id       (sender-assigned unique identifier)
 20      8   u64       timestamp       (Unix milliseconds at time of send)
 28      2   u16       payload_len     (bytes in payload section; 0..256)
 30      2   u16       code_len        (bytes in code section; 0..512)

 -- v2 extensions --
 32      1   u8        hop_count       (0 = single-hop; else 1..4)
 33      1   u8        hop_index       (current position in hops[]; 0..hop_count-1)
 34     16   u32[4]    hops            (IPv4 addresses for each hop slot)
 50      8   u16[4]    hop_ports       (UDP port for each hop slot)
 58    128   u8[128]   state           (cross-node state buffer)

 -- v3 extensions --
186      4   u32       allowed_ops     (capability opcode bitmask; 0 = unrestricted)
190      1   u8        cap_max_hops    (max hop_count; 0 = no limit)
191      1   u8        cap_max_compute (max initial compute_budget; 0 = no limit)
192      2   u16       compute_budget  (0xFFFF=unlimited; 0=exhausted; else remaining)
```

### 3.2 Variable-Length Body

Immediately following the header:

```
Offset         Len            Field
-------------- -------------- -----
194            payload_len    payload   (input/output data; big-endian i32 at [0..3])
194+payload_len  code_len     code      (WASM bytecode for EXEC / ROUTE_DECIDE)
```

Total serialized size: `194 + payload_len + code_len` bytes. Maximum: `194 + 256 + 512 = 962` bytes.

### 3.3 Field Encoding

- **All integer fields** use explicit big-endian byte-by-byte serialization (not relying on `htonl`). This guarantees identical wire bytes on all platforms regardless of host endianness.
- **`src` and `dst`** are IPv4 addresses in host byte order stored as 32-bit big-endian on the wire. Nodes do not currently use these fields for routing; they are informational.
- **`packet_id`** is assigned by the originator and SHOULD be unique per sender per session. Nodes do not deduplicate by `packet_id`.
- **`timestamp`** is updated by each node before forwarding (`pkt.timestamp = enp_timestamp_ms()`), recording the time of last processing.
- **`hops[]` and `hop_ports[]`** use host byte order for IPv4 addresses and are encoded big-endian on the wire. When a node opens a forward socket it calls `htonl()` on the extracted address.

### 3.4 Packet Size Constraints

| Field | Minimum | Maximum |
|-------|---------|---------|
| `payload_len` | 0 | 256 |
| `code_len` | 0 (FORWARD only) | 512 |
| `hop_count` | 0 | 4 |
| `compute_budget` | 0 | 65535 (0xFFFF) |

A node MUST reject (silently discard) any packet where `payload_len > 256` or `code_len > 512` or where the datagram is shorter than `194 + payload_len + code_len`.

---

## 4. Opcodes

### 4.1 ENP_FORWARD (0)

**Purpose:** Echo the packet back to the originator unchanged, or advance it to the next hop.

**Node behavior:**
1. No WASM is loaded or executed.
2. The state buffer is mutated (hop counter incremented).
3. Routing proceeds per §6.7.

**Constraints:**
- `code_len` MAY be 0 (code is ignored).
- `compute_budget` is not decremented.

### 4.2 ENP_EXEC (1)

**Purpose:** Execute the embedded WASM `process()` function and replace the payload with the i32 result.

**Node behavior:**
1. Capability and budget checks execute first (§6.3, §6.4).
2. The WASM module is loaded, `process(i32 input) → i32` is called.
3. The return value is written back to `payload[0..3]` as a 4-byte big-endian i32.
4. `compute_budget` is decremented by 1 (if not unlimited).
5. State mutation and routing proceed per §6.6, §6.7.

**Constraints:**
- `code_len` MUST be > 0; a packet with `opcode=ENP_EXEC` and `code_len=0` MUST be rejected during validation.
- `payload_len` SHOULD be ≥ 4 to carry an i32 input; if `payload_len < 4`, the input value is derived from the available bytes (single byte if `payload_len=1`, else 0).

### 4.3 ENP_ROUTE_DECIDE (2)

**Purpose:** Execute the embedded WASM `route_decide()` function to determine the routing action at this node.

**Node behavior:**
1. Capability and budget checks execute first.
2. The WASM module is loaded, `route_decide(i32 input) → i32` is called.
3. The return value is interpreted as an `enp_route_action_t`:
   - `0 = ENP_ACTION_FORWARD`: continue normal routing.
   - `1 = ENP_ACTION_DROP`: silently discard the packet at this node.
   - `2 = ENP_ACTION_CLONE`: in the current implementation, treated identically to FORWARD (prototype behavior; multipath forwarding is not yet implemented).
4. `compute_budget` is decremented by 1 (if not unlimited).
5. If action is DROP, the packet is discarded; no response is sent.
6. If action is FORWARD (or CLONE), state mutation and routing proceed per §6.6, §6.7.

**Constraints:**
- `code_len` MUST be > 0.
- If the WASM call fails, the node defaults to FORWARD (safe default: packet continues).

---

## 5. Flag Bits

The `flags` field is a 16-bit bitmask. Bits not listed are reserved and MUST be zero.

| Bit | Name | Direction | Meaning |
|-----|------|-----------|---------|
| 0 | `ENP_FLAG_RESPONSE` | Node→Originator | Set by the final (or only) node when sending a reply. |
| 1 | `ENP_FLAG_ERROR` | Node→Originator | Set when the node encountered an error processing this packet. |
| 2 | `ENP_FLAG_MULTIHOP` | Client→Node | Advisory: packet is source-routed. Nodes do not require this bit; they detect multi-hop via `hop_count > 0`. |
| 3 | `ENP_FLAG_BUDGET_EXHAUSTED` | Node→Originator | Set alongside `ENP_FLAG_ERROR` when `compute_budget == 0` caused rejection. |
| 4 | `ENP_FLAG_CAP_DENIED` | Node→Originator | Set alongside `ENP_FLAG_ERROR` when a capability check failed. |

---

## 6. Packet Lifecycle

The following is the normative step-by-step processing sequence that every conforming node MUST execute for each received datagram.

### 6.1 Receive and Parse

1. The node receives a UDP datagram of at most `ENP_MAX_PACKET_SIZE` (962) bytes.
2. If the datagram is shorter than `ENP_HEADER_SIZE` (194 bytes), it is **silently discarded**. No response is sent.
3. `enp_packet_deserialize()` reads the header fields from the wire buffer into the in-memory `enp_packet_t` structure. If `payload_len` or `code_len` exceed their maxima, deserialization fails and the packet is discarded.
4. If the serialized total length `(194 + payload_len + code_len)` exceeds the datagram size, the packet is discarded.

### 6.2 Structural Validation

`enp_packet_validate()` checks:

- `version == ENP_VERSION (3)`. Packets with any other version MUST be discarded.
- `opcode ∈ {0, 1, 2}`. Unknown opcodes MUST be discarded.
- `payload_len ≤ 256`, `code_len ≤ 512`.
- If `opcode ∈ {ENP_EXEC, ENP_ROUTE_DECIDE}`, then `code_len > 0`.
- `hop_count ≤ ENP_MAX_HOPS (4)`.
- If `hop_count > 0`, then `hop_index < hop_count`.

Any failure in this step results in a **silent discard** — no error response is sent.

### 6.3 Capability Enforcement

Capability checks occur **before** opcode dispatch. A failure produces a typed error response (§7.4) — never a silent discard.

**Step A — Opcode mask check:**
If `capability.allowed_ops ≠ 0` and the bit `(1 << opcode)` is not set in `allowed_ops`, the node:
1. Sets `ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED` on the response.
2. Emits a TRACE record with `action=ERROR`.
3. Sends the error response to the immediate sender.
4. Returns; no further processing.

**Step B — Hop count ceiling check:**
If `capability.cap_max_hops > 0` and `hop_count > cap_max_hops`, same error sequence.

**Step C — Compute budget ceiling check:**
If `capability.cap_max_compute > 0` and `compute_budget ≠ 0xFFFF` and `compute_budget > cap_max_compute`, same error sequence.

**Rationale for check order:** The opcode check is first (cheapest). The budget ceiling check uses the *declared* budget; because budget only decreases across hops, a packet that passes this check at the first node will always pass it at subsequent nodes.

### 6.4 Budget Check

If `opcode ∈ {ENP_EXEC, ENP_ROUTE_DECIDE}` and `compute_budget == 0` (not unlimited, not > 0):

1. Sets `ENP_FLAG_ERROR | ENP_FLAG_BUDGET_EXHAUSTED`.
2. Emits a TRACE record with `action=BUDGET_EXHAUSTED`.
3. Sends the error response to the immediate sender.
4. Returns.

A budget of `0xFFFF` bypasses this check entirely and is never decremented.

### 6.5 Opcode Dispatch

The WASM engine is invoked (if applicable) as described in §4. The node records:
- `exec_us`: wall-clock WASM execution time in microseconds.
- `output`: the i32 return value (for ENP_EXEC).
- `route_action`: the action decision (for ENP_ROUTE_DECIDE).

If WASM fails (parse error, function not found, timeout, OOM):
- For `ENP_EXEC`: `ENP_FLAG_ERROR` is set; processing does not continue to routing.
- For `ENP_ROUTE_DECIDE`: the node defaults to `ENP_ACTION_FORWARD` and logs an error.

### 6.6 State Mutation

After successful opcode dispatch (and if the packet is not being dropped), the node increments `state[0]` by 1.

If `state[0] == 255` (overflow), the packet is **dropped** (TRACE action=DROPPED) rather than forwarded. This prevents infinite routing loops caused by a misconfigured hop table.

`state[1..127]` is available for application logic and is not modified by the node itself.

### 6.7 Routing Decision

**Single-hop** (`hop_count == 0`): Proceed to §6.8 (send response to immediate sender).

**Multi-hop** (`hop_count > 0`):
- If `hop_index < hop_count - 1`: this is **not the last node**.
  - Increment `hop_index`.
  - Clear `ENP_FLAG_RESPONSE`.
  - Update `timestamp`.
  - Forward the packet (via a new UDP socket) to `hops[hop_index] : hop_ports[hop_index]`.
  - Emit TRACE `action=FORWARDED`. Return.
- If `hop_index == hop_count - 1`: this is the **last node**.
  - Set `ENP_FLAG_RESPONSE`.
  - Send the packet to `hops[0] : hop_ports[0]` (the originator's return address).
  - Emit TRACE `action=REPLIED`. Return.

### 6.8 Response Generation

For single-hop packets: set `ENP_FLAG_RESPONSE`, serialize, and send to the immediate UDP sender address. Emit TRACE `action=REPLIED`.

---

## 7. Capability Model

The capability model allows an originator (or a controlling infrastructure layer) to declare **per-packet constraints** that every node in the route MUST enforce. Capabilities travel inside the packet and cannot be relaxed by a node — only the originator sets them.

### 7.1 Opcode Mask (`allowed_ops`)

A 32-bit bitmask. Bit `N` being set means opcode `N` is **permitted**.

```c
ENP_OP_BIT(ENP_EXEC)         == (1u << 1) == 0x00000002
ENP_OP_BIT(ENP_ROUTE_DECIDE) == (1u << 2) == 0x00000004
ENP_OP_BIT(ENP_FORWARD)      == (1u << 0) == 0x00000001
```

`allowed_ops == 0` (`ENP_OP_ALL`) means **no restriction** — all opcodes are permitted.

**Use cases:**
- A management plane can issue packets with `allowed_ops = ENP_OP_BIT(ENP_FORWARD)` to prevent any WASM execution on the path.
- A trusted orchestrator can issue packets with `allowed_ops = ENP_OP_BIT(ENP_EXEC)` to prevent routing manipulation.

### 7.2 Hop Count Ceiling (`cap_max_hops`)

If non-zero, the packet's `hop_count` MUST NOT exceed this value. A packet with `hop_count > cap_max_hops` is denied.

Value `0` means no limit.

### 7.3 Compute Ceiling (`cap_max_compute`)

If non-zero and `compute_budget ≠ 0xFFFF`, the packet's `compute_budget` MUST NOT exceed this value. This limits how many WASM executions the packet can cause — useful for enforcing cost quotas in a metered environment.

Value `0` means no limit. `compute_budget == 0xFFFF` (unlimited) bypasses this check.

### 7.4 Capability Denial Response

When any capability check fails, the node sends an error response carrying the **original packet fields** (including the capability that was violated), with these modifications:

- `ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED` set in `flags`.
- The response is sent to the **immediate UDP sender** (not to `hops[0]`), because at the time of denial the node cannot trust the hop table.

---

## 8. Execution Budgeting

### 8.1 Budget States

| `compute_budget` value | Meaning |
|------------------------|---------|
| `0xFFFF` | Unlimited — WASM executes freely; budget is never decremented. |
| `1..0xFFFE` | Remaining executions — decremented by 1 at each WASM-executing node. |
| `0` | Exhausted — WASM execution refused; node returns BUDGET_EXHAUSTED error. |

### 8.2 Decrement Rule

After a **successful** WASM execution (ENP_EXEC or ENP_ROUTE_DECIDE), if `compute_budget ≠ 0xFFFF`, the node decrements `compute_budget` by 1 in the outgoing packet. This decrement persists across hops; subsequent nodes see the reduced budget.

The decrement occurs **after** successful execution, not before. A node that fails the budget check (budget == 0) returns an error before any execution attempt.

### 8.3 Budget Exhaustion Response

When `compute_budget == 0` and a WASM opcode is requested:

- `ENP_FLAG_ERROR | ENP_FLAG_BUDGET_EXHAUSTED` set in `flags`.
- Response sent to immediate UDP sender.
- The exhausted-budget packet is **not forwarded**; the chain stops at this node.

---

## 9. WASM Execution Contract

### 9.1 Runtime Constraints

The wasm3 interpreter is used with the following hard limits:

| Constraint | Value | Enforcement |
|------------|-------|-------------|
| Interpreter stack | 64 KiB | `ENP_WASM_STACK_SIZE` |
| Linear memory | 256 KiB max | Checked after `m3_LoadModule` |
| Execution timeout | 2 seconds | POSIX `SIGALRM` + `sigsetjmp` (POSIX only; Windows has no timeout) |

Each WASM invocation creates a **fresh environment and runtime** (`m3_NewEnvironment`, `m3_NewRuntime`). There is no shared state between invocations, between packets, or across hops. A packet's WASM module cannot read or write the node's memory, the packet header, or the state buffer; it receives only the integer input and returns an integer output.

### 9.2 Function Signatures

| Opcode | Required export | Signature (WAT) |
|--------|-----------------|-----------------|
| ENP_EXEC | `process` | `(func (param i32) (result i32))` |
| ENP_ROUTE_DECIDE | `route_decide` | `(func (param i32) (result i32))` |

If the required function is not exported by the WASM module, execution fails (§9.4).

### 9.3 Payload Encoding

The i32 input to WASM is read from `payload[0..3]` as a big-endian 32-bit signed integer:

```
input = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
```

If `payload_len < 4` but > 0, only `payload[0]` is used (zero-extended to i32). If `payload_len == 0`, input is 0.

The i32 output of `ENP_EXEC` is written back to `payload[0..3]` in the same big-endian encoding, setting `payload_len = 4`.

### 9.4 Execution Failure Handling

| Failure cause | ENP_EXEC behavior | ENP_ROUTE_DECIDE behavior |
|--------------|-------------------|--------------------------|
| Module parse error | Set `ENP_FLAG_ERROR`; stop | Log error; default to FORWARD |
| Function not found | Set `ENP_FLAG_ERROR`; stop | Log error; default to FORWARD |
| Execution timeout | Set `ENP_FLAG_ERROR`; stop | Log error; default to FORWARD |
| Out of memory | Set `ENP_FLAG_ERROR`; stop | Log error; default to FORWARD |

The asymmetry is deliberate: for `ENP_ROUTE_DECIDE`, failing closed (dropping the packet) is typically worse than failing open (forwarding), so the safe default is FORWARD. For `ENP_EXEC`, the result would be meaningless, so the packet is flagged as an error.

---

## 10. Multi-Hop Routing

### 10.1 Hop Table Layout

```
hops[0] / hop_ports[0]  →  Return address (originator)
hops[1] / hop_ports[1]  →  First processing node
hops[2] / hop_ports[2]  →  Second processing node
hops[3] / hop_ports[3]  →  Third processing node (max ENP_MAX_HOPS-1 = 3)
```

`hop_count` = total number of populated slots (including slot 0). Maximum is 4.  
`hop_index` = the slot index of the node that should process the packet right now.

The originator sets `hop_index = 1` before sending to indicate that `hops[1]` is the first processing node. The originator fills `hops[0]` with its own address (done automatically by `enp_client_send_multihop`).

### 10.2 Forwarding Rules

A node at position `hop_index` forwards to `hops[hop_index + 1]` after incrementing `hop_index`. The node opens a **new UDP socket per forward** (fire-and-forget). It does not wait for acknowledgment from the next node.

The forwarded packet carries:
- The updated `payload` (result of WASM execution, if applicable).
- The updated `state` (hop counter incremented).
- The updated `compute_budget` (decremented, if applicable).
- The updated `timestamp`.
- The same `hop_count`, `hops[]`, and `hop_ports[]` as the received packet.

### 10.3 Return Path

When the last processing node finishes, it sends to `hops[0] : hop_ports[0]`. It uses the same fire-and-forget mechanism (new temporary UDP socket).

The originator's `enp_client_send_multihop()` binds a local UDP socket and inserts its address into `hops[0]` before sending. It then blocks on `recvfrom` with a configurable timeout waiting for the response from the last node.

---

## 11. State Buffer

### 11.1 Layout and Reserved Fields

The state buffer is 128 bytes (`ENP_STATE_LEN`), carried verbatim through all hops.

| Byte(s) | Owner | Meaning |
|---------|-------|---------|
| `state[0]` | Protocol | **Hop counter**: incremented by each node after successful dispatch. Read-only for WASM; modified only by the node runtime. |
| `state[1..127]` | Application | Available for arbitrary cross-hop state. Not modified by the node runtime. |

### 11.2 Hop Counter Overflow

If a node would increment `state[0]` past 255 (the u8 maximum), it instead **drops the packet** (TRACE action=DROPPED, no response). This is the protocol's loop detection mechanism. A well-formed route with `hop_count ≤ 4` will never reach 255.

---

## 12. Network Semantics

### 12.1 Node Definition

**Formally:** An ENP node is a stateless UDP service that, for each received datagram, executes the deterministic function:

```
f(packet, local_clock) → (action, outgoing_packet?)
```

where:
- `action ∈ {REPLIED, FORWARDED, DROPPED, ERROR, BUDGET_EXHAUSTED}`
- `outgoing_packet` is present for all actions except DROPPED

**Stateless** means: a node holds no per-packet or per-session state between datagrams. All state that must persist across hops lives inside the packet's `state[]` buffer. The node's only external inputs are the received datagram and the local clock (used only for `timestamp` updates and WASM timeout enforcement; the clock does not affect routing or execution outcomes).

**Logically stateless, physically state-constrained:** This distinction is important. While a node maintains no application-level state, its physical processing is constrained by fields that are evaluated at execution time and are not carried in the packet itself:

| Constraint source | Where it lives | Nature |
|-------------------|---------------|--------|
| Routing table / next-hop address | Encoded in `hops[]` inside the packet | Packet-local; node is pure |
| Compute budget enforcement | `compute_budget` field inside the packet | Packet-local; node is pure |
| Hop tracking (`hop_index`) | `hop_index` field inside the packet | Packet-local; node is pure |
| Capability validation (`allowed_ops`, `cap_max_hops`, `cap_max_compute`) | Capability fields inside the packet | Packet-local; node is pure |
| WASM execution time limit | Node's local clock (not in packet) | **Physically constrained** — node-local, non-deterministic under load |

All four of the apparent "node-local state" concerns (routing, budget, hop tracking, capability validation) are in fact packet-carried fields — the node is a pure function of the packet. The sole genuine node-local constraint is the WASM timeout clock, which is explicitly excluded from the determinism guarantee in §15.2.

**Practical implication:** Any two nodes running the same binary will process identical packets identically. A single node restarted mid-route will process the next forwarded packet identically to if it had never restarted.

### 12.2 Delivery Guarantees

ENP uses UDP as its transport. The following guarantees are provided **by the protocol layer** and the following are **explicitly not guaranteed**:

| Property | Guarantee level |
|----------|----------------|
| Packet delivery to next hop | **Best-effort** — UDP; no retransmission |
| Packet ordering between hops | **Not guaranteed** — each hop is an independent UDP send |
| Exactly-once execution at a node | **Not guaranteed** — UDP duplicates can cause re-execution |
| Delivery of error responses to originator | **Best-effort** |
| Payload integrity | **Guaranteed** — fixed-size wire format; length fields are validated before copy |
| State buffer integrity | **Guaranteed** within a packet's lifetime |

**Consequence for application design:** Applications requiring reliable delivery MUST implement idempotency (e.g., check `packet_id`) or add a reliability layer above ENP. The `packet_id` field is available for this purpose; nodes do not deduplicate by it.

### 12.3 Packet Splitting and Merging

**Splitting (ENP_ACTION_CLONE):** The `ENP_ACTION_CLONE` return value from `route_decide()` is defined in the protocol as "forward to all remaining hops simultaneously." In the current reference implementation, CLONE is treated identically to FORWARD. A conforming future implementation MUST send the packet to all `hops[hop_index+1..hop_count-1]` simultaneously with independent copies.

**Merging:** ENP has no merge primitive. Packets are independent datagrams; once split, their results cannot be combined at the protocol level. Application-level aggregation requires a coordination node that acts as the last hop for multiple packets.

**Formal execution model for CLONE — non-join semilattice:**

ENP's CLONE execution model is a **non-join semilattice**: execution trees can branch (via CLONE) but have no defined join operation. This is an intentional design choice, not an oversight, but it has formal consequences that implementors and users must understand:

| Consequence | Description |
|-------------|-------------|
| **Race conditions** | Two branches from the same CLONE originate from the same packet state. If both branches write to a shared coordination node, arrival order is undefined. Applications MUST be designed so that the result is correct regardless of which branch arrives first. |
| **Divergent state evolution** | After CLONE, each branch carries an independent copy of `state[]`. Mutations in branch A are invisible to branch B. The two execution trees evolve independently and irreconcilably after the split point. |
| **Non-joinable execution trees** | The protocol provides no mechanism to wait for all branches of a CLONE or to merge their `state[]` buffers. A coordinator that receives N responses from N branches receives N independent state snapshots; it cannot reconstruct the "combined" state without application-level logic. |

**Implication for §15 (Determinism):** Network-level execution of a CLONE path is non-deterministic in delivery order. Node-level execution of each individual branch remains deterministic per §15.2. The determinism guarantee applies to each branch in isolation, not to the aggregate result of a CLONE split.

### 12.4 Execution Order Across Hops

Execution is **strictly sequential** in a single-path route:

```
Node A executes → forwards → Node B executes → forwards → ... → Originator
```

Node B sees the output of Node A in `payload[]` and the updated `state[]`. There is no parallelism in a linear route.

For routes where CLONE is used (multipath), the order of execution across branches is **undefined** — branches execute concurrently in separate UDP chains. The originator may receive multiple response packets (one per branch). The ENP protocol does not define a merge point; this is left to the application. The formal properties of this model — including race conditions, divergent state evolution, and non-joinability — are specified in §12.3.

---

## 13. Security Model

### 13.1 Trust Boundary

ENP is a **zero-trust-per-packet** system at the protocol level. Each node:
- Validates the packet structure independently.
- Enforces capabilities independently (a compromised intermediate node cannot relax a capability set by the originator).
- Runs WASM in an isolated interpreter with hard resource limits.

The originator is trusted to set its own capabilities correctly. The protocol does not authenticate the originator — any sender can construct any packet.

### 13.2 Threat Mitigations

| Threat | Mitigation |
|--------|-----------|
| Malicious WASM (infinite loop) | 2-second SIGALRM timeout per execution |
| Malicious WASM (memory bomb) | 256 KiB linear memory limit; checked after module load |
| WASM escaping the interpreter | wasm3 interpreter isolation; no host function imports in the current ABI |
| Oversized packets | `payload_len` and `code_len` validated against hard maxima before any copy |
| Routing loops | `state[0]` hop counter; drop at 255 |
| Unauthorized opcode use | `allowed_ops` bitmask enforced per-hop |
| Compute abuse (multi-hop WASM spam) | `compute_budget` decremented per execution; `cap_max_compute` limits initial budget |
| Excessive hop count | `cap_max_hops` limits `hop_count` per-hop |
| Buffer overread during deserialization | `size` parameter checked against `194 + payload_len + code_len` before any variable-length copy |

### 13.3 Remaining Attack Surface

The following are **not currently mitigated**:

| Gap | Risk |
|-----|------|
| No packet authentication | Any sender can craft an ENP packet. Capability constraints are advisory, not signed. |
| No multi-tenant isolation | Multiple packets from different senders execute in the same node process. There is no namespace or memory isolation between concurrent packets. |
| WASM timeout not enforced on Windows | Windows builds of the reference implementation have no execution timeout; a malicious WASM module can block the node indefinitely. |
| No IPv6 support | Hop addresses are 32-bit IPv4 only. IPv6 networks are not supported in v3. |
| ENP_ACTION_CLONE not implemented | The multipath forward action is defined but produces single-path behavior, creating an inconsistency between the spec and the implementation. |

---

## 14. Failure Modes

The following table enumerates all defined failure outcomes, their triggers, the node's response, and the flags set on the error response packet.

| Failure | Trigger | Node action | Flags set |
|---------|---------|-------------|-----------|
| Malformed packet | Datagram < 194 bytes, or length fields inconsistent | Silent discard | (none; no response) |
| Validation failure | Wrong version, unknown opcode, code_len=0 for EXEC | Silent discard | (none; no response) |
| CAP_DENIED (opcode) | Opcode not in `allowed_ops` bitmask | Error response to sender | `ERROR \| CAP_DENIED` |
| CAP_DENIED (hop count) | `hop_count > cap_max_hops` | Error response to sender | `ERROR \| CAP_DENIED` |
| CAP_DENIED (budget) | `compute_budget > cap_max_compute` | Error response to sender | `ERROR \| CAP_DENIED` |
| BUDGET_EXHAUSTED | `compute_budget == 0` and WASM opcode | Error response to sender | `ERROR \| BUDGET_EXHAUSTED` |
| WASM execution error | Parse, link, or runtime failure in ENP_EXEC | Error response (no forwarding) | `ERROR` |
| WASM timeout | WASM runs > 2 seconds (POSIX) | Error response (no forwarding) | `ERROR` |
| WASM route failure | Parse/runtime failure in ENP_ROUTE_DECIDE | Default to FORWARD; log error | (none; processing continues) |
| Routing loop detected | `state[0]` would exceed 255 | Silent drop (TRACE logged) | (none; no response) |
| ROUTE_DECIDE DROP | `route_decide()` returns 1 | Silent drop (TRACE logged) | (none; no response) |

**Important:** Only failures in §6.3 and §6.4 (capability and budget) produce a response back to the originator. All other failures either silently discard or continue with a default. This means:
- The originator can distinguish a capability/budget failure (receives an error response) from a network drop (receives nothing, times out).
- The originator cannot distinguish a WASM execution error from a network drop in the non-CAP/non-budget case unless it receives the error-flagged response.

---

## 15. Determinism Guarantees

This section specifies under which conditions ENP execution is deterministic, which is required for testability, simulation, and enterprise auditability.

### 15.1 WASM Execution Determinism

**Guarantee:** Given the same WASM bytecode and the same i32 input, `enp_wasm_exec()` and `enp_wasm_exec_route()` produce the **same i32 output** on every call, on every platform, provided the WASM module:

1. Does not use non-deterministic WASM instructions (none are available in the current ENP WASM ABI — there are no host function imports, no random number generation, no I/O).
2. Does not exceed resource limits (timeout or memory limit failures are not deterministic with respect to wall-clock time on loaded systems).
3. Uses only the provided i32 input and deterministic arithmetic operations.

**Source of non-determinism in WASM:** Execution timing (and thus timeout behavior) is wall-clock dependent. On a severely loaded system, a module that normally completes in 1.9 seconds may exceed the 2-second limit. Applications requiring hard real-time guarantees SHOULD keep WASM modules well below the timeout threshold.

### 15.2 Node Processing Determinism

**Guarantee:** Given the same input packet bytes (identical wire representation), a node running the reference implementation produces the **same output action, the same outgoing packet bytes, and the same TRACE record** on every invocation, with the following exceptions:

| Non-deterministic field | Source |
|------------------------|--------|
| `timestamp` in outgoing packet | Wall-clock time (`enp_timestamp_ms()`); varies per invocation |
| `exec_us` in TRACE record | Wall-clock WASM execution time; varies per invocation |

All **semantic** fields — `payload`, `state`, `compute_budget`, `flags`, `hop_index`, `action` — are fully deterministic given the same input packet.

**Formal statement:**

> Let **S** be the *semantic state* of a packet, defined as all wire fields except `timestamp` and `exec_us`. Let **N** be an ENP node and **E** be an execution environment (CPU, OS, WASM interpreter version). Define `process(N, P)` as the pair `(action, P_out)` produced by N processing packet P.
>
> **Determinism invariant:** For any two executions of `process(N, P)` under the same N, the same E, and packets P₁, P₂ such that `S(P₁) = S(P₂)`:
>
> ```
> S(process(N, P₁)) = S(process(N, P₂))
> ```
>
> That is: when two input packets are semantically identical (same payload, state, capabilities, budget, opcodes, and routing fields), the node produces semantically identical outputs (same action, same output payload, same state mutation, same flags).
>
> **Scope of the guarantee:** The invariant holds within a single execution environment E. Cross-platform behavioral equivalence holds for all semantics except WASM execution timeout, which depends on wall-clock time and is therefore environment-dependent (see §15.1).

### 15.3 Network-Level Non-Determinism

The following properties of a multi-hop ENP execution are **not deterministic** at the network level:

| Property | Reason |
|----------|--------|
| Whether any given hop completes | UDP packet loss |
| Which hop a packet arrives at first (in multipath/CLONE scenarios) | Concurrent UDP delivery |
| Total end-to-end latency | Network conditions, node load |
| Whether a WASM timeout fires | System load affects real-time clock |

These are inherent to best-effort UDP transport and are not deficiencies of the ENP protocol.

### 15.4 Testability Contract

The determinism guarantees in §15.2 enable the following test patterns:

**1. Unit test of node behavior** (no network):  
Call `handle_packet()` directly with a crafted `enp_packet_t` and assert the TRACE record fields and output packet fields. No UDP socket required.

**2. Simulation of a multi-hop chain** (single process):  
Create N packets sequentially, applying each node's processing function in order. The output of node K is the input to node K+1. The result is identical to a live multi-hop execution modulo `timestamp` and `exec_us`.

**3. Regression testing with golden packets**:  
Record the wire bytes of a packet at the originator and at each hop. Because serialization is deterministic (big-endian, no padding, fixed offsets), the same packet bytes will always serialize and deserialize to identical `enp_packet_t` values. A test that sends a fixed packet and checks the response payload is a valid regression test.

**4. Replay attack testing**:  
Because nodes are stateless, replaying a packet to a node always produces the same result (modulo timestamp and exec_us). This enables negative testing: a packet that should be denied by budget or capability will always be denied.

---

## 16. Observability

Every packet handled by a node produces exactly one TRACE log line, emitted via `enp_trace_log()` at the INFO log level immediately after the packet is processed. The TRACE record captures a complete snapshot of the hop's inputs and outputs.

### TRACE Log Format

```
TRACE pkt=<packet_id> hop=<hop_index>/<hop_count> op=<OPCODE>
      input=<i32> output=<i32> route_action=<0|1|2>
      exec_us=<microseconds> budget=<before>→<after>
      action=<REPLIED|FORWARDED|DROPPED|ERROR|BUDGET_EXHAUSTED>
      state=[<8 hex bytes before>]→[<8 hex bytes after>]
```

**Example:**
```
TRACE pkt=100 hop=1/3 op=EXEC input=3 output=6 route_action=0 exec_us=47
      budget=2→1 action=FORWARDED state=[00 00 00 00 00 00 00 00]→[01 00 00 00 00 00 00 00]
```

### TRACE Record Fields

| Field | Type | Description |
|-------|------|-------------|
| `packet_id` | u64 | From packet header |
| `hop_index` | u8 | Position of this node in the hop table |
| `hop_count` | u8 | Total hops declared in the packet |
| `opcode` | u8 | Opcode dispatched (0/1/2) |
| `input` | i32 | i32 extracted from payload on entry |
| `output` | i32 | i32 result from process() (0 if not EXEC) |
| `route_action` | u8 | Return value of route_decide() (0 if not ROUTE_DECIDE) |
| `exec_us` | u32 | WASM execution time in microseconds (0 if no WASM) |
| `budget_before` | u16 | `compute_budget` on entry |
| `budget_after` | u16 | `compute_budget` after this hop |
| `action` | u8 | Final action taken (see `enp_trace_action_t`) |
| `state_before[0..7]` | u8[8] | First 8 bytes of state buffer on entry |
| `state_after[0..7]` | u8[8] | First 8 bytes of state buffer on exit |

**Guarantee:** A TRACE record is emitted for **every** packet that passes structural validation (§6.2), including packets that are denied by capability or budget. Packets that fail structural validation or deserialization do not produce a TRACE record (they are silently discarded before the trace infrastructure is initialized).

---

## 17. Versioning and Compatibility

### Version Field

The first byte of every packet MUST be the protocol version. The current version is **3**. Nodes MUST reject packets with `version ≠ 3` silently (no error response, to avoid version-scanning amplification).

### Wire Format Evolution

Version 3 is a strict superset of version 2 (186-byte header). The v3 additions (bytes 186–193) are appended at the end of the header, so the layout of all v2 fields is unchanged at the same byte offsets.

A v2 node receiving a v3 packet will reject it (version mismatch). A v3 node receiving a v2 packet will reject it (version mismatch). There is no negotiation or backward compatibility mode.

### Future Version Guidelines

Future versions SHOULD:
- Append new fixed-width fields after byte 193.
- Introduce new opcode values (currently 3–255 are reserved).
- Reserve new flag bits (bits 5–15 are currently reserved).

---

## 18. Constants Reference

| Constant | Value | Description |
|----------|-------|-------------|
| `ENP_VERSION` | `3` | Protocol version |
| `ENP_HEADER_SIZE` | `194` | Fixed header size in bytes |
| `ENP_PAYLOAD_MAX_LEN` | `256` | Maximum payload section length |
| `ENP_CODE_MAX_LEN` | `512` | Maximum WASM code section length |
| `ENP_MAX_PACKET_SIZE` | `962` | Maximum total serialized packet size |
| `ENP_MAX_HOPS` | `4` | Maximum entries in the hop table |
| `ENP_STATE_LEN` | `128` | State buffer size in bytes |
| `ENP_BUDGET_UNLIMITED` | `0xFFFF` | Sentinel: unlimited compute budget |
| `ENP_OP_ALL` | `0` | Sentinel: all opcodes permitted (no restriction) |
| `ENP_DEFAULT_PORT` | `9000` | Default UDP port for a node |
| `ENP_WASM_STACK_SIZE` | `65536` | wasm3 interpreter stack (bytes) |
| `ENP_WASM_MAX_MEMORY` | `262144` | Maximum WASM linear memory (bytes) |
| `ENP_WASM_EXEC_TIMEOUT_MS` | `2000` | WASM execution timeout (milliseconds, POSIX) |
| `ENP_TRACE_STATE_SNAP` | `8` | Bytes of state buffer captured in a TRACE record |

| Flag | Bit | Value |
|------|-----|-------|
| `ENP_FLAG_RESPONSE` | 0 | `0x0001` |
| `ENP_FLAG_ERROR` | 1 | `0x0002` |
| `ENP_FLAG_MULTIHOP` | 2 | `0x0004` |
| `ENP_FLAG_BUDGET_EXHAUSTED` | 3 | `0x0008` |
| `ENP_FLAG_CAP_DENIED` | 4 | `0x0010` |

| Opcode | Value |
|--------|-------|
| `ENP_FORWARD` | `0` |
| `ENP_EXEC` | `1` |
| `ENP_ROUTE_DECIDE` | `2` |

| Route action | Value |
|-------------|-------|
| `ENP_ACTION_FORWARD` | `0` |
| `ENP_ACTION_DROP` | `1` |
| `ENP_ACTION_CLONE` | `2` (prototype: same as FORWARD) |
