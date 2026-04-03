# ENP v3 – Open Research Axes

**Status:** Informational / Research Prelude  
**Scope:** Theoretical analysis only — no protocol changes proposed  
**Base version:** ENP v3 (194-byte wire header, §1–§18 of ENP-SPEC-v3.md)  
**Date:** 2026-04-03  

---

## Overview

ENP v3 is a validated, deterministic, single-domain execution fabric with the following core invariants:

| ID | Invariant | Spec section |
|----|-----------|--------------|
| **I1** | **Determinism:** `S(P₁) = S(P₂) ⟹ S(process(N, P₁)) = S(process(N, P₂))` | §15.2 |
| **I2** | **Budget monotonicity:** `compute_budget` is non-increasing along any hop chain | §8.2 |
| **I3** | **Stateless nodes:** node output is a pure function of the input packet | §12.1 |
| **I4** | **Capability enforcement:** `allowed_ops`, `cap_max_hops`, `cap_max_compute` are checked independently at every node | §7 |
| **I5** | **Single-path sequential execution:** hops execute in strict index order | §12.4 |
| **I6** | **Honest-node trust model:** all nodes in `hops[]` are assumed to behave correctly | §13.1 |

This document formalizes three research axes that extend beyond the current system's scope. Each axis identifies what the current system guarantees, what it does not, and what formal machinery would be required to close the gap. No code changes or protocol modifications are proposed.

---

## Table of Contents

1. [Composability Across Domains](#1-composability-across-domains)
2. [Scalability Semantics and Abstraction Collapse](#2-scalability-semantics-and-abstraction-collapse)
3. [Fault Model Completeness: Byzantine Extension](#3-fault-model-completeness-byzantine-extension)
4. [Cross-Cutting Concerns](#4-cross-cutting-concerns)

---

## 1. Composability Across Domains

### 1.1 Problem Statement

ENP v3 operates within a single administrative domain. All nodes share the same trust assumptions (I6), the same binary (§15.2 scope), and the same wire format. The composability question is:

> Given two ENP domains **A** and **B**, each independently satisfying I1–I6, under what conditions does a packet transiting A then B preserve those invariants?

### 1.2 Domain Model

Define an **ENP domain** `D = (N, C, T)` where:

- `N` is the set of nodes (all running the same reference binary within D).
- `C` is the domain's capability policy: a function `C: enp_packet_t → {permit, deny}`.
- `T` is the trust boundary: the set of IP/port endpoints reachable from within D.

A **cross-domain transfer** occurs when `hops[k]` is in domain A and `hops[k+1]` is in domain B. Define the **composition operator**:

```
D_A ∘ D_B : enp_packet_t → enp_packet_t
```

as the result of processing hops `[1..j]` in D_A, then hops `[j+1..hop_count-1]` in D_B, with the cross-domain boundary at hop index `j`.

### 1.3 Invariant Preservation Under Composition

| Invariant | Preserved under ∘? | Condition |
|-----------|--------------------|-----------|
| **I1** Determinism | **Yes** — determinism is a local property of each node | Requires identical binary within each domain; cross-domain requires both domains to run conforming implementations |
| **I2** Budget monotonicity | **Yes** — budget only decreases; no node can increase it | Requires that domain B does not re-initialize `compute_budget` to a higher value. Current wire format allows mutation by any node. |
| **I3** Stateless nodes | **Yes** — node purity is structural | No cross-domain state is shared |
| **I4** Capability enforcement | **No** — each domain applies its own policy `C` | Domain B may permit opcodes that domain A intended to deny. Requires a **capability attenuation protocol** (§1.4). |
| **I5** Sequential execution | **Yes** — hop ordering is packet-carried | `hop_index` continues incrementing across the boundary |
| **I6** Honest-node trust | **No** — domain A cannot verify that domain B's nodes are honest | Requires either mutual attestation or a trust federation protocol |

### 1.4 Capability Attenuation Model

Inspired by the object-capability discipline, define:

**Attenuation rule:** A domain boundary relay MUST NOT amplify capabilities. Formally:

```
allowed_ops(P_out) ⊆ allowed_ops(P_in)
cap_max_hops(P_out) ≤ cap_max_hops(P_in)
cap_max_compute(P_out) ≤ cap_max_compute(P_in)
```

where `P_in` is the packet arriving at the boundary and `P_out` is the packet forwarded into the receiving domain.

**Current gap:** ENP v3 has no enforcement mechanism at a domain boundary. Any intermediate node can rewrite capability fields because there is no cryptographic binding between the originator's intent and the wire fields.

**Hypothetical extension — signed capability token:**

```
cap_signature = HMAC-SHA256(
    key = domain_shared_secret,
    data = allowed_ops ‖ cap_max_hops ‖ cap_max_compute ‖ compute_budget_initial ‖ packet_id
)
```

This would be a v4 extension field (appended after byte 193). A receiving domain would verify the signature before applying the capability. Attenuation is enforced by requiring the relay to re-sign with a strictly narrower capability set.

### 1.5 Failure Modes Under Differing Trust Boundaries

| Scenario | Failure mode | Observable effect |
|----------|-------------|-------------------|
| Domain B permits `ENP_EXEC` but domain A blocked it via `allowed_ops` | Capability escalation — the packet executes WASM in B that A intended to prevent | Originator receives a response with WASM output that should not exist |
| Domain B re-initializes `compute_budget` upward | Budget inflation — the packet gets more execution than the originator authorized | Budget monotonicity (I2) violated |
| Domain B uses a different WASM interpreter version | Different timeout/memory behavior under edge cases | Determinism (I1) holds within each domain but cross-domain `exec_us` diverges; timeout failures may differ |
| Domain B is unreachable | Standard UDP loss | Originator timeout; indistinguishable from network partition |

### 1.6 Open Questions

1. Can `∘` be made associative? If `D_A ∘ (D_B ∘ D_C) = (D_A ∘ D_B) ∘ D_C`, then multi-domain chains can be reasoned about incrementally.
2. Is there a minimal set of signed fields that makes I4 hold under composition without signing the entire packet?
3. Can capability attenuation be expressed as a lattice operation on the `(allowed_ops, cap_max_hops, cap_max_compute)` triple?

---

## 2. Scalability Semantics and Abstraction Collapse

### 2.1 Current Scaling Behavior

ENP v3 simulation and execution scale as follows:

| Dimension | Complexity | Bound | Root cause |
|-----------|-----------|-------|------------|
| Single chain of N hops | O(N) | N ≤ 4 (`ENP_MAX_HOPS`) | Each hop is O(1) in packet size; dominated by 194-byte wire round-trip + WASM execution |
| M independent packets | O(M) | Unbounded | No shared state between packets; fully parallelizable |
| Wire serialization | O(1) per packet | 194 + payload_len + code_len bytes | Fixed-size header; deterministic layout |

**Why it scales:** The current model scales because of I3 (stateless nodes). Each packet is processed independently. There is no shared mutable state between packets, no lock contention, no ordering dependency across packet streams.

### 2.2 Abstraction Collapse Condition

Define **abstraction collapse** as the point at which the per-packet independent processing model breaks down, requiring the simulator (or verifier) to reason about inter-packet interactions.

**Formal condition:**

> Abstraction collapse occurs when the output of `process(N, P_i)` depends on the prior processing of `process(N, P_j)` for some `j ≠ i`. That is, when node N maintains **mutable cross-packet state** `σ_N` such that:
>
> ```
> process(N, P_i) = f(P_i, σ_N)
> σ_N' = g(σ_N, P_i)
> ```
>
> Under this model, I3 (stateless nodes) no longer holds. The output of processing P_i depends on the order in which packets were previously processed — `process(N, P_i)` is no longer a pure function of `P_i` alone.

### 2.3 Consequences of Node-Local Mutable State

If ENP nodes were extended to maintain local state (e.g., a congestion counter, a packet cache, or a routing table updated by passing packets), the following invariants would be affected:

| Invariant | Impact |
|-----------|--------|
| **I1** Determinism | **Broken** — output depends on arrival order of prior packets. Two identical packets processed at different times may produce different outputs. |
| **I3** Stateless nodes | **Violated by definition** |
| **I5** Sequential execution | Still holds within a single chain, but inter-chain ordering becomes relevant |

### 2.4 Consistency Model Requirements

If node state `σ_N` becomes mutable, the system requires a consistency model to define how concurrent packet streams interact:

| Consistency model | Definition | Applicability to ENP |
|-------------------|-----------|---------------------|
| **Sequential consistency** | All nodes observe the same global total order of state mutations | Required if determinism must hold across all packet streams. Expensive — requires coordination. |
| **Causal consistency** | State mutations respect happens-before ordering; concurrent mutations are unordered | Sufficient if determinism is only required within a single packet chain (I5 scope). Compatible with UDP's lack of global ordering. |
| **Eventual consistency** | Nodes converge to the same state eventually; no ordering guarantee during convergence | Insufficient for ENP's determinism guarantee. |

**Recommendation:** If node state is introduced in a future version, causal consistency is the minimum viable model. It preserves I1 within a single chain while acknowledging that cross-chain ordering is undefined (consistent with §15.3).

### 2.5 Simulation Scalability

The reference simulator (`sim/enp_sim.c`) operates in O(N) per chain, O(1) per hop. It scales linearly with the number of hops and independently across chains because it inherits I3.

**Scaling limits of simulation:**

| Property being verified | Scales? | Reason |
|------------------------|---------|--------|
| Per-hop determinism (I1) | **Yes** — each hop is independent | No inter-hop state |
| Budget monotonicity (I2) | **Yes** — single chain check | Linear scan of budget values |
| Multi-chain interaction | **N/A** — not applicable in v3 | I3 ensures no interaction |
| CLONE branch divergence | **Yes per branch** — each branch is an independent chain | Non-joinable (§12.3) |
| Hypothetical node-state interactions | **No** — would require modeling `σ_N` mutation order | Abstraction collapse (§2.2) |

### 2.6 Open Questions

1. Can a restricted form of node state (e.g., append-only counters) preserve I1 while enabling useful cross-packet features like rate limiting?
2. What is the minimal coordination primitive needed to support a join operation for CLONE branches without full sequential consistency?
3. If `ENP_MAX_HOPS` is extended beyond 4, at what point does the wire header overhead dominate payload utility?

---

## 3. Fault Model Completeness: Byzantine Extension

### 3.1 Current Threat Model

ENP v3 assumes honest nodes (I6). The existing security model (§13) addresses:

| Threat | Defense | Spec section |
|--------|---------|-------------|
| Malicious WASM (infinite loop) | `SIGALRM` 2-second timeout | §9.1, §13.2 |
| Malicious WASM (memory bomb) | 256 KiB memory limit | §9.1, §13.2 |
| Oversized packets | Length field validation | §6.2 |
| Routing loops | `state[0]` hop counter, drop at 255 | §11.2 |
| Unauthorized opcode | `allowed_ops` bitmask | §7.1 |
| Compute abuse | `compute_budget` decrement + ceiling | §8 |

### 3.2 Unmodeled Adversarial Scenarios

The following threats assume one or more nodes in `hops[]` are **Byzantine** (arbitrarily malicious):

| Threat | Description | Current defense | Gap |
|--------|-------------|----------------|-----|
| **T1: Packet mutation in transit** | A compromised node modifies `packet_id`, `state[]`, or `payload[]` before forwarding | None | No integrity check on forwarded packets |
| **T2: Budget inflation** | A compromised node re-initializes `compute_budget` to a higher value | None | Budget field is mutable by any node |
| **T3: Replay attack** | An adversary re-sends a previously observed packet with the same `packet_id` | None | No nonce or sequence number freshness check; nodes are stateless so cannot deduplicate |
| **T4: Silent drop** | A compromised node drops a packet without forwarding | None — observable only as originator timeout | No acknowledgment protocol; indistinguishable from network loss |
| **T5: Forged WASM output** | A compromised node replaces the WASM execution result with an arbitrary value in the `payload[]` | None | No output attestation |

### 3.3 Defense Strategy Comparison

Three defense strategies are analyzed for compatibility with the ENP v3 architecture:

#### Strategy A: Per-Hop HMAC

**Mechanism:** Each domain shares a symmetric key. A forwarding node computes:

```
hmac = HMAC-SHA256(key, header_bytes[0..193] ‖ payload ‖ code)
```

and appends the 32-byte HMAC as a v4 extension field (bytes 194–225).

| Property | Assessment |
|----------|-----------|
| Defends against | T1 (mutation), T2 (budget inflation) |
| Does not defend against | T3 (replay), T4 (silent drop), T5 (forged output — HMAC is computed after execution) |
| Wire format compatibility | **Compatible** — extension field appended after byte 193; v3 nodes reject (version mismatch) |
| Key management | Requires shared secret per domain; does not scale to cross-domain without key federation |
| Overhead | 32 bytes per packet; O(1) computation per hop |

#### Strategy B: Signed Execution Receipts

**Mechanism:** After processing a packet, a node appends a **receipt**:

```
receipt = {
    node_id   : uint32,
    hop_index : uint8,
    input     : int32,
    output    : int32,
    state_hash: SHA256(state[0..127]),
    budget_after: uint16,
    signature : Ed25519(private_key, receipt_fields)
}
```

Receipts accumulate in a variable-length **receipt chain** appended after the packet body.

| Property | Assessment |
|----------|-----------|
| Defends against | T1 (mutation — detectable by next honest node), T2 (budget inflation — detectable), T5 (forged output — detectable by verifying receipt chain) |
| Does not defend against | T3 (replay — unless combined with nonce), T4 (silent drop — receipt never generated) |
| Wire format compatibility | **Requires v4 redesign** — variable-length receipt chain exceeds the fixed-header model |
| Key management | Requires per-node key pair; public keys must be distributed or discoverable |
| Overhead | ~100 bytes per hop; O(N) total for N hops; Ed25519 signature per hop |

#### Strategy C: Redundant Multipath BFT (2f+1)

**Mechanism:** The originator sends the packet over `2f+1` independent paths through different node sets. The originator (or a designated aggregator) collects responses and takes the majority result.

| Property | Assessment |
|----------|-----------|
| Defends against | T1, T2, T4, T5 — all detectable by majority vote | 
| Does not defend against | T3 (replay — orthogonal to path redundancy) |
| Wire format compatibility | **Incompatible with current routing model** — single `hops[]` array supports one path only. Would require either multiple packet copies (application-level) or a v4 multipath routing table. |
| Overhead | `(2f+1)×` bandwidth; requires `2f+1` disjoint node sets |
| Structural conflict | ENP's CLONE mechanism (§12.3) produces independent non-joinable branches. BFT requires a join point with majority-vote logic, which is the merge primitive ENP explicitly lacks. |

### 3.4 Compatibility Summary

| Strategy | v3 wire compat | Preserves I3 | Preserves I1 | Practical for v4? |
|----------|---------------|-------------|-------------|-------------------|
| A: Per-hop HMAC | ✓ (extension field) | ✓ | ✓ | **Yes** — minimal change |
| B: Signed receipts | ✗ (variable-length chain) | ✓ | ✓ (modulo signature timing) | **Possible** — requires header redesign |
| C: Multipath BFT | ✗ (requires multipath routing) | ✓ per path | ✓ per path | **Research-stage** — requires merge primitive |

### 3.5 Replay Defense (T3) — Orthogonal Concern

Replay attacks require a freshness mechanism. Options:

| Mechanism | Description | Compatibility |
|-----------|-------------|--------------|
| **Nonce in packet** | Add a monotonic nonce field; nodes reject packets with nonce ≤ last-seen | **Violates I3** — requires node-local state (last-seen nonce). Triggers abstraction collapse (§2.2). |
| **Time-based window** | Accept packets only if `timestamp` is within a configurable window of the node's clock | Compatible with I3; requires clock synchronization (NTP). Can be added as a v4 validation rule. |
| **Originator-side dedup** | The originator tracks `packet_id` responses and ignores duplicates | Compatible; no protocol change needed. Does not prevent re-execution at nodes. |

### 3.6 Structural Observation

The ENP v3 security model is **trust-in-transit** — functionally equivalent to how MPLS, SR-MPLS, and SRv6 operate in production. All three assume that the nodes along the label-switched or segment-routed path are within a single trust domain. Byzantine fault tolerance is not a standard requirement for these protocols.

ENP's position is architecturally consistent: the threat model matches the deployment model (intra-domain, operator-controlled nodes). Extending to Byzantine tolerance would constitute a fundamental shift from a **network fabric** to a **distributed consensus system**, with corresponding complexity and performance costs.

### 3.7 Open Questions

1. Can Strategy A (HMAC) and a time-based replay window be combined into a single v4 extension field that is backward-compatible for v3 nodes to skip?
2. If receipt chains (Strategy B) are adopted, what is the maximum receipt chain length before the packet exceeds typical MTU (1500 bytes)?
   - Current max packet: 962 bytes. Headroom: ~538 bytes. At ~100 bytes per receipt, max 5 receipts — exactly matching `ENP_MAX_HOPS=4` plus one originator receipt.
3. Is there a hybrid of B and C where `2f+1` paths each produce signed receipts, and the originator verifies a quorum of consistent receipt chains?

---

## 4. Cross-Cutting Concerns

### 4.1 Relationship Between Axes

The three research axes interact:

```
Composability ←→ Byzantine Tolerance
     ↑                    ↑
     └──── Scalability ───┘
```

- **Composability × Byzantine:** Cross-domain composition is meaningless without at least Strategy A (HMAC) to prevent capability escalation at the boundary.
- **Scalability × Byzantine:** Strategy C (multipath BFT) multiplies bandwidth by `2f+1`, directly impacting scalability.
- **Composability × Scalability:** Multi-domain chains increase effective hop count; if `ENP_MAX_HOPS` is extended, wire header size grows.

### 4.2 ENP v3 Assumptions Preserved

This document is purely analytical. The following assumptions from ENP v3 remain in force and are not modified:

- 194-byte wire header (§3.1)
- `ENP_MAX_HOPS = 4` (§10.1)
- `ENP_STATE_LEN = 128` (§11.1)
- UDP transport, best-effort delivery (§12.2)
- Honest-node trust model (§13.1)
- Single-path sequential execution (§12.4)
- Stateless nodes (§12.1)

### 4.3 Criteria for ENP v4

Based on this analysis, an ENP v4 protocol revision should prioritize:

1. **Extension field mechanism** — a TLV (type-length-value) trailer after byte 193 that v3 nodes can skip, enabling HMAC, receipts, and future extensions without a header redesign.
2. **Signed capability binding** — cryptographic link between `packet_id` and capability fields to prevent escalation under composition.
3. **Time-based freshness** — optional validation rule using `timestamp` to reject stale packets without node-local state.

These three additions address the highest-impact gaps identified across all three research axes while preserving backward compatibility with the v3 wire format.

---

*End of document. This analysis is a prelude to ENP v4 design and does not constitute a protocol change proposal.*
