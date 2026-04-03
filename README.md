# Executable Network Packets (ENP)

ENP is a **programmable network execution fabric**.  Instead of moving data between fixed functions, ENP embeds executable logic (WebAssembly bytecode) directly inside the packet.  Each network node that receives an ENP packet *executes the logic it carries*, then forwards the mutated packet — with updated state and a decremented compute budget — to the next node or returns it to the originator.

See [`docs/ENP-SPEC-v3.md`](docs/ENP-SPEC-v3.md) for the formal protocol specification (v3).

---

## Quick start

### 1. Build the reference simulator (no dependencies)

```sh
make sim
./build/enp_sim
```

The simulator runs entirely in-process — no running server, no UDP sockets required.  It exercises the canonical multi-hop chain, budget enforcement, capability denial, programmable routing, and the §15.2 determinism invariant.

### 2. Build the full node binary (requires wasm3)

```sh
make wasm3-fetch          # clone wasm3 v0.5.0 into third_party/
make ENP_WITH_WASM3=1     # build enp binary with live WASM execution
```

### 3. Run a live node

```sh
# Terminal 1 – start a node on port 9000
./build/enp server 9000

# Terminal 2 – send an ENP_EXEC packet (process(5) → 10)
./build/enp client 127.0.0.1 9000
```

---

## Canonical demo — multi-hop stateful ENP_EXEC chain

The reference simulator (`sim/enp_sim.c`) implements **one** canonical demonstration:

```
Originator → NodeA(hop 1) → NodeB(hop 2) → NodeC(hop 3) → Originator
```

| Hop | Input | WASM (`x*2`) | Output | Budget | state[0] | Action    |
|-----|-------|-------------|--------|--------|----------|-----------|
| 1   | 5     | 5 × 2       | 10     | 3 → 2  | 0 → 1    | FORWARDED |
| 2   | 10    | 10 × 2      | 20     | 2 → 1  | 1 → 2    | FORWARDED |
| 3   | 20    | 20 × 2      | 40     | 1 → 0  | 2 → 3    | REPLIED   |

Every hop emits a structured TRACE record.  The simulator then runs the same scenario twice and asserts `S(run_A) = S(run_B)` at every hop, proving the §15.2 determinism invariant.

---

## Repository layout

| Path | Description |
|------|-------------|
| `sim/enp_sim.c` | **Reference simulator** — in-process node chain, canonical demo, determinism check |
| `docs/ENP-SPEC-v3.md` | Formal protocol specification (v3) |
| `include/enp_packet.h` | Packet structure and wire-format API |
| `core/enp_packet.c` | Serialisation / deserialisation / validation |
| `net/enp_server.c` | UDP node server (`handle_packet` pipeline) |
| `net/enp_client.c` | UDP client (single-hop and multi-hop) |
| `wasm/enp_wasm.c` | wasm3 execution engine with timeout and memory limits |
| `utils/enp_trace.c` | Structured per-hop TRACE log emission |
| `utils/enp_logger.c` | Levelled timestamped logger |
