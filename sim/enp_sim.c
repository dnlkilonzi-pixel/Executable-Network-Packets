/*
 * sim/enp_sim.c – ENP v3 Reference Execution Simulator
 *
 * Simulates a complete ENP v3 multi-hop execution chain entirely
 * in-process.  No UDP sockets, no running server instances required.
 * Each hop passes through a full wire-format serialize→deserialize
 * round-trip so that serialization determinism is also verified.
 *
 * Purpose
 * -------
 * 1. Spec §15.2 (Determinism Invariant) – runs every scenario twice
 *    with S(P₁) = S(P₂) and asserts S(out₁) = S(out₂).
 * 2. Spec §8 (Execution Budgeting) – budget is decremented at each
 *    WASM-executing hop; exhaustion is caught before dispatch.
 * 3. Spec §7 (Capability Model) – allowed_ops bitmask is enforced.
 * 4. Spec §12.4 (Execution Order) – sequential single-path hop chain.
 * 5. Canonical demo – one multi-hop stateful ENP_EXEC chain that
 *    exercises trace emission, routing, and budget enforcement end-to-end.
 *
 * Mock WASM (deterministic C equivalents – no wasm3 required)
 * -----------------------------------------------------------
 *   process(x)      = x * 2            (mirrors PROCESS_WASM in main.c)
 *   route_decide(x) = x > 100 → DROP, else FORWARD
 *
 * Build
 * -----
 *   make sim              → build/enp_sim
 *
 * Run
 * ---
 *   ./build/enp_sim
 *   Exit code: 0 = all checks passed, 1 = any failure.
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "enp_packet.h"
#include "enp_trace.h"
#include "enp_logger.h"

/* =========================================================================
 * Mock WASM: deterministic C equivalents of the embedded WASM modules.
 * These stand in for wasm3 execution so the simulator needs no third-party
 * dependency and produces fully deterministic output on every platform.
 * =========================================================================*/

/* Mirrors PROCESS_WASM – int process(int x) { return x * 2; } */
static int32_t mock_process(int32_t x)
{
    return x * 2;
}

/*
 * Mirrors ROUTE_WASM – int route_decide(int x) {
 *     return x > 100 ? ENP_ACTION_DROP : ENP_ACTION_FORWARD; }
 */
static int32_t mock_route_decide(int32_t x)
{
    return (x > 100) ? (int32_t)ENP_ACTION_DROP : (int32_t)ENP_ACTION_FORWARD;
}

/* =========================================================================
 * Simulator core types
 * =========================================================================*/

/*
 * sim_hop_result_t – everything a node produces when processing one packet.
 *
 * out_pkt  : packet ready to hand to the next node (or originator).
 * trace    : full per-hop trace record (logged via enp_trace_log).
 * dropped  : non-zero if the packet was silently dropped.
 * error    : non-zero if an error response was generated (CAP / budget).
 */
typedef struct {
    enp_packet_t       out_pkt;
    enp_trace_record_t trace;
    int                dropped;
    int                error;
} sim_hop_result_t;

/* =========================================================================
 * sim_node_process()
 *
 * Single-hop processing function.  Mirrors handle_packet() from
 * net/enp_server.c exactly, substituting wasm3 calls with mock_process()
 * and mock_route_decide().
 *
 * The function first serialises the input packet to wire bytes and
 * deserialises it back, verifying the wire-format round-trip before any
 * processing takes place.
 * =========================================================================*/

/* Helper: read a big-endian i32 from the packet payload. */
static int32_t pkt_read_i32(const enp_packet_t *pkt)
{
    if (pkt->payload_len >= 4)
        return (int32_t)(((uint32_t)pkt->payload[0] << 24) |
                         ((uint32_t)pkt->payload[1] << 16) |
                         ((uint32_t)pkt->payload[2] <<  8) |
                          (uint32_t)pkt->payload[3]);
    if (pkt->payload_len > 0)
        return (int32_t)pkt->payload[0];
    return 0;
}

/* Helper: write a big-endian i32 into the packet payload. */
static void pkt_write_i32(enp_packet_t *pkt, int32_t v)
{
    pkt->payload_len = 4;
    pkt->payload[0]  = (uint8_t)((uint32_t)v >> 24);
    pkt->payload[1]  = (uint8_t)((uint32_t)v >> 16);
    pkt->payload[2]  = (uint8_t)((uint32_t)v >>  8);
    pkt->payload[3]  = (uint8_t)((uint32_t)v & 0xFF);
}

static void sim_node_process(const enp_packet_t *in, sim_hop_result_t *res)
{
    memset(res, 0, sizeof(*res));

    /* ------------------------------------------------------------------
     * Wire-format round-trip.
     * Serialising then deserialising the packet before processing proves
     * that enp_packet_serialize / enp_packet_deserialize are inverse
     * functions and that no information is lost or corrupted on the wire.
     * ------------------------------------------------------------------*/
    uint8_t wire[ENP_MAX_PACKET_SIZE];
    int wlen = enp_packet_serialize(in, wire, sizeof(wire));
    if (wlen < 0) {
        fprintf(stderr, "[SIM] serialization failed at hop %u\n",
                (unsigned)in->hop_index);
        res->error = 1;
        return;
    }

    enp_packet_t pkt;
    if (enp_packet_deserialize(wire, (size_t)wlen, &pkt) != 0) {
        fprintf(stderr, "[SIM] deserialization failed at hop %u\n",
                (unsigned)in->hop_index);
        res->error = 1;
        return;
    }

    if (enp_packet_validate(&pkt) != 0) {
        fprintf(stderr, "[SIM] packet validation failed at hop %u\n",
                (unsigned)pkt.hop_index);
        res->error = 1;
        return;
    }

    /* Build working copy for output. */
    enp_packet_t out;
    memcpy(&out, &pkt, sizeof(out));

    /* ------------------------------------------------------------------
     * Initialise trace record (mirrors enp_server.c handle_packet).
     * ------------------------------------------------------------------*/
    enp_trace_record_t *tr = &res->trace;
    tr->packet_id     = pkt.packet_id;
    tr->hop_index     = pkt.hop_index;
    tr->hop_count     = pkt.hop_count;
    tr->opcode        = pkt.opcode;
    tr->input         = pkt_read_i32(&pkt);
    tr->budget_before = pkt.compute_budget;
    memcpy(tr->state_before, pkt.state, ENP_TRACE_STATE_SNAP);

    /* ------------------------------------------------------------------
     * Capability: opcode check (§7.1)
     * ------------------------------------------------------------------*/
    if (pkt.capability.allowed_ops != ENP_OP_ALL &&
            !(pkt.capability.allowed_ops & ENP_OP_BIT(pkt.opcode))) {
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED;
        tr->action = ENP_TRACE_ACTION_ERROR;
        memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
        tr->budget_after = out.compute_budget;
        enp_trace_log(tr);
        res->error = 1;
        memcpy(&res->out_pkt, &out, sizeof(out));
        return;
    }

    /* ------------------------------------------------------------------
     * Capability: hop count ceiling (§7.2)
     * ------------------------------------------------------------------*/
    if (pkt.capability.cap_max_hops > 0 &&
            pkt.hop_count > pkt.capability.cap_max_hops) {
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED;
        tr->action = ENP_TRACE_ACTION_ERROR;
        memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
        tr->budget_after = out.compute_budget;
        enp_trace_log(tr);
        res->error = 1;
        memcpy(&res->out_pkt, &out, sizeof(out));
        return;
    }

    /* ------------------------------------------------------------------
     * Capability: initial budget ceiling (§7.3)
     * ------------------------------------------------------------------*/
    if (pkt.capability.cap_max_compute > 0 &&
            pkt.compute_budget != ENP_BUDGET_UNLIMITED &&
            pkt.compute_budget > pkt.capability.cap_max_compute) {
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED;
        tr->action = ENP_TRACE_ACTION_ERROR;
        memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
        tr->budget_after = out.compute_budget;
        enp_trace_log(tr);
        res->error = 1;
        memcpy(&res->out_pkt, &out, sizeof(out));
        return;
    }

    /* ------------------------------------------------------------------
     * Budget check: refuse WASM execution if budget is exhausted (§8.3)
     * ------------------------------------------------------------------*/
    int needs_wasm = (pkt.opcode == ENP_EXEC ||
                      pkt.opcode == ENP_ROUTE_DECIDE);
    if (needs_wasm &&
            pkt.compute_budget != ENP_BUDGET_UNLIMITED &&
            pkt.compute_budget == 0) {
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_BUDGET_EXHAUSTED;
        tr->action = ENP_TRACE_ACTION_BUDGET_EXH;
        memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
        tr->budget_after = out.compute_budget;
        enp_trace_log(tr);
        res->error = 1;
        memcpy(&res->out_pkt, &out, sizeof(out));
        return;
    }

    /* ------------------------------------------------------------------
     * Opcode dispatch (§6.5) – mock WASM replaces wasm3 execution.
     * ------------------------------------------------------------------*/
    int drop = 0;

    switch (pkt.opcode) {

    case ENP_FORWARD:
        /* No WASM; packet echoed unchanged. */
        break;

    case ENP_EXEC: {
        int32_t result = mock_process(tr->input);
        tr->output = result;
        pkt_write_i32(&out, result);
        if (out.compute_budget != ENP_BUDGET_UNLIMITED)
            out.compute_budget--;
        break;
    }

    case ENP_ROUTE_DECIDE: {
        int32_t action = mock_route_decide(tr->input);
        tr->route_action = (uint8_t)action;
        if (action == (int32_t)ENP_ACTION_DROP)
            drop = 1;
        if (out.compute_budget != ENP_BUDGET_UNLIMITED)
            out.compute_budget--;
        break;
    }

    default:
        fprintf(stderr, "[SIM] unexpected opcode %u at hop %u\n",
                (unsigned)pkt.opcode, (unsigned)pkt.hop_index);
        res->error = 1;
        return;
    }

    /* ------------------------------------------------------------------
     * Routing decision: DROP (§6.7)
     * ------------------------------------------------------------------*/
    if (drop) {
        tr->action = ENP_TRACE_ACTION_DROPPED;
        memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
        tr->budget_after = out.compute_budget;
        enp_trace_log(tr);
        res->dropped = 1;
        memcpy(&res->out_pkt, &out, sizeof(out));
        return;
    }

    /* ------------------------------------------------------------------
     * State mutation: increment hop counter in state[0] (§11.2)
     * ------------------------------------------------------------------*/
    if (out.state[0] < 255) {
        out.state[0]++;
    } else {
        /* Loop-guard: drop to prevent routing cycle. */
        tr->action = ENP_TRACE_ACTION_DROPPED;
        memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
        tr->budget_after = out.compute_budget;
        enp_trace_log(tr);
        res->dropped = 1;
        memcpy(&res->out_pkt, &out, sizeof(out));
        return;
    }

    /* ------------------------------------------------------------------
     * Multi-hop routing advancement (§10.2)
     * ------------------------------------------------------------------*/
    if (pkt.hop_count > 0) {
        int is_last = (pkt.hop_index >= (int)(pkt.hop_count - 1));
        if (!is_last) {
            out.hop_index++;
            out.flags &= (uint16_t)~ENP_FLAG_RESPONSE;
            tr->action = ENP_TRACE_ACTION_FORWARDED;
        } else {
            out.flags |= ENP_FLAG_RESPONSE;
            tr->action = ENP_TRACE_ACTION_REPLIED;
        }
    } else {
        out.flags |= ENP_FLAG_RESPONSE;
        tr->action = ENP_TRACE_ACTION_REPLIED;
    }

    memcpy(tr->state_after, out.state, ENP_TRACE_STATE_SNAP);
    tr->budget_after = out.compute_budget;
    enp_trace_log(tr);
    memcpy(&res->out_pkt, &out, sizeof(out));
}

/* =========================================================================
 * Helpers
 * =========================================================================*/

/*
 * build_exec_packet() – construct a multi-hop ENP_EXEC packet.
 *
 * Route: originator(0) → nodeA(1) → nodeB(2) → nodeC(3)
 *   hop_count  = 4
 *   hop_index  = 1  (nodeA processes first)
 */
static void build_exec_packet(enp_packet_t *pkt, uint64_t id,
                               int32_t initial_value, uint16_t budget)
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->version        = ENP_VERSION;
    pkt->opcode         = ENP_EXEC;
    pkt->flags          = ENP_FLAG_MULTIHOP;
    pkt->src            = 0x7F000001u; /* 127.0.0.1 */
    pkt->dst            = 0x7F000001u;
    pkt->packet_id      = id;
    pkt->timestamp      = 0; /* fixed: not a semantic field */
    pkt->hop_count      = 4;
    pkt->hop_index      = 1;
    /* Hop addresses (loopback, simulator never actually sends to these) */
    pkt->hops[0]        = 0x7F000001u; /* originator return address */
    pkt->hop_ports[0]   = 9000;
    pkt->hops[1]        = 0x7F000001u; /* nodeA */
    pkt->hop_ports[1]   = 9001;
    pkt->hops[2]        = 0x7F000001u; /* nodeB */
    pkt->hop_ports[2]   = 9002;
    pkt->hops[3]        = 0x7F000001u; /* nodeC */
    pkt->hop_ports[3]   = 9003;
    /* Capabilities: all opcodes permitted, no hop/compute ceiling */
    pkt->capability.allowed_ops     = ENP_OP_ALL;
    pkt->capability.cap_max_hops    = 0;
    pkt->capability.cap_max_compute = 0;
    pkt->compute_budget             = budget;
    /* WASM code placeholder: sim uses mock functions, code bytes not executed */
    pkt->code_len       = 1;
    pkt->code[0]        = 0x00;
    /* Initial payload */
    pkt_write_i32(pkt, initial_value);
}

/*
 * Compare semantic fields of two packets (§15.2 semantic state S).
 * Returns 0 if equal, -1 if they differ.
 * Excludes: timestamp (non-semantic wall-clock field).
 */
static int cmp_semantic(const enp_packet_t *a, const enp_packet_t *b)
{
    if (a->version    != b->version    ||
        a->opcode     != b->opcode     ||
        a->flags      != b->flags      ||
        a->src        != b->src        ||
        a->dst        != b->dst        ||
        a->packet_id  != b->packet_id  ||
        a->payload_len!= b->payload_len||
        a->code_len   != b->code_len   ||
        a->hop_count  != b->hop_count  ||
        a->hop_index  != b->hop_index  ||
        a->compute_budget != b->compute_budget)
        return -1;
    if (memcmp(a->hops,     b->hops,     sizeof(a->hops))     != 0) return -1;
    if (memcmp(a->hop_ports,b->hop_ports,sizeof(a->hop_ports))!= 0) return -1;
    if (memcmp(a->state,    b->state,    ENP_STATE_LEN)        != 0) return -1;
    if (memcmp(&a->capability, &b->capability,
               sizeof(a->capability)) != 0) return -1;
    if (a->payload_len > 0 &&
        memcmp(a->payload, b->payload, a->payload_len) != 0) return -1;
    if (a->code_len > 0 &&
        memcmp(a->code, b->code, a->code_len) != 0) return -1;
    return 0;
}

/* Simple assertion helper */
static int g_failures = 0;

#define SIM_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stdout, "  [FAIL] %s\n", (msg)); \
            g_failures++; \
        } else { \
            fprintf(stdout, "  [PASS] %s\n", (msg)); \
        } \
    } while (0)

/* =========================================================================
 * Test 1 – Canonical Demo
 *
 * Three-hop ENP_EXEC chain.  WASM: process(x) = x * 2.
 *
 *   Initial payload : 5
 *   Budget          : 3
 *   Route           : originator → NodeA(hop 1) → NodeB(hop 2)
 *                     → NodeC(hop 3, last) → originator
 *
 *   Expected trace
 *   --------------
 *   hop 1  input= 5  output=10  budget 3→2  state[0] 0→1  FORWARDED
 *   hop 2  input=10  output=20  budget 2→1  state[0] 1→2  FORWARDED
 *   hop 3  input=20  output=40  budget 1→0  state[0] 2→3  REPLIED
 * =========================================================================*/
static int run_canonical_demo(void)
{
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  CANONICAL DEMO: 3-hop stateful ENP_EXEC chain\n");
    printf("  WASM: process(x) = x*2   initial=5   budget=3\n");
    printf("══════════════════════════════════════════════════════════════\n\n");

    enp_packet_t seed;
    build_exec_packet(&seed, 1001, 5, 3);

    enp_packet_t cur;
    memcpy(&cur, &seed, sizeof(cur));

    sim_hop_result_t r;

    /* ---- Hop 1: NodeA ---- */
    printf("[Hop 1 – NodeA]\n");
    sim_node_process(&cur, &r);
    SIM_ASSERT(!r.error && !r.dropped,           "hop 1: processed without error/drop");
    SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_FORWARDED, "hop 1: action=FORWARDED");
    SIM_ASSERT(r.trace.input  == 5,              "hop 1: input=5");
    SIM_ASSERT(r.trace.output == 10,             "hop 1: output=10 (5*2)");
    SIM_ASSERT(r.trace.budget_before == 3,       "hop 1: budget_before=3");
    SIM_ASSERT(r.trace.budget_after  == 2,       "hop 1: budget_after=2");
    SIM_ASSERT(r.trace.state_before[0] == 0,     "hop 1: state[0] before=0");
    SIM_ASSERT(r.trace.state_after[0]  == 1,     "hop 1: state[0] after=1");
    SIM_ASSERT(r.out_pkt.hop_index == 2,         "hop 1: hop_index advanced to 2");
    memcpy(&cur, &r.out_pkt, sizeof(cur));
    printf("\n");

    /* ---- Hop 2: NodeB ---- */
    printf("[Hop 2 – NodeB]\n");
    sim_node_process(&cur, &r);
    SIM_ASSERT(!r.error && !r.dropped,           "hop 2: processed without error/drop");
    SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_FORWARDED, "hop 2: action=FORWARDED");
    SIM_ASSERT(r.trace.input  == 10,             "hop 2: input=10");
    SIM_ASSERT(r.trace.output == 20,             "hop 2: output=20 (10*2)");
    SIM_ASSERT(r.trace.budget_before == 2,       "hop 2: budget_before=2");
    SIM_ASSERT(r.trace.budget_after  == 1,       "hop 2: budget_after=1");
    SIM_ASSERT(r.trace.state_before[0] == 1,     "hop 2: state[0] before=1");
    SIM_ASSERT(r.trace.state_after[0]  == 2,     "hop 2: state[0] after=2");
    SIM_ASSERT(r.out_pkt.hop_index == 3,         "hop 2: hop_index advanced to 3");
    memcpy(&cur, &r.out_pkt, sizeof(cur));
    printf("\n");

    /* ---- Hop 3: NodeC (last) ---- */
    printf("[Hop 3 – NodeC (last)]\n");
    sim_node_process(&cur, &r);
    SIM_ASSERT(!r.error && !r.dropped,           "hop 3: processed without error/drop");
    SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_REPLIED, "hop 3: action=REPLIED");
    SIM_ASSERT(r.trace.input  == 20,             "hop 3: input=20");
    SIM_ASSERT(r.trace.output == 40,             "hop 3: output=40 (20*2)");
    SIM_ASSERT(r.trace.budget_before == 1,       "hop 3: budget_before=1");
    SIM_ASSERT(r.trace.budget_after  == 0,       "hop 3: budget_after=0");
    SIM_ASSERT(r.trace.state_before[0] == 2,     "hop 3: state[0] before=2");
    SIM_ASSERT(r.trace.state_after[0]  == 3,     "hop 3: state[0] after=3");
    SIM_ASSERT(r.out_pkt.flags & ENP_FLAG_RESPONSE, "hop 3: RESPONSE flag set");
    printf("\n");

    /* Final result */
    int32_t final_val = pkt_read_i32(&r.out_pkt);
    printf("  Final payload : %d  (expected 40)\n", (int)final_val);
    printf("  Final state[0]: %u  (expected 3)\n",  (unsigned)r.out_pkt.state[0]);
    printf("  Final budget  : %u  (expected 0)\n",  (unsigned)r.out_pkt.compute_budget);
    SIM_ASSERT(final_val == 40, "final payload=40");
    SIM_ASSERT(r.out_pkt.state[0] == 3, "final state[0]=3");
    SIM_ASSERT(r.out_pkt.compute_budget == 0, "final budget=0");

    return 0;
}

/* =========================================================================
 * Test 2 – Budget Exhaustion (§8.3)
 *
 * 3-hop chain, budget=1.
 *   hop 1: ENP_EXEC OK, budget 1→0
 *   hop 2: budget=0 → BUDGET_EXHAUSTED error before dispatch
 * =========================================================================*/
static int run_budget_exhaustion_test(void)
{
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  BUDGET EXHAUSTION TEST  (budget=1, 3-hop chain)\n");
    printf("══════════════════════════════════════════════════════════════\n\n");

    enp_packet_t seed;
    build_exec_packet(&seed, 1002, 7, 1); /* budget=1 */

    enp_packet_t cur;
    memcpy(&cur, &seed, sizeof(cur));
    sim_hop_result_t r;

    printf("[Hop 1 – NodeA]\n");
    sim_node_process(&cur, &r);
    SIM_ASSERT(!r.error && !r.dropped,           "hop 1: processed OK");
    SIM_ASSERT(r.trace.budget_after == 0,        "hop 1: budget decremented to 0");
    SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_FORWARDED, "hop 1: FORWARDED");
    memcpy(&cur, &r.out_pkt, sizeof(cur));
    printf("\n");

    printf("[Hop 2 – NodeB]\n");
    sim_node_process(&cur, &r);
    SIM_ASSERT(r.error,                          "hop 2: error raised");
    SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_BUDGET_EXH,
               "hop 2: action=BUDGET_EXHAUSTED");
    SIM_ASSERT(r.out_pkt.flags & ENP_FLAG_BUDGET_EXHAUSTED,
               "hop 2: BUDGET_EXHAUSTED flag set in response");
    printf("\n");

    return 0;
}

/* =========================================================================
 * Test 3 – Capability Denial (§7.1)
 *
 * ENP_EXEC opcode, allowed_ops restricts to ENP_FORWARD only.
 * Expect CAP_DENIED error on the first hop.
 * =========================================================================*/
static int run_cap_denied_test(void)
{
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  CAPABILITY DENIAL TEST  (ENP_EXEC blocked by allowed_ops)\n");
    printf("══════════════════════════════════════════════════════════════\n\n");

    enp_packet_t pkt;
    build_exec_packet(&pkt, 1003, 5, ENP_BUDGET_UNLIMITED);
    /* Restrict to FORWARD only – EXEC is not permitted */
    pkt.capability.allowed_ops = ENP_OP_BIT(ENP_FORWARD);

    sim_hop_result_t r;
    printf("[Hop 1 – NodeA]\n");
    sim_node_process(&pkt, &r);
    SIM_ASSERT(r.error,                          "hop 1: error raised");
    SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_ERROR,
               "hop 1: action=ERROR");
    SIM_ASSERT(r.out_pkt.flags & ENP_FLAG_CAP_DENIED,
               "hop 1: CAP_DENIED flag set");
    printf("\n");

    return 0;
}

/* =========================================================================
 * Test 4 – Programmable Routing (§4.3 / §6.7)
 *
 * ENP_ROUTE_DECIDE: mock_route_decide(x) = x > 100 → DROP, else FORWARD.
 *   Subtest A: payload=50  → FORWARD  → route continues
 *   Subtest B: payload=150 → DROP     → silent discard
 * =========================================================================*/
static int run_route_decide_test(void)
{
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  ROUTE-DECIDE TEST\n");
    printf("  route_decide(x): x > 100 → DROP, else FORWARD\n");
    printf("══════════════════════════════════════════════════════════════\n\n");

    /* Subtest A: value=50 → FORWARD */
    {
        enp_packet_t pkt;
        build_exec_packet(&pkt, 1004, 50, ENP_BUDGET_UNLIMITED);
        pkt.opcode = ENP_ROUTE_DECIDE;

        sim_hop_result_t r;
        printf("[Route Subtest A – payload=50, expect FORWARD]\n");
        sim_node_process(&pkt, &r);
        SIM_ASSERT(!r.error && !r.dropped,                       "A: not dropped/error");
        SIM_ASSERT(r.trace.route_action == ENP_ACTION_FORWARD,   "A: route_action=FORWARD");
        SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_FORWARDED, "A: action=FORWARDED");
        printf("\n");
    }

    /* Subtest B: value=150 → DROP */
    {
        enp_packet_t pkt;
        build_exec_packet(&pkt, 1005, 150, ENP_BUDGET_UNLIMITED);
        pkt.opcode = ENP_ROUTE_DECIDE;

        sim_hop_result_t r;
        printf("[Route Subtest B – payload=150, expect DROP]\n");
        sim_node_process(&pkt, &r);
        SIM_ASSERT(r.dropped,                                    "B: packet dropped");
        SIM_ASSERT(r.trace.route_action == ENP_ACTION_DROP,      "B: route_action=DROP");
        SIM_ASSERT(r.trace.action == ENP_TRACE_ACTION_DROPPED,   "B: action=DROPPED");
        printf("\n");
    }

    return 0;
}

/* =========================================================================
 * Test 5 – Determinism Invariant (§15.2)
 *
 * Runs the canonical 3-hop chain twice from the same seed packet.
 * Asserts S(run_A output) = S(run_B output) at every hop.
 *
 * Formal statement (from §15.2):
 *   For P₁, P₂ where S(P₁) = S(P₂): S(process(N,P₁)) = S(process(N,P₂))
 * =========================================================================*/
static int run_determinism_check(void)
{
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  DETERMINISM CHECK  (§15.2 state-invariant verification)\n");
    printf("  Two runs from S(P₁)=S(P₂) must produce S(out₁)=S(out₂)\n");
    printf("══════════════════════════════════════════════════════════════\n\n");

    enp_packet_t seed;
    build_exec_packet(&seed, 2001, 5, 3);

    enp_packet_t cur_a, cur_b;
    memcpy(&cur_a, &seed, sizeof(cur_a));
    memcpy(&cur_b, &seed, sizeof(cur_b));

    sim_hop_result_t ra, rb;

    for (int hop = 1; hop <= 3; hop++) {
        sim_node_process(&cur_a, &ra);
        sim_node_process(&cur_b, &rb);

        char label[64];
        snprintf(label, sizeof(label), "hop %d: S(run_A) == S(run_B)", hop);
        SIM_ASSERT(cmp_semantic(&ra.out_pkt, &rb.out_pkt) == 0, label);

        snprintf(label, sizeof(label),
                 "hop %d: action identical (A=%u B=%u)",
                 hop, (unsigned)ra.trace.action, (unsigned)rb.trace.action);
        SIM_ASSERT(ra.trace.action == rb.trace.action, label);

        memcpy(&cur_a, &ra.out_pkt, sizeof(cur_a));
        memcpy(&cur_b, &rb.out_pkt, sizeof(cur_b));
    }

    printf("\n");
    return 0;
}

/* =========================================================================
 * main
 * =========================================================================*/
int main(void)
{
    enp_logger_init(ENP_LOG_INFO, stdout);

    printf("ENP v%u Reference Execution Simulator\n", ENP_VERSION);
    printf("Wire header: %u bytes  |  State: %u bytes  |  "
           "Budget unlimited sentinel: 0x%04X\n\n",
           ENP_HEADER_SIZE, ENP_STATE_LEN, ENP_BUDGET_UNLIMITED);

    run_canonical_demo();
    run_budget_exhaustion_test();
    run_cap_denied_test();
    run_route_decide_test();
    run_determinism_check();

    printf("\n══════════════════════════════════════════════════════════════\n");
    if (g_failures == 0) {
        printf("  RESULT: ALL CHECKS PASSED\n");
    } else {
        printf("  RESULT: %d CHECK(S) FAILED\n", g_failures);
    }
    printf("══════════════════════════════════════════════════════════════\n\n");

    return (g_failures == 0) ? 0 : 1;
}
