/*
 * enp_trace.h - ENP Observability / Execution Trace API
 *
 * Each ENP node records a structured trace record for every packet it
 * processes, capturing:
 *   - packet identity (id, hop position)
 *   - opcode and input / output values
 *   - WASM execution time in microseconds
 *   - compute budget before and after this hop
 *   - routing action taken
 *   - first 8 bytes of the state buffer before and after processing
 *     (state diff)
 *
 * Traces are emitted to the log immediately after a packet is handled,
 * making the node's behaviour fully debuggable.
 */

#ifndef ENP_TRACE_H
#define ENP_TRACE_H

#include <stdint.h>

/* Number of state bytes captured in the trace (for the state diff) */
#define ENP_TRACE_STATE_SNAP 8

/* Actions recorded in a trace record */
typedef enum {
    ENP_TRACE_ACTION_REPLIED    = 0, /* Node sent a reply to the caller      */
    ENP_TRACE_ACTION_FORWARDED  = 1, /* Packet forwarded to next hop         */
    ENP_TRACE_ACTION_DROPPED    = 2, /* Packet silently dropped (route/cap)  */
    ENP_TRACE_ACTION_ERROR      = 3, /* Error set; response sent             */
    ENP_TRACE_ACTION_BUDGET_EXH = 4  /* Compute budget exhausted             */
} enp_trace_action_t;

/*
 * A single per-hop trace record.
 *
 * Fields:
 *   packet_id       64-bit identifier from the packet header.
 *   hop_index       Which hop position this node occupied.
 *   hop_count       Total hops declared in the packet.
 *   opcode          Opcode that was dispatched.
 *   input           i32 value extracted from the payload.
 *   output          i32 result after WASM process() (0 for non-EXEC ops).
 *   route_action    Routing decision from route_decide() (0 if not applicable).
 *   exec_us         WASM execution duration in microseconds (0 = no WASM ran).
 *   budget_before   compute_budget on entry to this hop.
 *   budget_after    compute_budget after this hop.
 *   action          Final action taken by this node (see enp_trace_action_t).
 *   state_before[]  Snapshot of state[0..ENP_TRACE_STATE_SNAP-1] on entry.
 *   state_after[]   Snapshot of state[0..ENP_TRACE_STATE_SNAP-1] on exit.
 */
typedef struct {
    uint64_t  packet_id;
    uint8_t   hop_index;
    uint8_t   hop_count;
    uint8_t   opcode;
    int32_t   input;
    int32_t   output;
    uint8_t   route_action;
    uint32_t  exec_us;
    uint16_t  budget_before;
    uint16_t  budget_after;
    uint8_t   action;                              /* enp_trace_action_t */
    uint8_t   state_before[ENP_TRACE_STATE_SNAP];
    uint8_t   state_after[ENP_TRACE_STATE_SNAP];
} enp_trace_record_t;

/*
 * Emit a trace record to the log.
 *
 * Formats the record as a structured, human-readable log line at INFO level.
 * The output is suitable for grepping, parsing, or forwarding to an
 * observability backend.
 *
 * @param rec  Pointer to the completed trace record.
 */
void enp_trace_log(const enp_trace_record_t *rec);

#endif /* ENP_TRACE_H */
