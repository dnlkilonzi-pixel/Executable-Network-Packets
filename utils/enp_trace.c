/*
 * enp_trace.c - ENP Observability / Execution Trace Implementation
 *
 * Formats and emits structured per-hop trace records to the ENP logger.
 */

#include "enp_trace.h"
#include "enp_logger.h"

#include <stdio.h>
#include <string.h>

static const char *action_str(uint8_t action)
{
    switch (action) {
    case ENP_TRACE_ACTION_REPLIED:    return "REPLIED";
    case ENP_TRACE_ACTION_FORWARDED:  return "FORWARDED";
    case ENP_TRACE_ACTION_DROPPED:    return "DROPPED";
    case ENP_TRACE_ACTION_ERROR:      return "ERROR";
    case ENP_TRACE_ACTION_BUDGET_EXH: return "BUDGET_EXHAUSTED";
    default:                          return "UNKNOWN";
    }
}

static const char *opcode_str(uint8_t opcode)
{
    switch (opcode) {
    case 0: return "FORWARD";
    case 1: return "EXEC";
    case 2: return "ROUTE_DECIDE";
    default: return "?";
    }
}

/* Format state snapshot as a compact hex string "xx xx xx ..." */
static void fmt_state(const uint8_t *snap, char *out, size_t out_sz)
{
    size_t pos = 0;
    for (int i = 0; i < ENP_TRACE_STATE_SNAP && pos + 4 <= out_sz; i++) {
        int n = snprintf(out + pos, out_sz - pos, "%02x", (unsigned)snap[i]);
        if (n < 0)
            break;
        pos += (size_t)n;
        if (i + 1 < ENP_TRACE_STATE_SNAP && pos + 1 < out_sz)
            out[pos++] = ' ';
    }
    out[pos] = '\0';
}

void enp_trace_log(const enp_trace_record_t *rec)
{
    if (!rec)
        return;

    /* Format state snapshots */
    char sb[ENP_TRACE_STATE_SNAP * 3 + 1];
    char sa[ENP_TRACE_STATE_SNAP * 3 + 1];
    fmt_state(rec->state_before, sb, sizeof(sb));
    fmt_state(rec->state_after,  sa, sizeof(sa));

    /* Budget display: 0xFFFF is shown as "unlimited" */
    char budget_before_str[16], budget_after_str[16];
    if (rec->budget_before == 0xFFFFu)
        snprintf(budget_before_str, sizeof(budget_before_str), "unlimited");
    else
        snprintf(budget_before_str, sizeof(budget_before_str), "%u", (unsigned)rec->budget_before);

    if (rec->budget_after == 0xFFFFu)
        snprintf(budget_after_str, sizeof(budget_after_str), "unlimited");
    else
        snprintf(budget_after_str, sizeof(budget_after_str), "%u", (unsigned)rec->budget_after);

    ENP_LOG_INFO(
        "TRACE pkt=%llu hop=%u/%u op=%s input=%d output=%d "
        "route_action=%u exec_us=%u budget=%s→%s "
        "action=%s state=[%s]→[%s]",
        (unsigned long long)rec->packet_id,
        (unsigned)rec->hop_index,
        (unsigned)rec->hop_count,
        opcode_str(rec->opcode),
        (int)rec->input,
        (int)rec->output,
        (unsigned)rec->route_action,
        (unsigned)rec->exec_us,
        budget_before_str,
        budget_after_str,
        action_str(rec->action),
        sb,
        sa
    );
}
