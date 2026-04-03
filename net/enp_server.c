/*
 * enp_server.c - ENP UDP Server (Node) Implementation
 *
 * Listens for incoming ENP packets, validates them, and routes based on opcode:
 *   ENP_FORWARD      -> echoes packet back to sender
 *   ENP_EXEC         -> executes embedded WASM and returns result
 *   ENP_ROUTE_DECIDE -> WASM route_decide() determines action (forward/drop)
 *
 * Multi-hop routing:
 *   When hop_count > 0, after processing the packet is forwarded to the
 *   next node in hops[], or the response is returned to hops[0]:hop_ports[0]
 *   (the original client's return address) when the last node is reached.
 *
 * Capability enforcement (v3):
 *   If allowed_ops != 0 and the packet's opcode is not in the mask, the
 *   node sets ENP_FLAG_CAP_DENIED and returns an error response.
 *
 * Execution budgeting (v3):
 *   compute_budget == 0xFFFF  -> unlimited (never decremented).
 *   compute_budget == 0       -> exhausted; WASM ops are refused.
 *   compute_budget > 0        -> decremented by 1 per WASM execution.
 *
 * Observability (v3):
 *   Every handled packet produces an enp_trace_record_t logged via
 *   enp_trace_log() capturing timing, budget, state diff, and action.
 */

#define _POSIX_C_SOURCE 200112L

#include "enp_net.h"
#include "enp_packet.h"
#include "enp_wasm.h"
#include "enp_trace.h"
#include "enp_logger.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef int socklen_t;
#  define CLOSE_SOCKET(s) closesocket(s)
#  define SOCK_ERR        WSAGetLastError()
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <errno.h>
   typedef int SOCKET;
#  define INVALID_SOCKET  (-1)
#  define SOCKET_ERROR    (-1)
#  define CLOSE_SOCKET(s) close(s)
#  define SOCK_ERR        errno
#endif

/* Maximum UDP datagram size we accept */
#define ENP_UDP_BUFSIZE ENP_MAX_PACKET_SIZE

/* -------------------------------------------------------------------------
 * Internal: send a serialized packet to a specific IPv4 address / port
 * (fire-and-forget; uses a temporary socket so we don't block the server).
 * -------------------------------------------------------------------------*/
static void send_to_addr(const enp_packet_t *pkt, uint32_t ip_host, uint16_t port)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        ENP_LOG_ERR("forward: socket() failed: %d", SOCK_ERR);
        return;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(port);
    dst.sin_addr.s_addr = htonl(ip_host);

    uint8_t buf[ENP_MAX_PACKET_SIZE];
    int len = enp_packet_serialize(pkt, buf, sizeof(buf));
    if (len < 0) {
        ENP_LOG_ERR("forward: serialize failed");
        CLOSE_SOCKET(s);
        return;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst.sin_addr, ip_str, sizeof(ip_str));
    ENP_LOG_INFO("Sending %d bytes to %s:%u", len, ip_str, (unsigned)port);

    if (sendto(s, (const char *)buf, len, 0,
               (const struct sockaddr *)&dst, sizeof(dst)) == SOCKET_ERROR) {
        ENP_LOG_ERR("forward: sendto failed: %d", SOCK_ERR);
    }

    CLOSE_SOCKET(s);
}

/* -------------------------------------------------------------------------
 * Internal: extract payload i32 (big-endian, first 4 bytes)
 * -------------------------------------------------------------------------*/
static int32_t payload_to_i32(const enp_packet_t *pkt)
{
    if (pkt->payload_len >= 4) {
        return (int32_t)(
            ((uint32_t)pkt->payload[0] << 24) |
            ((uint32_t)pkt->payload[1] << 16) |
            ((uint32_t)pkt->payload[2] <<  8) |
             (uint32_t)pkt->payload[3]);
    }
    if (pkt->payload_len > 0)
        return (int32_t)pkt->payload[0];
    return 0;
}

/* -------------------------------------------------------------------------
 * Internal: write i32 into response payload (big-endian, 4 bytes)
 * -------------------------------------------------------------------------*/
static void i32_to_payload(enp_packet_t *pkt, int32_t v)
{
    pkt->payload_len = 4;
    pkt->payload[0]  = (uint8_t)((uint32_t)v >> 24);
    pkt->payload[1]  = (uint8_t)((uint32_t)v >> 16);
    pkt->payload[2]  = (uint8_t)((uint32_t)v >>  8);
    pkt->payload[3]  = (uint8_t)((uint32_t)v & 0xFF);
}

/* -------------------------------------------------------------------------
 * Internal: snap first ENP_TRACE_STATE_SNAP bytes of state into dst[]
 * -------------------------------------------------------------------------*/
static void snap_state(const enp_packet_t *pkt,
                       uint8_t dst[ENP_TRACE_STATE_SNAP])
{
    memcpy(dst, pkt->state, ENP_TRACE_STATE_SNAP);
}

/* -------------------------------------------------------------------------
 * Internal: send an error response (capability or budget failure)
 * -------------------------------------------------------------------------*/
static void send_error_response(SOCKET sock,
                                 enp_packet_t *out,
                                 const struct sockaddr_in *client_addr,
                                 socklen_t addr_len)
{
    out->flags |= ENP_FLAG_RESPONSE;
    uint8_t resp_buf[ENP_MAX_PACKET_SIZE];
    int resp_len = enp_packet_serialize(out, resp_buf, sizeof(resp_buf));
    if (resp_len > 0)
        sendto(sock, (const char *)resp_buf, resp_len, 0,
               (const struct sockaddr *)client_addr, addr_len);
}

/* -------------------------------------------------------------------------
 * Internal: handle a single incoming packet
 * -------------------------------------------------------------------------*/
static void handle_packet(SOCKET sock,
                           uint16_t srv_port,
                           const uint8_t *raw, size_t raw_len,
                           const struct sockaddr_in *client_addr,
                           socklen_t addr_len)
{
    enp_packet_t pkt;
    if (enp_packet_deserialize(raw, raw_len, &pkt) != 0) {
        ENP_LOG_WARN("Received malformed packet - discarding");
        return;
    }

    if (enp_packet_validate(&pkt) != 0) {
        ENP_LOG_WARN("Packet failed validation - discarding");
        return;
    }

    ENP_LOG_INFO("Received packet id=%llu src=0x%08X opcode=%u "
                 "hop=%u/%u payload_len=%u code_len=%u "
                 "state[0]=%u budget=%u allowed_ops=0x%08X",
                 (unsigned long long)pkt.packet_id,
                 pkt.src,
                 (unsigned)pkt.opcode,
                 (unsigned)pkt.hop_index,
                 (unsigned)pkt.hop_count,
                 pkt.payload_len, pkt.code_len,
                 (unsigned)pkt.state[0],
                 (unsigned)pkt.compute_budget,
                 (unsigned)pkt.capability.allowed_ops);

    /* Initialise trace record */
    enp_trace_record_t trace;
    memset(&trace, 0, sizeof(trace));
    trace.packet_id     = pkt.packet_id;
    trace.hop_index     = pkt.hop_index;
    trace.hop_count     = pkt.hop_count;
    trace.opcode        = pkt.opcode;
    trace.input         = payload_to_i32(&pkt);
    trace.budget_before = pkt.compute_budget;
    snap_state(&pkt, trace.state_before);

    /* Build working copy for response / forwarding */
    enp_packet_t out;
    memcpy(&out, &pkt, sizeof(out));
    out.timestamp = enp_timestamp_ms();

    /* ---- Capability: opcode check ---- */
    if (pkt.capability.allowed_ops != ENP_OP_ALL &&
            !(pkt.capability.allowed_ops & ENP_OP_BIT(pkt.opcode))) {
        ENP_LOG_WARN("Capability: opcode %u not permitted (allowed_ops=0x%08X) "
                     "- sending CAP_DENIED error",
                     (unsigned)pkt.opcode,
                     (unsigned)pkt.capability.allowed_ops);
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED;
        trace.action = ENP_TRACE_ACTION_ERROR;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        send_error_response(sock, &out, client_addr, addr_len);
        return;
    }

    /* ---- Capability: hop count ceiling check ---- */
    if (pkt.capability.cap_max_hops > 0 &&
            pkt.hop_count > pkt.capability.cap_max_hops) {
        ENP_LOG_WARN("Capability: hop_count %u > cap_max_hops %u - CAP_DENIED",
                     (unsigned)pkt.hop_count,
                     (unsigned)pkt.capability.cap_max_hops);
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED;
        trace.action = ENP_TRACE_ACTION_ERROR;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        send_error_response(sock, &out, client_addr, addr_len);
        return;
    }

    /* ---- Capability: budget ceiling check ----
     * Verify that the declared compute_budget does not exceed the cap. Since
     * budget only decreases at each hop, a packet that passes this check at
     * the first node will always pass it on subsequent nodes. */
    if (pkt.capability.cap_max_compute > 0 &&
            pkt.compute_budget != ENP_BUDGET_UNLIMITED &&
            pkt.compute_budget > pkt.capability.cap_max_compute) {
        ENP_LOG_WARN("Capability: compute_budget %u > cap_max_compute %u - CAP_DENIED",
                     (unsigned)pkt.compute_budget,
                     (unsigned)pkt.capability.cap_max_compute);
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_CAP_DENIED;
        trace.action = ENP_TRACE_ACTION_ERROR;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        send_error_response(sock, &out, client_addr, addr_len);
        return;
    }

    /* ---- Budget check: refuse WASM execution if budget is exhausted ---- */
    int needs_wasm = (pkt.opcode == ENP_EXEC || pkt.opcode == ENP_ROUTE_DECIDE);
    if (needs_wasm &&
            pkt.compute_budget != ENP_BUDGET_UNLIMITED &&
            pkt.compute_budget == 0) {
        ENP_LOG_WARN("Compute budget exhausted for packet id=%llu - refusing WASM",
                     (unsigned long long)pkt.packet_id);
        out.flags |= ENP_FLAG_ERROR | ENP_FLAG_BUDGET_EXHAUSTED;
        trace.action = ENP_TRACE_ACTION_BUDGET_EXH;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        send_error_response(sock, &out, client_addr, addr_len);
        return;
    }

    /* ---- Opcode dispatch ---- */
    int32_t input = payload_to_i32(&pkt);
    int drop = 0;   /* set to 1 if routing decision is DROP */

    switch (pkt.opcode) {

    case ENP_FORWARD:
        ENP_LOG_INFO("Opcode ENP_FORWARD: echoing packet");
        break;

    case ENP_EXEC: {
        ENP_LOG_INFO("Opcode ENP_EXEC: executing WASM (%u bytes) input=%d",
                     pkt.code_len, (int)input);
        int32_t output = 0;
        uint64_t t0 = enp_timestamp_us();
        enp_wasm_result_t wres = enp_wasm_exec(pkt.code, pkt.code_len,
                                                input, &output);
        uint64_t t1 = enp_timestamp_us();
        trace.exec_us = (t1 > t0) ? (uint32_t)(t1 - t0) : 0u;

        if (wres == ENP_WASM_OK) {
            ENP_LOG_INFO("WASM result: %d  (exec_us=%u)", (int)output,
                         (unsigned)trace.exec_us);
            i32_to_payload(&out, output);
            trace.output = output;
            /* Decrement budget (skip if unlimited) */
            if (out.compute_budget != ENP_BUDGET_UNLIMITED)
                out.compute_budget--;
        } else {
            ENP_LOG_ERR("WASM execution failed (result=%d)", (int)wres);
            out.flags |= ENP_FLAG_ERROR;
        }
        break;
    }

    case ENP_ROUTE_DECIDE: {
        ENP_LOG_INFO("Opcode ENP_ROUTE_DECIDE: executing route_decide WASM "
                     "(%u bytes) input=%d", pkt.code_len, (int)input);
        enp_route_decision_t decision;
        uint64_t t0 = enp_timestamp_us();
        enp_wasm_result_t wres = enp_wasm_exec_route(pkt.code, pkt.code_len,
                                                      input, &decision);
        uint64_t t1 = enp_timestamp_us();
        trace.exec_us = (t1 > t0) ? (uint32_t)(t1 - t0) : 0u;

        if (wres == ENP_WASM_OK) {
            ENP_LOG_INFO("Route decision: action=%u  (exec_us=%u)",
                         (unsigned)decision.action, (unsigned)trace.exec_us);
            trace.route_action = decision.action;
            if (decision.action == ENP_ACTION_DROP) {
                ENP_LOG_INFO("Routing decision: DROP - discarding packet");
                drop = 1;
            }
            /* ENP_ACTION_CLONE treated same as FORWARD in this prototype */
            /* Decrement budget (skip if unlimited) */
            if (out.compute_budget != ENP_BUDGET_UNLIMITED)
                out.compute_budget--;
        } else {
            ENP_LOG_ERR("route_decide WASM failed - defaulting to FORWARD");
        }
        break;
    }

    default:
        ENP_LOG_ERR("Unexpected opcode %u", (unsigned)pkt.opcode);
        return;
    }

    if (drop) {
        trace.action = ENP_TRACE_ACTION_DROPPED;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        return;
    }

    /* ---- State mutation: increment hop counter ---- */
    if (out.state[0] < 255) {
        out.state[0]++;
    } else {
        ENP_LOG_WARN("state[0] hop-counter overflow at 255 – dropping packet to prevent loop");
        trace.action = ENP_TRACE_ACTION_DROPPED;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        return;
    }
    ENP_LOG_DBG("State: hop_counter=%u", (unsigned)out.state[0]);

    /* ---- Multi-hop routing ---- */
    if (pkt.hop_count > 0) {
        int is_last = (pkt.hop_index >= pkt.hop_count - 1);

        if (!is_last) {
            /* Advance to next processing node and forward */
            out.hop_index++;
            out.flags &= (uint16_t)~ENP_FLAG_RESPONSE;
            ENP_LOG_INFO("Multi-hop: forwarding to hop %u/%u  [%08X:%u]",
                         (unsigned)out.hop_index,
                         (unsigned)out.hop_count,
                         out.hops[out.hop_index],
                         (unsigned)out.hop_ports[out.hop_index]);
            trace.action = ENP_TRACE_ACTION_FORWARDED;
            snap_state(&out, trace.state_after);
            trace.budget_after = out.compute_budget;
            enp_trace_log(&trace);
            send_to_addr(&out, out.hops[out.hop_index], out.hop_ports[out.hop_index]);
            return;
        }

        /* Last node: return to the originator (hops[0]:hop_ports[0]) */
        out.flags |= ENP_FLAG_RESPONSE;
        uint32_t ret_ip   = out.hops[0];
        uint16_t ret_port = out.hop_ports[0];
        ENP_LOG_INFO("Multi-hop: last node - returning to originator [%08X:%u]",
                     ret_ip, (unsigned)ret_port);
        trace.action = ENP_TRACE_ACTION_REPLIED;
        snap_state(&out, trace.state_after);
        trace.budget_after = out.compute_budget;
        enp_trace_log(&trace);
        send_to_addr(&out, ret_ip, ret_port);
        return;
    }

    /* ---- Single-hop: reply to the immediate sender ---- */
    out.flags |= ENP_FLAG_RESPONSE;
    uint8_t resp_buf[ENP_MAX_PACKET_SIZE];
    int resp_len = enp_packet_serialize(&out, resp_buf, sizeof(resp_buf));
    if (resp_len < 0) {
        ENP_LOG_ERR("Failed to serialize response packet");
        return;
    }

    trace.action = ENP_TRACE_ACTION_REPLIED;
    snap_state(&out, trace.state_after);
    trace.budget_after = out.compute_budget;
    enp_trace_log(&trace);

    int sent = (int)sendto(sock, (const char *)resp_buf, resp_len, 0,
                           (const struct sockaddr *)client_addr, addr_len);
    if (sent == SOCKET_ERROR) {
        ENP_LOG_ERR("sendto failed: %d", SOCK_ERR);
    } else {
        ENP_LOG_INFO("Response sent (%d bytes)", sent);
    }
    (void)srv_port;
}

/* -------------------------------------------------------------------------
 * Public: enp_server_run
 * -------------------------------------------------------------------------*/
int enp_server_run(uint16_t port)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        ENP_LOG_ERR("WSAStartup failed");
        return -1;
    }
#endif

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        ENP_LOG_ERR("socket() failed: %d", SOCK_ERR);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        ENP_LOG_ERR("bind() failed: %d", SOCK_ERR);
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    ENP_LOG_INFO("ENP node listening on port %u", (unsigned)port);

    uint8_t buf[ENP_UDP_BUFSIZE];

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int n = (int)recvfrom(sock, (char *)buf, sizeof(buf), 0,
                              (struct sockaddr *)&client_addr, &addr_len);
        if (n == SOCKET_ERROR) {
            ENP_LOG_ERR("recvfrom() failed: %d", SOCK_ERR);
            break;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        ENP_LOG_DBG("Received %d bytes from %s:%u",
                    n, client_ip, ntohs(client_addr.sin_port));

        handle_packet(sock, port, buf, (size_t)n, &client_addr, addr_len);
    }

    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
