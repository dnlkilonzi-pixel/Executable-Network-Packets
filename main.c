/*
 * main.c - ENP Entry Point
 *
 * Usage:
 *   enp server [port]
 *       Start an ENP node server (default port 9000).
 *
 *   enp client <host> [port]
 *       Send a single-hop ENP_EXEC packet: process(5) → 10.
 *
 *   enp route <host> [port]
 *       Send a single-hop ENP_ROUTE_DECIDE packet.
 *       Demonstrates programmable routing: WASM decides FORWARD / DROP.
 *
 *   enp multihop <hostA> <portA> <hostB> <portB>
 *       Send an ENP_EXEC packet through a two-node chain.
 *       Each node doubles the value: 3 → 6 (Node A) → 12 (Node B).
 *       Requires two server instances already running on portA and portB.
 *
 * Demo WASM modules (hand-assembled bytecode):
 *   PROCESS_WASM    – int process(int x)      { return x * 2; }   (44 bytes)
 *   ROUTE_WASM      – int route_decide(int x) { return x > 100 ? DROP : FORWARD; }
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif

#include "enp_packet.h"
#include "enp_net.h"
#include "enp_logger.h"

/* -------------------------------------------------------------------------
 * Pre-compiled WASM: int process(int x) { return x * 2; }
 * Signature: (func (param i32) (result i32))
 * Export name: "process"
 * -------------------------------------------------------------------------*/
static const uint8_t PROCESS_WASM[] = {
    /* magic + version */
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    /* type section: (func (param i32) (result i32)) */
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    /* function section: 1 function, type index 0 */
    0x03, 0x02, 0x01, 0x00,
    /* export section: "process" -> func 0 */
    0x07, 0x0b, 0x01, 0x07,
    0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73,  /* "process" */
    0x00, 0x00,
    /* code section: local.get 0, i32.const 2, i32.mul, end */
    0x0a, 0x09, 0x01, 0x07, 0x00,
    0x20, 0x00,  /* local.get 0  */
    0x41, 0x02,  /* i32.const 2  */
    0x6c,        /* i32.mul      */
    0x0b         /* end          */
};

/* -------------------------------------------------------------------------
 * Pre-compiled WASM: int route_decide(int x) { return x > 63 ? 1 : 0; }
 *   Returns 0 (ENP_ACTION_FORWARD) when x <= 63
 *   Returns 1 (ENP_ACTION_DROP)    when x > 63
 * Signature: (func (param i32) (result i32))
 * Export name: "route_decide"
 *
 * WAT equivalent:
 *   (func (param $x i32) (result i32)
 *     (i32.gt_s (local.get $x) (i32.const 63)))
 *
 * NOTE: positive WASM i32.const values > 63 require two-byte signed LEB128
 * encoding (0x3f = 63 fits safely in a single signed-LEB128 byte).
 *
 * Hand-assembled (49 bytes):
 *   code body: locals=0, local.get 0, i32.const 63, i32.gt_s, end
 * -------------------------------------------------------------------------*/
static const uint8_t ROUTE_WASM[] = {
    /* magic + version */
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    /* type section: (func (param i32) (result i32)) */
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    /* function section: 1 function, type index 0 */
    0x03, 0x02, 0x01, 0x00,
    /* export section: "route_decide" -> func 0  (section size = 16) */
    0x07, 0x10, 0x01, 0x0c,
    0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x64, 0x65,  /* "route_de" */
    0x63, 0x69, 0x64, 0x65,                            /* "cide"     */
    0x00, 0x00,
    /* code section: local.get 0, i32.const 63, i32.gt_s, end
     * body (7 bytes): 00(locals) 20 00(local.get 0) 41 3f(i32.const 63) 4a(gt_s) 0b(end)
     * section content = 01(count) 07(body_size) + 7 bytes = 9 bytes, section size = 0x09 */
    0x0a, 0x09, 0x01, 0x07, 0x00,
    0x20, 0x00,   /* local.get 0    */
    0x41, 0x3f,   /* i32.const 63   */
    0x4a,         /* i32.gt_s       */
    0x0b          /* end            */
};

/* -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------*/
static int32_t decode_i32_payload(const enp_packet_t *pkt)
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

static void encode_i32_payload(enp_packet_t *pkt, int32_t v)
{
    pkt->payload_len = 4;
    pkt->payload[0]  = (uint8_t)((uint32_t)v >> 24);
    pkt->payload[1]  = (uint8_t)((uint32_t)v >> 16);
    pkt->payload[2]  = (uint8_t)((uint32_t)v >>  8);
    pkt->payload[3]  = (uint8_t)((uint32_t)v & 0xFF);
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s server [port]\n"
            "      Start ENP node (default port %u)\n\n"
            "  %s client <host> [port]\n"
            "      Single-hop ENP_EXEC demo: process(5) = 10\n\n"
            "  %s route <host> [port]\n"
            "      Single-hop ENP_ROUTE_DECIDE demo\n\n"
            "  %s multihop <hostA> <portA> <hostB> <portB>\n"
            "      Two-hop ENP_EXEC demo: 3 → 6 → 12\n"
            "      (Run two server instances first)\n",
            prog, ENP_DEFAULT_PORT, prog, prog, prog);
}

/* -------------------------------------------------------------------------
 * Demo: single-hop ENP_EXEC
 * -------------------------------------------------------------------------*/
static int run_client(const char *host, uint16_t port)
{
    enp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.version   = ENP_VERSION;
    pkt.opcode    = ENP_EXEC;
    pkt.src       = 0x7F000001u;
    pkt.dst       = 0x7F000001u;
    pkt.packet_id = 1;
    pkt.timestamp = enp_timestamp_ms();

    int32_t input_val = 5;
    encode_i32_payload(&pkt, input_val);

    if (sizeof(PROCESS_WASM) > ENP_CODE_MAX_LEN) {
        ENP_LOG_ERR("WASM module exceeds code_len limit");
        return -1;
    }
    pkt.code_len = (uint16_t)sizeof(PROCESS_WASM);
    memcpy(pkt.code, PROCESS_WASM, sizeof(PROCESS_WASM));

    ENP_LOG_INFO("Sending ENP_EXEC: process(%d) to %s:%u",
                 (int)input_val, host, (unsigned)port);

    enp_packet_t response;
    memset(&response, 0, sizeof(response));

    if (enp_client_send(host, port, &pkt, &response, 5) != 0) {
        ENP_LOG_ERR("Client failed to send/receive");
        return -1;
    }

    if (response.flags & ENP_FLAG_ERROR) {
        ENP_LOG_ERR("Server returned an error response");
        return -1;
    }

    int32_t result = decode_i32_payload(&response);
    ENP_LOG_INFO("Result: process(%d) = %d  (state[0]/hops=%u)",
                 (int)input_val, (int)result, (unsigned)response.state[0]);
    printf("ENP_EXEC result: process(%d) = %d\n", (int)input_val, (int)result);
    return 0;
}

/* -------------------------------------------------------------------------
 * Demo: single-hop ENP_ROUTE_DECIDE
 * Two packets are sent:
 *   1. payload = 50  → route_decide(50)  = 0 (FORWARD): server replies
 *   2. payload = 150 → route_decide(150) = 1 (DROP):    server discards
 * -------------------------------------------------------------------------*/
static int run_route(const char *host, uint16_t port)
{
    int ok = 0;
    static const int32_t test_vals[] = {50, 150};
    static const char   *expected[]  = {"FORWARD (50 <= 63, response expected)",
                                        "DROP    (150 > 63,  no response – expect timeout)"};

    for (int i = 0; i < 2; i++) {
        enp_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));

        pkt.version   = ENP_VERSION;
        pkt.opcode    = ENP_ROUTE_DECIDE;
        pkt.src       = 0x7F000001u;
        pkt.dst       = 0x7F000001u;
        pkt.packet_id = (uint64_t)(10 + i);
        pkt.timestamp = enp_timestamp_ms();

        encode_i32_payload(&pkt, test_vals[i]);

        if (sizeof(ROUTE_WASM) > ENP_CODE_MAX_LEN) {
            ENP_LOG_ERR("ROUTE_WASM exceeds code_len limit");
            return -1;
        }
        pkt.code_len = (uint16_t)sizeof(ROUTE_WASM);
        memcpy(pkt.code, ROUTE_WASM, sizeof(ROUTE_WASM));

        printf("\nENP_ROUTE_DECIDE: input=%d  expected=%s\n",
               (int)test_vals[i], expected[i]);
        ENP_LOG_INFO("Sending ENP_ROUTE_DECIDE: input=%d to %s:%u",
                     (int)test_vals[i], host, (unsigned)port);

        enp_packet_t response;
        memset(&response, 0, sizeof(response));

        int rc = enp_client_send(host, port, &pkt, &response,
                                 (i == 1) ? 2 : 5);  /* short timeout for DROP */
        if (rc == 0 && !(response.flags & ENP_FLAG_ERROR)) {
            printf("  → Server replied (FORWARD confirmed)\n");
        } else if (i == 1) {
            /* Timeout on DROP is the correct behaviour */
            printf("  → No reply (DROP confirmed)\n");
            ok = 1;
        } else {
            ENP_LOG_ERR("Unexpected failure for input=%d", (int)test_vals[i]);
        }
    }
    (void)ok;
    return 0;
}

/* -------------------------------------------------------------------------
 * Demo: two-hop ENP_EXEC
 *   Client → Node A (portA) → Node B (portB) → Client
 *   Each node runs process(x) = x * 2, so:
 *     start=3  → Node A: 3*2=6  → Node B: 6*2=12  → client receives 12
 * -------------------------------------------------------------------------*/
static int run_multihop(const char *hostA, uint16_t portA,
                        const char *hostB, uint16_t portB)
{
    /* Resolve host IPs to uint32 (host byte order) */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    uint32_t ipA = 0, ipB = 0;
    char portA_str[8], portB_str[8];
    snprintf(portA_str, sizeof(portA_str), "%u", (unsigned)portA);
    snprintf(portB_str, sizeof(portB_str), "%u", (unsigned)portB);

    if (getaddrinfo(hostA, portA_str, &hints, &res) == 0 && res) {
        ipA = ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
        freeaddrinfo(res);
    } else {
        ENP_LOG_ERR("Cannot resolve hostA '%s'", hostA);
        return -1;
    }

    res = NULL;
    if (getaddrinfo(hostB, portB_str, &hints, &res) == 0 && res) {
        ipB = ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
        freeaddrinfo(res);
    } else {
        ENP_LOG_ERR("Cannot resolve hostB '%s'", hostB);
        return -1;
    }

    enp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.version    = ENP_VERSION;
    pkt.opcode     = ENP_EXEC;
    pkt.src        = 0x7F000001u;
    pkt.dst        = 0x7F000001u;
    pkt.packet_id  = 100;
    pkt.timestamp  = enp_timestamp_ms();
    pkt.flags      = ENP_FLAG_MULTIHOP;

    /* Hop routing:
     *   hops[0]/hop_ports[0] = return address (filled by enp_client_send_multihop)
     *   hops[1]/hop_ports[1] = Node A
     *   hops[2]/hop_ports[2] = Node B
     */
    pkt.hop_count = 3;
    pkt.hop_index = 1;  /* start processing at Node A */
    pkt.hops[1]      = ipA;   pkt.hop_ports[1] = portA;
    pkt.hops[2]      = ipB;   pkt.hop_ports[2] = portB;

    /* Payload: input = 3 */
    int32_t input_val = 3;
    encode_i32_payload(&pkt, input_val);

    /* Code: process(x) = x * 2 */
    if (sizeof(PROCESS_WASM) > ENP_CODE_MAX_LEN) {
        ENP_LOG_ERR("WASM module exceeds code_len limit");
        return -1;
    }
    pkt.code_len = (uint16_t)sizeof(PROCESS_WASM);
    memcpy(pkt.code, PROCESS_WASM, sizeof(PROCESS_WASM));

    printf("Multi-hop ENP_EXEC: input=%d  route: client → %s:%u → %s:%u → client\n",
           (int)input_val, hostA, (unsigned)portA, hostB, (unsigned)portB);
    printf("Expected: %d → (×2) → %d → (×2) → %d\n",
           input_val, input_val * 2, input_val * 4);

    enp_packet_t response;
    memset(&response, 0, sizeof(response));

    if (enp_client_send_multihop("127.0.0.1", &pkt, &response, 8) != 0) {
        ENP_LOG_ERR("Multi-hop client failed");
        return -1;
    }

    if (response.flags & ENP_FLAG_ERROR) {
        ENP_LOG_ERR("Final node returned an error response");
        return -1;
    }

    int32_t result = decode_i32_payload(&response);
    printf("Multi-hop result: %d (hops traversed: %u)\n",
           (int)result, (unsigned)response.state[0]);
    ENP_LOG_INFO("Multi-hop result=%d  state[0]=%u",
                 (int)result, (unsigned)response.state[0]);

    if (result == input_val * 4)
        printf("✓ Correct: %d * 2 * 2 = %d\n", input_val, result);
    else
        printf("✗ Unexpected result (expected %d)\n", input_val * 4);

    return 0;
}

/* -------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    enp_logger_init(ENP_LOG_INFO, stdout);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0) {
        uint16_t port = ENP_DEFAULT_PORT;
        if (argc >= 3)
            port = (uint16_t)atoi(argv[2]);
        return enp_server_run(port);
    }

    if (strcmp(argv[1], "client") == 0) {
        if (argc < 3) { print_usage(argv[0]); return 1; }
        const char *host = argv[2];
        uint16_t    port = ENP_DEFAULT_PORT;
        if (argc >= 4)
            port = (uint16_t)atoi(argv[3]);
        return run_client(host, port);
    }

    if (strcmp(argv[1], "route") == 0) {
        if (argc < 3) { print_usage(argv[0]); return 1; }
        const char *host = argv[2];
        uint16_t    port = ENP_DEFAULT_PORT;
        if (argc >= 4)
            port = (uint16_t)atoi(argv[3]);
        return run_route(host, port);
    }

    if (strcmp(argv[1], "multihop") == 0) {
        if (argc < 6) { print_usage(argv[0]); return 1; }
        const char *hostA = argv[2];
        uint16_t    portA = (uint16_t)atoi(argv[3]);
        const char *hostB = argv[4];
        uint16_t    portB = (uint16_t)atoi(argv[5]);
        return run_multihop(hostA, portA, hostB, portB);
    }

    print_usage(argv[0]);
    return 1;
}

