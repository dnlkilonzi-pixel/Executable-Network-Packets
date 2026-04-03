/*
 * main.c - ENP Entry Point
 *
 * Usage:
 *   enp server [port]        Start the ENP server (default port 9000)
 *   enp client <host> [port] Send a demo ENP_EXEC packet to <host>
 *
 * Demo scenario:
 *   The client sends an ENP_EXEC packet carrying a WASM module that
 *   implements  int process(int x) { return x * 2; }  with payload = 5.
 *   The server executes the WASM and returns the result (10) in the
 *   response packet.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "enp_packet.h"
#include "enp_net.h"
#include "enp_logger.h"

/* -------------------------------------------------------------------------
 * Pre-compiled WASM for:  int process(int x) { return x * 2; }
 *
 * Hand-assembled minimal WASM binary (44 bytes):
 *
 *   Magic + version:      00 61 73 6d  01 00 00 00
 *   Type section:         01 06 01 60  01 7f 01 7f
 *   Function section:     03 02 01 00
 *   Export section:       07 0b 01 07  70 72 6f 63
 *                         65 73 73 00  00
 *   Code section:         0a 09 01 07  00 20 00 41
 *                         02 6c 0b
 * -------------------------------------------------------------------------*/
static const uint8_t PROCESS_WASM[] = {
    /* magic */
    0x00, 0x61, 0x73, 0x6d,
    /* version */
    0x01, 0x00, 0x00, 0x00,
    /* type section: (func (param i32) (result i32)) */
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    /* function section: 1 function, type index 0 */
    0x03, 0x02, 0x01, 0x00,
    /* export section: "process" -> func 0 */
    0x07, 0x0b, 0x01, 0x07,
    0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, /* "process" */
    0x00, 0x00,
    /* code section: local.get 0, i32.const 2, i32.mul, end */
    0x0a, 0x09, 0x01, 0x07, 0x00,
    0x20, 0x00,  /* local.get 0 */
    0x41, 0x02,  /* i32.const 2 */
    0x6c,        /* i32.mul     */
    0x0b         /* end         */
};

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s server [port]          Start ENP server (default: %u)\n"
            "  %s client <host> [port]   Send demo ENP_EXEC packet\n",
            prog, ENP_DEFAULT_PORT, prog);
}

/* -------------------------------------------------------------------------
 * Client demo
 * -------------------------------------------------------------------------*/
static int run_client(const char *host, uint16_t port)
{
    enp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.version   = ENP_VERSION;
    pkt.opcode    = ENP_EXEC;
    pkt.src       = 0x7F000001u; /* 127.0.0.1 */
    pkt.dst       = 0x7F000001u;
    pkt.packet_id = 1;
    pkt.timestamp = enp_timestamp_ms();

    /* Payload: input integer 5 encoded as 4-byte big-endian */
    int32_t input_val = 5;
    pkt.payload_len = 4;
    pkt.payload[0]  = (uint8_t)((uint32_t)input_val >> 24);
    pkt.payload[1]  = (uint8_t)((uint32_t)input_val >> 16);
    pkt.payload[2]  = (uint8_t)((uint32_t)input_val >>  8);
    pkt.payload[3]  = (uint8_t)((uint32_t)input_val & 0xFF);

    /* Code: embed the pre-compiled WASM module */
    if (sizeof(PROCESS_WASM) > ENP_CODE_MAX_LEN) {
        ENP_LOG_ERR("WASM module exceeds code_len limit");
        return -1;
    }
    pkt.code_len = (uint16_t)sizeof(PROCESS_WASM);
    memcpy(pkt.code, PROCESS_WASM, sizeof(PROCESS_WASM));

    ENP_LOG_INFO("Sending ENP_EXEC packet: process(%d) to %s:%u",
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

    /* Decode result integer from response payload */
    if (response.payload_len >= 4) {
        int32_t result = (int32_t)(
            ((uint32_t)response.payload[0] << 24) |
            ((uint32_t)response.payload[1] << 16) |
            ((uint32_t)response.payload[2] <<  8) |
             (uint32_t)response.payload[3]);
        ENP_LOG_INFO("Result: process(%d) = %d", (int)input_val, (int)result);
        printf("ENP_EXEC result: process(%d) = %d\n", (int)input_val, (int)result);
    } else if (response.payload_len > 0) {
        ENP_LOG_INFO("Result (1-byte): %u", response.payload[0]);
        printf("ENP_EXEC result: %u\n", response.payload[0]);
    } else {
        ENP_LOG_WARN("Response has no payload");
    }

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
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        const char *host = argv[2];
        uint16_t    port = ENP_DEFAULT_PORT;
        if (argc >= 4)
            port = (uint16_t)atoi(argv[3]);
        return run_client(host, port);
    }

    print_usage(argv[0]);
    return 1;
}
