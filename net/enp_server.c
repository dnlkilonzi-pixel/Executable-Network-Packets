/*
 * enp_server.c - ENP UDP Server (Node) Implementation
 *
 * Listens for incoming ENP packets, validates them, and routes based on opcode:
 *   ENP_FORWARD  -> echoes packet back to sender
 *   ENP_EXEC     -> executes embedded WASM and returns result
 */

#include "enp_net.h"
#include "enp_packet.h"
#include "enp_wasm.h"
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
 * Internal: handle a single incoming packet
 * -------------------------------------------------------------------------*/
static void handle_packet(SOCKET sock,
                           const uint8_t *raw, size_t raw_len,
                           const struct sockaddr_in *client_addr,
                           socklen_t addr_len)
{
    enp_packet_t pkt;
    if (enp_packet_deserialize(raw, raw_len, &pkt) != 0) {
        ENP_LOG_WARN("Received malformed packet – discarding");
        return;
    }

    if (enp_packet_validate(&pkt) != 0) {
        ENP_LOG_WARN("Packet failed validation – discarding");
        return;
    }

    ENP_LOG_INFO("Received packet id=%llu src=0x%08X dst=0x%08X opcode=%u "
                 "payload_len=%u code_len=%u",
                 (unsigned long long)pkt.packet_id,
                 pkt.src, pkt.dst,
                 (unsigned)pkt.opcode,
                 pkt.payload_len, pkt.code_len);

    enp_packet_t resp;
    memcpy(&resp, &pkt, sizeof(resp));
    resp.flags |= ENP_FLAG_RESPONSE;
    resp.timestamp = enp_timestamp_ms();

    switch (pkt.opcode) {
    case ENP_FORWARD:
        ENP_LOG_INFO("Opcode ENP_FORWARD: echoing packet");
        /* Response is already a copy – just send it back */
        break;

    case ENP_EXEC: {
        ENP_LOG_INFO("Opcode ENP_EXEC: executing WASM code (%u bytes)", pkt.code_len);

        /* Extract input integer from payload (first 4 bytes, big-endian) */
        int32_t input  = 0;
        int32_t output = 0;

        if (pkt.payload_len >= 4) {
            input = (int32_t)(
                ((uint32_t)pkt.payload[0] << 24) |
                ((uint32_t)pkt.payload[1] << 16) |
                ((uint32_t)pkt.payload[2] <<  8) |
                 (uint32_t)pkt.payload[3]);
        } else if (pkt.payload_len > 0) {
            input = (int32_t)pkt.payload[0];
        }

        ENP_LOG_INFO("WASM input: %d", (int)input);

        enp_wasm_result_t wres = enp_wasm_exec(pkt.code, pkt.code_len, input, &output);

        if (wres == ENP_WASM_OK) {
            ENP_LOG_INFO("WASM result: %d", (int)output);
            /* Write result back into the response payload as 4-byte big-endian */
            resp.payload_len = 4;
            resp.payload[0] = (uint8_t)((uint32_t)output >> 24);
            resp.payload[1] = (uint8_t)((uint32_t)output >> 16);
            resp.payload[2] = (uint8_t)((uint32_t)output >>  8);
            resp.payload[3] = (uint8_t)((uint32_t)output & 0xFF);
        } else {
            ENP_LOG_ERR("WASM execution failed (result=%d)", (int)wres);
            resp.flags |= ENP_FLAG_ERROR;
        }
        break;
    }

    default:
        /* Already caught by validate() – should not reach here */
        ENP_LOG_ERR("Unexpected opcode %u", (unsigned)pkt.opcode);
        return;
    }

    /* Serialize and send response */
    uint8_t resp_buf[ENP_MAX_PACKET_SIZE];
    int resp_len = enp_packet_serialize(&resp, resp_buf, sizeof(resp_buf));
    if (resp_len < 0) {
        ENP_LOG_ERR("Failed to serialize response packet");
        return;
    }

    int sent = (int)sendto(sock, (const char *)resp_buf, resp_len, 0,
                           (const struct sockaddr *)client_addr, addr_len);
    if (sent == SOCKET_ERROR) {
        ENP_LOG_ERR("sendto failed: %d", SOCK_ERR);
    } else {
        ENP_LOG_INFO("Response sent (%d bytes)", sent);
    }
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

    ENP_LOG_INFO("ENP server listening on port %u", (unsigned)port);

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

        ENP_LOG_DBG("Received %d bytes from %s:%u",
                    n,
                    inet_ntoa(client_addr.sin_addr),
                    ntohs(client_addr.sin_port));

        handle_packet(sock, buf, (size_t)n, &client_addr, addr_len);
    }

    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
