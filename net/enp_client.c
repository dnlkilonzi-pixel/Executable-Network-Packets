/*
 * enp_client.c - ENP UDP Client Implementation
 *
 * Constructs and sends ENP packets to a server, then receives a response.
 */

#define _POSIX_C_SOURCE 200112L

#include "enp_net.h"
#include "enp_packet.h"
#include "enp_logger.h"

#include <string.h>
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
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <errno.h>
   typedef int SOCKET;
#  define INVALID_SOCKET  (-1)
#  define SOCKET_ERROR    (-1)
#  define CLOSE_SOCKET(s) close(s)
#  define SOCK_ERR        errno
#endif

int enp_client_send(const char *host, uint16_t port,
                    const enp_packet_t *pkt, enp_packet_t *response,
                    int timeout_sec)
{
    if (!host || !pkt || !response)
        return -1;

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

    /* Resolve host using getaddrinfo (thread-safe) */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    int gai_err = getaddrinfo(host, port_str, &hints, &res);
    if (gai_err != 0 || !res) {
        ENP_LOG_ERR("Cannot resolve host '%s': %s", host, gai_strerror(gai_err));
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    /* Serialize packet */
    uint8_t buf[ENP_MAX_PACKET_SIZE];
    int len = enp_packet_serialize(pkt, buf, sizeof(buf));
    if (len < 0) {
        ENP_LOG_ERR("Failed to serialize packet");
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    ENP_LOG_INFO("Sending %d-byte ENP packet to %s:%u (opcode=%u)",
                 len, host, (unsigned)port, (unsigned)pkt->opcode);

    int sent = (int)sendto(sock, (const char *)buf, len, 0,
                           (const struct sockaddr *)&server_addr,
                           sizeof(server_addr));
    if (sent == SOCKET_ERROR) {
        ENP_LOG_ERR("sendto() failed: %d", SOCK_ERR);
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    /* Set receive timeout */
#ifdef _WIN32
    DWORD tv_ms = (DWORD)(timeout_sec * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
#else
    struct timeval tv;
    tv.tv_sec  = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    /* Receive response */
    uint8_t resp_buf[ENP_MAX_PACKET_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    int n = (int)recvfrom(sock, (char *)resp_buf, sizeof(resp_buf), 0,
                          (struct sockaddr *)&from_addr, &from_len);
    if (n == SOCKET_ERROR) {
        ENP_LOG_ERR("recvfrom() failed (timeout?): %d", SOCK_ERR);
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    char from_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from_addr.sin_addr, from_ip, sizeof(from_ip));
    ENP_LOG_INFO("Received %d-byte response from %s:%u",
                 n, from_ip, ntohs(from_addr.sin_port));

    int rc = enp_packet_deserialize(resp_buf, (size_t)n, response);
    if (rc != 0) {
        ENP_LOG_ERR("Failed to deserialize response");
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
