/*
 * enp_net.h - ENP Networking API (UDP)
 *
 * Cross-platform UDP server and client for the ENP system.
 */

#ifndef ENP_NET_H
#define ENP_NET_H

#include <stdint.h>
#include "enp_packet.h"

/* Default port */
#define ENP_DEFAULT_PORT 9000

/*
 * Start the ENP UDP server.
 *
 * Listens on the given port, receives packets, validates them,
 * and dispatches based on opcode:
 *   ENP_FORWARD -> echoes the packet back to the sender
 *   ENP_EXEC    -> executes embedded WASM and returns result
 *
 * This function blocks until the server is stopped.
 *
 * @param port  UDP port to listen on.
 * @return      0 on clean shutdown, -1 on error.
 */
int enp_server_run(uint16_t port);

/*
 * Send an ENP packet to a server and receive a response.
 *
 * @param host        Destination hostname or IP string.
 * @param port        Destination port.
 * @param pkt         Packet to send.
 * @param response    Output: populated with the response packet on success.
 * @param timeout_sec Receive timeout in seconds.
 * @return            0 on success, -1 on error.
 */
int enp_client_send(const char *host, uint16_t port,
                    const enp_packet_t *pkt, enp_packet_t *response,
                    int timeout_sec);

#endif /* ENP_NET_H */
