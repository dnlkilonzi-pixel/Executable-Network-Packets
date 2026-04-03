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
 * Start the ENP UDP server (node).
 *
 * Listens on the given port, receives packets, validates them,
 * and dispatches based on opcode:
 *   ENP_FORWARD      -> echoes the packet back to the sender
 *   ENP_EXEC         -> executes embedded WASM and returns result
 *   ENP_ROUTE_DECIDE -> WASM decides routing action (forward/drop)
 *
 * Multi-hop packets (hop_count > 0) are automatically forwarded to the
 * next hop in the route list, or the final response is returned to the
 * return address (hops[0]:hop_ports[0]) when the last node is reached.
 *
 * This function blocks until the server is stopped.
 *
 * @param port  UDP port to listen on.
 * @return      0 on clean shutdown, -1 on error.
 */
int enp_server_run(uint16_t port);

/*
 * Send an ENP packet to a server and receive a response (single-hop).
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

/*
 * Send an ENP packet through a multi-hop route and receive the final response.
 *
 * The caller must pre-fill pkt->hops[1..hop_count-1] and
 * pkt->hop_ports[1..hop_count-1] with the processing node addresses.
 * This function binds a local socket, records its port into
 * pkt->hops[0] / pkt->hop_ports[0] as the return address, then sends
 * the packet to hops[1]:hop_ports[1] and waits for the final response.
 *
 * @param local_ip    Local IPv4 address string (e.g. "127.0.0.1").
 * @param pkt         Packet to send (hops[0]/hop_ports[0] will be filled).
 * @param response    Output: final response packet.
 * @param timeout_sec Receive timeout in seconds.
 * @return            0 on success, -1 on error.
 */
int enp_client_send_multihop(const char *local_ip, enp_packet_t *pkt,
                              enp_packet_t *response, int timeout_sec);

#endif /* ENP_NET_H */
