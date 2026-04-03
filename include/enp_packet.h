/*
 * enp_packet.h - ENP Packet Structure and Serialization API
 *
 * Defines the packet format for Executable Network Packets (ENP).
 * All multi-byte fields are stored in network byte order (big-endian).
 *
 * Protocol version 2 adds:
 *   - ENP_ROUTE_DECIDE opcode: WASM decides packet routing at each hop
 *   - Stateful packets: 128-byte state buffer carried across nodes
 *   - Multi-node execution: source-routed hop list with return address
 *
 * Protocol version 3 adds:
 *   - Capability model: per-packet allowed_ops mask + max_hops / max_compute
 *   - Execution budgeting: compute_budget decremented per WASM node
 */

#ifndef ENP_PACKET_H
#define ENP_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* Packet field size limits */
#define ENP_PAYLOAD_MAX_LEN  256
#define ENP_CODE_MAX_LEN     512

/* Routing / state limits */
#define ENP_MAX_HOPS   4    /* Maximum hops in a route list (including return addr) */
#define ENP_STATE_LEN  128  /* Size of the per-packet state buffer */

/* Compute budget sentinel: 0xFFFF = unlimited (never decremented or rejected) */
#define ENP_BUDGET_UNLIMITED  0xFFFFu

/* Wire format header size (bytes):
 *
 *  Base (v1-compatible):
 *    1  version        +  1  opcode      +  2  flags
 *  + 4  src            +  4  dst
 *  + 8  packet_id      +  8  timestamp
 *  + 2  payload_len    +  2  code_len
 *  = 32 bytes
 *
 *  v2 extensions:
 *  + 1  hop_count      +  1  hop_index
 *  + 4*ENP_MAX_HOPS(16) hops[]      (IPv4 addresses → big-endian)
 *  + 2*ENP_MAX_HOPS( 8) hop_ports[] (UDP ports)
 *  + ENP_STATE_LEN(128) state[]
 *  = 32 + 2 + 16 + 8 + 128 = 186 bytes
 *
 *  v3 extensions:
 *  + 4  allowed_ops   (capability bitmask: bit N = opcode N is permitted)
 *  + 1  cap_max_hops  (0 = no limit; else max hop_count this packet may use)
 *  + 1  cap_max_compute (0 = no limit; else max initial compute_budget)
 *  + 2  compute_budget (0xFFFF = unlimited; 0 = exhausted; else remaining)
 *  = 186 + 8 = 194 bytes
 */
#define ENP_HEADER_SIZE 194

/* Maximum total serialized packet size */
#define ENP_MAX_PACKET_SIZE (ENP_HEADER_SIZE + ENP_PAYLOAD_MAX_LEN + ENP_CODE_MAX_LEN)

/* Protocol version */
#define ENP_VERSION 3

/* Opcode definitions */
typedef enum {
    ENP_FORWARD      = 0,  /* Forward / echo packet unchanged            */
    ENP_EXEC         = 1,  /* Execute embedded WASM, return result       */
    ENP_ROUTE_DECIDE = 2   /* WASM decides routing action at this node   */
} enp_opcode_t;

/* allowed_ops bitmask helpers */
#define ENP_OP_BIT(opcode)   (1u << (unsigned)(opcode))
#define ENP_OP_ALL           0u   /* 0 = no restriction (all ops allowed) */

/* Route action values returned by the route_decide WASM function */
typedef enum {
    ENP_ACTION_FORWARD = 0,  /* Continue to next hop (or respond if last) */
    ENP_ACTION_DROP    = 1,  /* Silently discard the packet               */
    ENP_ACTION_CLONE   = 2   /* Forward to all remaining hops (prototype: same as FORWARD) */
} enp_route_action_t;

/* Routing decision produced by ENP_ROUTE_DECIDE WASM execution */
typedef struct {
    uint8_t  action;   /* enp_route_action_t */
} enp_route_decision_t;

/*
 * Per-packet capability token.
 *
 * allowed_ops:   Bitmask of permitted opcodes (ENP_OP_BIT(ENP_EXEC) etc.).
 *                0 means no restriction.
 * cap_max_hops:  Maximum allowed hop_count for this packet.  0 = no limit.
 * cap_max_compute: Maximum initial compute_budget this packet may declare.
 *                  0 = no limit.
 */
typedef struct {
    uint32_t allowed_ops;
    uint8_t  cap_max_hops;
    uint8_t  cap_max_compute;
} enp_capability_t;

/* Flag bits */
#define ENP_FLAG_RESPONSE         (1u << 0)  /* Packet is a response               */
#define ENP_FLAG_ERROR            (1u << 1)  /* Packet signals an error            */
#define ENP_FLAG_MULTIHOP         (1u << 2)  /* Packet is source-routed            */
#define ENP_FLAG_BUDGET_EXHAUSTED (1u << 3)  /* Compute budget was exhausted       */
#define ENP_FLAG_CAP_DENIED       (1u << 4)  /* Capability check failed            */

/* ENP Packet structure (in-memory representation)
 *
 * Multi-hop convention:
 *   hops[0] / hop_ports[0] = return address (original client)
 *   hops[1..hop_count-1]   = processing nodes (Node A, Node B, …)
 *   hop_index              = index of the CURRENT node in hops[]
 *
 * When a node finishes processing:
 *   - If hop_index < hop_count - 1: increment hop_index, forward to
 *     hops[hop_index]:hop_ports[hop_index].
 *   - If hop_index == hop_count - 1 (last node): send response back to
 *     hops[0]:hop_ports[0] (the return address).
 *
 * State:
 *   state[0] is reserved as a hop-counter (incremented by each node).
 *   state[1..127] is available for application-level cross-node state.
 *
 * Capability + Budget:
 *   capability.allowed_ops: bitmask of opcodes this packet may use.
 *   capability.cap_max_hops: if > 0, hop_count must not exceed this.
 *   capability.cap_max_compute: if > 0, compute_budget must not exceed this.
 *   compute_budget: 0xFFFF = unlimited; 0 = exhausted; N = N units remaining.
 *   Each WASM-executing node decrements compute_budget by 1.
 */
typedef struct {
    uint8_t  version;
    uint8_t  opcode;                    /* enp_opcode_t              */
    uint16_t flags;
    uint32_t src;                       /* Originator IPv4 (host BO) */
    uint32_t dst;                       /* Destination IPv4          */
    uint64_t packet_id;
    uint64_t timestamp;
    uint16_t payload_len;
    uint16_t code_len;
    /* v2: programmable routing */
    uint8_t  hop_count;                 /* 0 = single-hop (no routing table) */
    uint8_t  hop_index;                 /* Current position in hops[]        */
    uint32_t hops[ENP_MAX_HOPS];        /* IPv4 addresses (host byte order)  */
    uint16_t hop_ports[ENP_MAX_HOPS];   /* UDP ports for each hop            */
    /* v2: stateful packets */
    uint8_t  state[ENP_STATE_LEN];      /* Cross-node state buffer           */
    /* v3: capability + budgeting */
    enp_capability_t capability;        /* Trust / capability token          */
    uint16_t compute_budget;            /* Execution budget (units)          */
    /* variable-length fields */
    uint8_t  payload[ENP_PAYLOAD_MAX_LEN];
    uint8_t  code[ENP_CODE_MAX_LEN];
} enp_packet_t;

/*
 * Serialize a packet to a byte buffer in network byte order.
 *
 * @param pkt   Pointer to the packet to serialize.
 * @param buf   Output buffer (must be at least ENP_MAX_PACKET_SIZE bytes).
 * @param size  Size of the output buffer.
 * @return      Number of bytes written, or -1 on error.
 */
int enp_packet_serialize(const enp_packet_t *pkt, uint8_t *buf, size_t size);

/*
 * Deserialize a byte buffer into a packet structure.
 *
 * @param buf   Input buffer in network byte order.
 * @param size  Number of valid bytes in the buffer.
 * @param pkt   Output packet structure.
 * @return      0 on success, -1 on error (invalid data or buffer too small).
 */
int enp_packet_deserialize(const uint8_t *buf, size_t size, enp_packet_t *pkt);

/*
 * Validate a deserialized packet.
 *
 * @param pkt  Packet to validate.
 * @return     0 if valid, -1 if invalid.
 */
int enp_packet_validate(const enp_packet_t *pkt);

/*
 * Get a current 64-bit UNIX timestamp in milliseconds.
 */
uint64_t enp_timestamp_ms(void);

/*
 * Get a current 64-bit UNIX timestamp in microseconds.
 * Used for high-resolution WASM execution timing.
 */
uint64_t enp_timestamp_us(void);

#endif /* ENP_PACKET_H */
