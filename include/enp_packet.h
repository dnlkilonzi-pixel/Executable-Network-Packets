/*
 * enp_packet.h - ENP Packet Structure and Serialization API
 *
 * Defines the packet format for Executable Network Packets (ENP).
 * All multi-byte fields are stored in network byte order (big-endian).
 */

#ifndef ENP_PACKET_H
#define ENP_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* Packet field size limits */
#define ENP_PAYLOAD_MAX_LEN  256
#define ENP_CODE_MAX_LEN     512

/* Wire format header size (bytes):
 *   1 (version) + 1 (opcode) + 2 (flags) + 4 (src) + 4 (dst)
 * + 8 (packet_id) + 8 (timestamp) + 2 (payload_len) + 2 (code_len)
 * = 32 bytes
 */
#define ENP_HEADER_SIZE 32

/* Maximum total serialized packet size */
#define ENP_MAX_PACKET_SIZE (ENP_HEADER_SIZE + ENP_PAYLOAD_MAX_LEN + ENP_CODE_MAX_LEN)

/* Protocol version */
#define ENP_VERSION 1

/* Opcode definitions */
typedef enum {
    ENP_FORWARD = 0,   /* Forward / echo packet unchanged */
    ENP_EXEC    = 1    /* Execute embedded WASM logic */
} enp_opcode_t;

/* Flag bits */
#define ENP_FLAG_RESPONSE  (1u << 0)  /* Packet is a response */
#define ENP_FLAG_ERROR     (1u << 1)  /* Packet signals an error */

/* ENP Packet structure (in-memory representation) */
typedef struct {
    uint8_t  version;
    uint8_t  opcode;             /* enp_opcode_t */
    uint16_t flags;
    uint32_t src;
    uint32_t dst;
    uint64_t packet_id;
    uint64_t timestamp;
    uint16_t payload_len;
    uint16_t code_len;
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

#endif /* ENP_PACKET_H */
