/*
 * enp_packet.c - ENP Packet Serialization / Deserialization / Validation
 *
 * All multi-byte fields are serialized in network byte order (big-endian)
 * using manual byte manipulation to guarantee cross-platform compatibility.
 */

#include "enp_packet.h"
#include "enp_logger.h"

#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#  include <sys/time.h>
#endif

/* ---------------------------------------------------------------------------
 * Endianness helpers (work on all platforms, including those without htonl)
 * ---------------------------------------------------------------------------*/

static void write_u16_be(uint8_t *buf, uint16_t v)
{
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v & 0xFF);
}

static void write_u32_be(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >>  8);
    buf[3] = (uint8_t)(v & 0xFF);
}

static void write_u64_be(uint8_t *buf, uint64_t v)
{
    buf[0] = (uint8_t)(v >> 56);
    buf[1] = (uint8_t)(v >> 48);
    buf[2] = (uint8_t)(v >> 40);
    buf[3] = (uint8_t)(v >> 32);
    buf[4] = (uint8_t)(v >> 24);
    buf[5] = (uint8_t)(v >> 16);
    buf[6] = (uint8_t)(v >>  8);
    buf[7] = (uint8_t)(v & 0xFF);
}

static uint16_t read_u16_be(const uint8_t *buf)
{
    return ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
}

static uint32_t read_u32_be(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
}

static uint64_t read_u64_be(const uint8_t *buf)
{
    return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48)
         | ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32)
         | ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16)
         | ((uint64_t)buf[6] <<  8) |  (uint64_t)buf[7];
}

/* ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------*/

int enp_packet_serialize(const enp_packet_t *pkt, uint8_t *buf, size_t size)
{
    if (!pkt || !buf)
        return -1;

    if (pkt->payload_len > ENP_PAYLOAD_MAX_LEN || pkt->code_len > ENP_CODE_MAX_LEN)
        return -1;

    size_t total = (size_t)ENP_HEADER_SIZE + pkt->payload_len + pkt->code_len;
    if (size < total)
        return -1;

    size_t off = 0;

    buf[off++] = pkt->version;
    buf[off++] = pkt->opcode;
    write_u16_be(buf + off, pkt->flags);      off += 2;
    write_u32_be(buf + off, pkt->src);        off += 4;
    write_u32_be(buf + off, pkt->dst);        off += 4;
    write_u64_be(buf + off, pkt->packet_id);  off += 8;
    write_u64_be(buf + off, pkt->timestamp);  off += 8;
    write_u16_be(buf + off, pkt->payload_len); off += 2;
    write_u16_be(buf + off, pkt->code_len);   off += 2;
    /* v2: routing */
    buf[off++] = pkt->hop_count;
    buf[off++] = pkt->hop_index;
    for (int i = 0; i < ENP_MAX_HOPS; i++) {
        write_u32_be(buf + off, pkt->hops[i]);      off += 4;
    }
    for (int i = 0; i < ENP_MAX_HOPS; i++) {
        write_u16_be(buf + off, pkt->hop_ports[i]); off += 2;
    }
    /* v2: state */
    memcpy(buf + off, pkt->state, ENP_STATE_LEN); off += ENP_STATE_LEN;
    /* v3: capability + budget */
    write_u32_be(buf + off, pkt->capability.allowed_ops);  off += 4;
    buf[off++] = pkt->capability.cap_max_hops;
    buf[off++] = pkt->capability.cap_max_compute;
    write_u16_be(buf + off, pkt->compute_budget);          off += 2;

    /* Sanity-check: header size must match */
    if (off != ENP_HEADER_SIZE)
        return -1;

    if (pkt->payload_len > 0) {
        memcpy(buf + off, pkt->payload, pkt->payload_len);
        off += pkt->payload_len;
    }

    if (pkt->code_len > 0) {
        memcpy(buf + off, pkt->code, pkt->code_len);
        off += pkt->code_len;
    }

    return (int)off;
}

int enp_packet_deserialize(const uint8_t *buf, size_t size, enp_packet_t *pkt)
{
    if (!buf || !pkt || size < ENP_HEADER_SIZE)
        return -1;

    memset(pkt, 0, sizeof(*pkt));

    size_t off = 0;

    pkt->version     = buf[off++];
    pkt->opcode      = buf[off++];
    pkt->flags       = read_u16_be(buf + off); off += 2;
    pkt->src         = read_u32_be(buf + off); off += 4;
    pkt->dst         = read_u32_be(buf + off); off += 4;
    pkt->packet_id   = read_u64_be(buf + off); off += 8;
    pkt->timestamp   = read_u64_be(buf + off); off += 8;
    pkt->payload_len = read_u16_be(buf + off); off += 2;
    pkt->code_len    = read_u16_be(buf + off); off += 2;
    /* v2: routing */
    pkt->hop_count   = buf[off++];
    pkt->hop_index   = buf[off++];
    for (int i = 0; i < ENP_MAX_HOPS; i++) {
        pkt->hops[i]      = read_u32_be(buf + off); off += 4;
    }
    for (int i = 0; i < ENP_MAX_HOPS; i++) {
        pkt->hop_ports[i] = read_u16_be(buf + off); off += 2;
    }
    /* v2: state */
    memcpy(pkt->state, buf + off, ENP_STATE_LEN); off += ENP_STATE_LEN;
    /* v3: capability + budget */
    pkt->capability.allowed_ops      = read_u32_be(buf + off); off += 4;
    pkt->capability.cap_max_hops     = buf[off++];
    pkt->capability.cap_max_compute  = buf[off++];
    pkt->compute_budget              = read_u16_be(buf + off); off += 2;

    /* Validate lengths before accessing variable-length data */
    if (pkt->payload_len > ENP_PAYLOAD_MAX_LEN || pkt->code_len > ENP_CODE_MAX_LEN) {
        ENP_LOG_ERR("Packet lengths exceed limits: payload=%u code=%u",
                    pkt->payload_len, pkt->code_len);
        return -1;
    }

    size_t expected = (size_t)ENP_HEADER_SIZE + pkt->payload_len + pkt->code_len;
    if (size < expected) {
        ENP_LOG_ERR("Buffer too small: need %zu, have %zu", expected, size);
        return -1;
    }

    if (pkt->payload_len > 0) {
        memcpy(pkt->payload, buf + off, pkt->payload_len);
        off += pkt->payload_len;
    }

    if (pkt->code_len > 0) {
        memcpy(pkt->code, buf + off, pkt->code_len);
    }

    return 0;
}

int enp_packet_validate(const enp_packet_t *pkt)
{
    if (!pkt)
        return -1;

    if (pkt->version != ENP_VERSION) {
        ENP_LOG_WARN("Unsupported packet version: %u", pkt->version);
        return -1;
    }

    if (pkt->opcode != ENP_FORWARD &&
        pkt->opcode != ENP_EXEC    &&
        pkt->opcode != ENP_ROUTE_DECIDE) {
        ENP_LOG_WARN("Invalid opcode: %u", pkt->opcode);
        return -1;
    }

    if (pkt->payload_len > ENP_PAYLOAD_MAX_LEN) {
        ENP_LOG_WARN("payload_len %u exceeds max %u", pkt->payload_len, ENP_PAYLOAD_MAX_LEN);
        return -1;
    }

    if (pkt->code_len > ENP_CODE_MAX_LEN) {
        ENP_LOG_WARN("code_len %u exceeds max %u", pkt->code_len, ENP_CODE_MAX_LEN);
        return -1;
    }

    if ((pkt->opcode == ENP_EXEC || pkt->opcode == ENP_ROUTE_DECIDE)
            && pkt->code_len == 0) {
        ENP_LOG_WARN("Opcode %u requires WASM code but code_len == 0", pkt->opcode);
        return -1;
    }

    if (pkt->hop_count > ENP_MAX_HOPS) {
        ENP_LOG_WARN("hop_count %u exceeds max %u", pkt->hop_count, ENP_MAX_HOPS);
        return -1;
    }

    if (pkt->hop_count > 0 && pkt->hop_index >= pkt->hop_count) {
        ENP_LOG_WARN("hop_index %u >= hop_count %u", pkt->hop_index, pkt->hop_count);
        return -1;
    }

    return 0;
}

uint64_t enp_timestamp_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    /* Convert from 100-nanosecond intervals since Windows epoch (1601-01-01)
     * to milliseconds since Unix epoch (1970-01-01):
     *   ÷ 10000   → milliseconds since 1601-01-01
     *   − 11644473600000  → milliseconds since 1970-01-01 (116444736000000000 intervals) */
    t /= 10000ULL;
    t -= 11644473600000ULL;
    return t;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
#endif
}

uint64_t enp_timestamp_us(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    /* ÷ 10 → microseconds since Windows epoch; − offset → Unix epoch */
    t /= 10ULL;
    t -= 11644473600000000ULL;
    return t;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
#endif
}
