/*
 * enp_wasm.h - ENP WASM Execution Engine API
 *
 * Integrates the wasm3 runtime to safely execute WASM bytecode
 * embedded in ENP packets.
 */

#ifndef ENP_WASM_H
#define ENP_WASM_H

#include <stdint.h>
#include <stddef.h>
#include "enp_packet.h"  /* for enp_route_decision_t */

/* WASM execution limits */
#define ENP_WASM_STACK_SIZE      (64 * 1024)  /* 64 KiB interpreter stack */
#define ENP_WASM_MAX_MEMORY      (256 * 1024) /* 256 KiB WASM linear memory */
#define ENP_WASM_EXEC_TIMEOUT_MS 2000         /* 2 second execution timeout */

/* WASM execution result codes */
typedef enum {
    ENP_WASM_OK      = 0,   /* Execution succeeded */
    ENP_WASM_ERR     = -1,  /* Generic execution error */
    ENP_WASM_TIMEOUT = -2,  /* Execution timed out */
    ENP_WASM_OOM     = -3   /* Out of memory */
} enp_wasm_result_t;

/*
 * Execute WASM bytecode for ENP_EXEC packets.
 *
 * Calls the exported function "process(i32 x) -> i32" with 'input' and
 * stores the return value in '*output'.
 *
 * @param code       Pointer to WASM bytecode.
 * @param code_len   Length of WASM bytecode in bytes.
 * @param input      Input integer to pass to process().
 * @param output     Output: the integer returned by process().
 * @return           ENP_WASM_OK on success, negative on failure.
 */
enp_wasm_result_t enp_wasm_exec(const uint8_t *code, size_t code_len,
                                 int32_t input, int32_t *output);

/*
 * Execute WASM bytecode for ENP_ROUTE_DECIDE packets.
 *
 * Calls the exported function "route_decide(i32 x) -> i32".  The return
 * value is an enp_route_action_t (0=FORWARD, 1=DROP, 2=CLONE).
 * The next hop is determined from the packet's hops[] table by the caller.
 *
 * @param code       Pointer to WASM bytecode.
 * @param code_len   Length of WASM bytecode in bytes.
 * @param input      Input integer from payload.
 * @param decision   Output: routing decision populated on success.
 * @return           ENP_WASM_OK on success, negative on failure.
 */
enp_wasm_result_t enp_wasm_exec_route(const uint8_t *code, size_t code_len,
                                       int32_t input,
                                       enp_route_decision_t *decision);

#endif /* ENP_WASM_H */
