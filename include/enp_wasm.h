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
 * Execute WASM bytecode from an ENP packet.
 *
 * Loads the WASM module from 'code', calls the exported function "process"
 * with 'input' as the sole i32 argument, and stores the i32 return value
 * in '*output'.
 *
 * @param code       Pointer to WASM bytecode.
 * @param code_len   Length of WASM bytecode in bytes.
 * @param input      Input integer to pass to process().
 * @param output     Output: the integer returned by process().
 * @return           ENP_WASM_OK on success, negative on failure.
 */
enp_wasm_result_t enp_wasm_exec(const uint8_t *code, size_t code_len,
                                 int32_t input, int32_t *output);

#endif /* ENP_WASM_H */
