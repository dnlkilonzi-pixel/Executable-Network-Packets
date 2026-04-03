/*
 * enp_wasm.c - WASM Execution Engine using wasm3
 *
 * Integrates the wasm3 interpreter to safely run WASM bytecode
 * embedded in ENP packets.  Enforces memory and time limits.
 *
 * Both enp_wasm_exec (calls "process") and enp_wasm_exec_route (calls
 * "route_decide") share a single internal helper to avoid duplication.
 */

#include "enp_wasm.h"
#include "enp_logger.h"

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * wasm3-based implementation
 * -------------------------------------------------------------------------*/
#ifdef ENP_WITH_WASM3

#include "wasm3.h"

/* Timeout via POSIX alarm() + sigsetjmp/siglongjmp */
#if !defined(_WIN32)
#  include <signal.h>
#  include <setjmp.h>
#  include <unistd.h>

static volatile int g_timed_out = 0;
static sigjmp_buf   g_timeout_jmp;

static void sigalrm_handler(int sig)
{
    (void)sig;
    g_timed_out = 1;
    siglongjmp(g_timeout_jmp, 1);
}
#endif /* !_WIN32 */

/* -------------------------------------------------------------------------
 * Internal helper: load WASM module, call fn_name(i32 input) -> i32,
 * store result in *output.
 * -------------------------------------------------------------------------*/
static enp_wasm_result_t exec_wasm_i32(const uint8_t *code, size_t code_len,
                                        const char *fn_name,
                                        int32_t input, int32_t *output)
{
    if (!code || code_len == 0 || !fn_name || !output)
        return ENP_WASM_ERR;

    enp_wasm_result_t result = ENP_WASM_ERR;

    IM3Environment env = m3_NewEnvironment();
    if (!env) {
        ENP_LOG_ERR("wasm3: failed to create environment");
        return ENP_WASM_OOM;
    }

    IM3Runtime runtime = m3_NewRuntime(env, ENP_WASM_STACK_SIZE, NULL);
    if (!runtime) {
        ENP_LOG_ERR("wasm3: failed to create runtime");
        m3_FreeEnvironment(env);
        return ENP_WASM_OOM;
    }

    IM3Module module = NULL;
    M3Result err = m3_ParseModule(env, &module, code, (uint32_t)code_len);
    if (err) {
        ENP_LOG_ERR("wasm3: parse module failed: %s", err);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_ERR;
    }

    err = m3_LoadModule(runtime, module);
    if (err) {
        ENP_LOG_ERR("wasm3: load module failed: %s", err);
        m3_FreeModule(module);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_ERR;
    }
    /* module is now owned by runtime */

    /* Check memory footprint against limit */
    uint32_t mem_size = m3_GetMemorySize(runtime);
    if (mem_size > ENP_WASM_MAX_MEMORY) {
        ENP_LOG_WARN("wasm3: module memory %u exceeds limit %u",
                     (unsigned)mem_size, ENP_WASM_MAX_MEMORY);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_OOM;
    }

    IM3Function fn = NULL;
    err = m3_FindFunction(&fn, runtime, fn_name);
    if (err) {
        ENP_LOG_ERR("wasm3: function '%s' not found: %s", fn_name, err);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_ERR;
    }

    /* ------------------------------------------------------------------
     * Execute with SIGALRM timeout (POSIX only).
     * On Windows we call directly without a timeout mechanism.
     * ------------------------------------------------------------------*/
#if !defined(_WIN32)
    struct sigaction sa_new, sa_old;
    sa_new.sa_handler = sigalrm_handler;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    sigaction(SIGALRM, &sa_new, &sa_old);

    g_timed_out = 0;
    unsigned int timeout_sec =
        (ENP_WASM_EXEC_TIMEOUT_MS + 999) / 1000;  /* round up */
    alarm(timeout_sec);

    if (sigsetjmp(g_timeout_jmp, 1) == 0) {
        err = m3_CallV(fn, (uint32_t)input);
    } else {
        ENP_LOG_WARN("wasm3: execution timed out after %u seconds", timeout_sec);
        result = ENP_WASM_TIMEOUT;
        alarm(0);
        sigaction(SIGALRM, &sa_old, NULL);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return result;
    }

    alarm(0);
    sigaction(SIGALRM, &sa_old, NULL);
#else
    err = m3_CallV(fn, (uint32_t)input);
#endif

    if (err) {
        ENP_LOG_ERR("wasm3: call to '%s' failed: %s", fn_name, err);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_ERR;
    }

    uint64_t ret = 0;
    err = m3_GetResultsV(fn, &ret);
    if (err) {
        ENP_LOG_ERR("wasm3: get result failed: %s", err);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_ERR;
    }

    *output = (int32_t)(uint32_t)ret;
    result  = ENP_WASM_OK;

    ENP_LOG_INFO("wasm3: %s(%d) = %d", fn_name, (int)input, (int)*output);

    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    return result;
}

/* -------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------*/

enp_wasm_result_t enp_wasm_exec(const uint8_t *code, size_t code_len,
                                 int32_t input, int32_t *output)
{
    return exec_wasm_i32(code, code_len, "process", input, output);
}

enp_wasm_result_t enp_wasm_exec_route(const uint8_t *code, size_t code_len,
                                       int32_t input,
                                       enp_route_decision_t *decision)
{
    if (!decision)
        return ENP_WASM_ERR;

    int32_t action = 0;
    enp_wasm_result_t res = exec_wasm_i32(code, code_len, "route_decide",
                                           input, &action);
    if (res == ENP_WASM_OK) {
        decision->action = (uint8_t)action;
        ENP_LOG_INFO("wasm3: route_decide(%d) → action=%u", (int)input,
                     (unsigned)decision->action);
    }
    return res;
}

/* -------------------------------------------------------------------------
 * Fallback stubs (no wasm3)
 * -------------------------------------------------------------------------*/
#else  /* !ENP_WITH_WASM3 */

enp_wasm_result_t enp_wasm_exec(const uint8_t *code, size_t code_len,
                                 int32_t input, int32_t *output)
{
    (void)code; (void)code_len; (void)input; (void)output;
    ENP_LOG_WARN("wasm3 not available – ENP_EXEC not supported in this build");
    return ENP_WASM_ERR;
}

enp_wasm_result_t enp_wasm_exec_route(const uint8_t *code, size_t code_len,
                                       int32_t input,
                                       enp_route_decision_t *decision)
{
    (void)code; (void)code_len; (void)input;
    ENP_LOG_WARN("wasm3 not available – ENP_ROUTE_DECIDE not supported in this build");
    if (decision)
        decision->action = ENP_ACTION_FORWARD;  /* safe default: always forward */
    return ENP_WASM_ERR;
}

#endif /* ENP_WITH_WASM3 */
