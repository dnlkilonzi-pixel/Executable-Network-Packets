/*
 * enp_wasm.c - WASM Execution Engine using wasm3
 *
 * Integrates the wasm3 interpreter to safely run WASM bytecode
 * embedded in ENP packets.  Enforces memory and time limits.
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

static volatile int       g_timed_out  = 0;
static sigjmp_buf         g_timeout_jmp;

static void sigalrm_handler(int sig)
{
    (void)sig;
    g_timed_out = 1;
    siglongjmp(g_timeout_jmp, 1);
}
#endif /* !_WIN32 */

enp_wasm_result_t enp_wasm_exec(const uint8_t *code, size_t code_len,
                                 int32_t input, int32_t *output)
{
    if (!code || code_len == 0 || !output)
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
    err = m3_FindFunction(&fn, runtime, "process");
    if (err) {
        ENP_LOG_ERR("wasm3: function 'process' not found: %s", err);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return ENP_WASM_ERR;
    }

    /* ------------------------------------------------------------------
     * Execute with timeout via SIGALRM (POSIX only)
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
        /* jumped here by SIGALRM handler */
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
    /* Windows: call without timeout */
    err = m3_CallV(fn, (uint32_t)input);
#endif

    if (err) {
        ENP_LOG_ERR("wasm3: call failed: %s", err);
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

    ENP_LOG_INFO("wasm3: process(%d) = %d", (int)input, (int)*output);

    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    return result;
}

/* -------------------------------------------------------------------------
 * Fallback stub (no wasm3)
 *
 * When ENP_WITH_WASM3 is not defined the server still compiles and runs
 * but returns an error for ENP_EXEC packets.  This allows the networking
 * and serialisation layers to be tested without the WASM dependency.
 * -------------------------------------------------------------------------*/
#else  /* !ENP_WITH_WASM3 */

enp_wasm_result_t enp_wasm_exec(const uint8_t *code, size_t code_len,
                                 int32_t input, int32_t *output)
{
    (void)code;
    (void)code_len;
    (void)input;
    (void)output;
    ENP_LOG_WARN("wasm3 not available – ENP_EXEC not supported in this build");
    return ENP_WASM_ERR;
}

#endif /* ENP_WITH_WASM3 */

