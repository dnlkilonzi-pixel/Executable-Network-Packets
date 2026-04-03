/*
 * enp_logger.c - ENP Logging Implementation
 */

#define _POSIX_C_SOURCE 1

#include "enp_logger.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

static enp_log_level_t g_min_level = ENP_LOG_INFO;
static FILE           *g_out       = NULL;

static const char *level_str(enp_log_level_t level)
{
    switch (level) {
    case ENP_LOG_DEBUG: return "DEBUG";
    case ENP_LOG_INFO:  return "INFO ";
    case ENP_LOG_WARN:  return "WARN ";
    case ENP_LOG_ERROR: return "ERROR";
    default:            return "?????";
    }
}

void enp_logger_init(enp_log_level_t level, FILE *out)
{
    g_min_level = level;
    g_out       = out ? out : stderr;
}

void enp_log(enp_log_level_t level, const char *fmt, ...)
{
    if (level < g_min_level)
        return;

    if (!g_out)
        g_out = stderr;

    /* Timestamp */
    time_t     now  = time(NULL);
    struct tm  tm_s;
    char       ts[20];

#if defined(_WIN32)
    localtime_s(&tm_s, &now);
#else
    localtime_r(&now, &tm_s);
#endif
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_s);

    fprintf(g_out, "[%s] [%s] ", ts, level_str(level));

    va_list args;
    va_start(args, fmt);
    vfprintf(g_out, fmt, args);
    va_end(args);

    fprintf(g_out, "\n");
    fflush(g_out);
}
