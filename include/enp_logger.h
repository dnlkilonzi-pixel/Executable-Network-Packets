/*
 * enp_logger.h - ENP Logging API
 *
 * Simple timestamped, leveled logging for the ENP system.
 */

#ifndef ENP_LOGGER_H
#define ENP_LOGGER_H

#include <stdio.h>

/* Log levels */
typedef enum {
    ENP_LOG_DEBUG = 0,
    ENP_LOG_INFO  = 1,
    ENP_LOG_WARN  = 2,
    ENP_LOG_ERROR = 3
} enp_log_level_t;

/*
 * Initialize the logger.
 *
 * @param level    Minimum log level to print.
 * @param out      Output file (e.g., stdout, stderr, or a log file).
 */
void enp_logger_init(enp_log_level_t level, FILE *out);

/*
 * Log a message.
 *
 * @param level   Log level for this message.
 * @param fmt     printf-style format string.
 * @param ...     Format arguments.
 */
void enp_log(enp_log_level_t level, const char *fmt, ...);

/* Convenience macros */
#define ENP_LOG_DBG(...)  enp_log(ENP_LOG_DEBUG, __VA_ARGS__)
#define ENP_LOG_INFO(...) enp_log(ENP_LOG_INFO,  __VA_ARGS__)
#define ENP_LOG_WARN(...) enp_log(ENP_LOG_WARN,  __VA_ARGS__)
#define ENP_LOG_ERR(...)  enp_log(ENP_LOG_ERROR, __VA_ARGS__)

#endif /* ENP_LOGGER_H */
