#ifndef LOGGING_H
#define LOGGING_H

typedef enum {
	LOG_VERBOSE,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR,
	LOG_CRITICAL,
} log_level_t;
typedef enum {
	LOG_UNIMPORTANT,
	LOG_SUCCESS,
} log_status_t;

log_status_t xpdbg_log(log_level_t log_level,
					   const char* fmt, ...);
log_status_t xpdbg_set_log_level(log_level_t log_level);

#endif
