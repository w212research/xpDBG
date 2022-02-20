#ifndef LOGGING_H
#define LOGGING_H

typedef enum {
	LOG_CRITICAL,
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARNING,
	LOG_INFO,
	LOG_VERBOSE,
	LOG_WAY_WAY_SUPER_DUPER_BUPER_VERBOSE,
} log_level_t;
typedef enum {
	LOG_UNIMPORTANT,
	LOG_SUCCESS,
} log_status_t;

log_status_t xpdbg_log(log_level_t log_level, char* fmt, ...);
log_status_t set_log_level(log_level_t log_level);

#endif
