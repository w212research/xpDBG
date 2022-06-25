#include "logging.h"
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>

using namespace std;

static log_level_t	current_log_level;
char 				log_char[] = "viwec";

log_status_t xpdbg_log(log_level_t log_level,
					   const char* fmt, ...) {
	if (log_level < current_log_level) {
		/*
		 *  do not log messages that are less important / more verbose
		 *  than the current log level
		 */
		return LOG_UNIMPORTANT;
	} else {
		va_list		args;

		char	   *asctime_ret = NULL;
		char	   *s_to_print = NULL;
		struct	tm *time_info;
		time_t		raw_time;

		/*
		 *  get the time, convert to a string
		 */
		time(&raw_time);
		time_info	= localtime(&raw_time);
		asctime_ret	= asctime(time_info);

		/*
		 *  asctime adds a newline, remove it.
		 */
		for (int i = 0; i < strlen(asctime_ret) + 2; i++) {
			if (asctime_ret[i] == '\n') {
				asctime_ret[i] = '\0';
				break;
			}
		}

		/*
		 *  variadic function stuff
		 */
		va_start(args, fmt);
		vasprintf(&s_to_print, fmt, args);

		/*
		 *  print that shit
		 */
		printf("[[%c] xpDBG (%s)]: %s\n",
			   log_char[log_level],
			   asctime_ret,
			   s_to_print);

		va_end(args);

		free(s_to_print);

		return LOG_SUCCESS;
	}

	__builtin_unreachable();
}

log_status_t xpdbg_set_log_level(log_level_t log_level) {
	current_log_level = log_level;
	return LOG_SUCCESS;
}