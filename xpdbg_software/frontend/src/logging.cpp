/*
 *  Copyright (C) 2022, w212 research. <contact@w212research.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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
