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

#include <stdarg.h>
#include <string.h>
#include <memory>
#include <string>

using namespace std;

string string_format(const string fmt_str, ...) {
	/*
	 *  reserve two times as much as the length of the fmt_str
	 */
	int final_n, n = ((int)fmt_str.size()) * 2;

	unique_ptr<char[]> formatted;
	va_list ap;

	while (1) {
		/*
		 *  wrap the plain char array into the unique_ptr
		 */
		formatted.reset(new char[n]);

		strcpy(&formatted[0], fmt_str.c_str());

		va_start(ap, fmt_str);

		final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);

		va_end(ap);

		if (final_n < 0 || final_n >= n) {
			n += abs(final_n - n + 1);
		} else {
			break;
		}
	}

	return string(formatted.get());
}

string string_format_cstr(const char* fmt_str, ...) {
	/*
	 *  reserve two times as much as the length of the fmt_str
	 */
	int final_n, n = ((int)strlen(fmt_str)) * 2;

	unique_ptr<char[]> formatted;
	va_list ap;

	while (1) {
		/*
		 *  wrap the plain char array into the unique_ptr
		 */
		formatted.reset(new char[n]);

		strcpy(&formatted[0], fmt_str);

		va_start(ap, fmt_str);

		final_n = vsnprintf(&formatted[0], n, fmt_str, ap);

		va_end(ap);

		if (final_n < 0 || final_n >= n) {
			n += abs(final_n - n + 1);
		} else {
			break;
		}
	}

	return string(formatted.get());
}