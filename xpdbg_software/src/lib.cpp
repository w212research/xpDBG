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