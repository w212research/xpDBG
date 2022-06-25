#ifndef LIB_H
#define LIB_H

#include <stdarg.h>
#include <memory>
#include <string>

#define LIST_LEN(l) (sizeof(l) / sizeof(l[0]))

std::string string_format_cstr(const char* fmt_str, ...);
std::string string_format(const std::string fmt_str, ...);

#endif
