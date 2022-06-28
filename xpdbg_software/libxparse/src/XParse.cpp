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

#include "XParse.hpp"

using namespace std;

XParse::format_t XParse::detect_format(vector<uint8_t> buf) {
	XParse::format_t ret = XParse::FORMAT_UNKNOWN;

	if (buf.size() < 4) {
		goto out;
	}

	if (buf[0] == '\x7f' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
		ret = XParse::FORMAT_ELF;
	}

out:
	return ret;
}