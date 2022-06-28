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

#ifndef XPARSE_HPP
#define XPARSE_HPP

#include <cstdint>
#include <vector>

namespace XParse {
	typedef enum {
		FORMAT_ELF,
		FORMAT_MACHO,
		FORMAT_PE,
		FORMAT_UNKNOWN,
	} format_t;

	format_t detect_format(std::vector<uint8_t> buf);
}

#define NORMAL_TEST_ELF_PATH "../submodules/binary-samples/elf-Linux-x64-bash"
#define NORMAL_TEST_MACHO_PATH "../submodules/binary-samples/MachO-OSX-x64-ls"

#endif