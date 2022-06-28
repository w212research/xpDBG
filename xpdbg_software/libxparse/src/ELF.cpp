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
#include "ELF.hpp"

using namespace std;

XParse::ELF::raw_elf_file_header_t XParse::ELF::parse_elf_binary_raw(vector<uint8_t> buf) {
	XParse::ELF::raw_elf_file_header_t ret;

	ret.addr_size = (XParse::ELF::raw_elf_addr_size_t)buf[0x4];
	ret.endianness = (XParse::ELF::raw_elf_endianness_t)buf[0x5];
	
	if (ret.addr_size != XParse::ELF::ELF_32
		&& ret.addr_size != XParse::ELF::ELF_64) {
		ret.endianness = XParse::ELF::ELF_INVALID_ADDR_SIZE;
	}
	
	if (ret.endianness != XParse::ELF::ELF_BIG_ENDIAN
		&& ret.endianness != XParse::ELF::ELF_LITTLE_ENDIAN) {
		ret.endianness = XParse::ELF::ELF_INVALID_ENDIANNESS;
	}

out:
	return ret;
}