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
#include <string>

using namespace std;

namespace XParse {
	namespace ELF {
		std::string abi_strs[] = {
			"SystemV",
			"HP-UX",
			"NetBSD",
			"Linux",
			"Hurd",
			"Solaris",
			"AIX",
			"IRIX",
			"FreeBSD",
			"Tru64",
			"Modesto",
			"OpenBSD",
			"OpenVMS",
			"NonStop",
			"AROS",
			"FenixOS",
			"CloudABI",
			"OpenVOS",
		};

		std::string obj_type_strs[] = {
			"Unknown",
			"Relocatable file",
			"Executable file",
			"Shared object",
			"Core file"
		};

		std::string isa_strs[] = {
			"Unspecified ISA",
			"AT&T WE 32100",
			"SPARC",
			"x86",
			"M68k",
			"M88k",
			"Intel MCU",
			"Intel 80680",
			"MIPS",
			"IBM System/370",
			"MIPS RS3000 LE",
			"Reserved",
			"Reserved",
			"Reserved",
			"PA-RISC",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"80960",
			"PowerPC",
			"PowerPC64",
			"S390(x)",
			"IBM SPU/SPC",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"V800",
			"FR20",
			"RH-32",
			"RCE",
			"ARM (32-bit)",
			"Alpha",
			"SuperH",
			"SPARC Version 9",
			"TriCore",
			"ARC",
			"H8/300",
			"H8/300H",
			"H8S",
			"H8/500",
			"IA-64",
			"MIPS-X",
			"ColdFire",
			"M68HC12",
			"MMA",
			"PCP",
			"Cell",
			"NDR1",
			"Star*Core",
			"ME16",
			"STM ST100",
			"TinyJ",
			"x86-64",
			"Sony DSP Processor",
			"PDP-10",
			"PDP-11",
			"FX66",
			"ST9+",
			"ST7",
			"MC68HC16",
			"MC68HC11",
			"MC68HC08",
			"MC68HC05",
			"SVx",
			"ST19",
			"VAX",
			"Axis",
			"Infineon",
			"Element 14",
			"LSI Logic",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"TMS320C6000",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Elbrus",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"ARM64",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Z80",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"RISC-V",
			"Reserved",
			"Reserved",
			"Reserved",
			"BPF",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"Reserved",
			"65C816",
		};
	}
}

XParse::ELF::raw_elf_file_header_t XParse::ELF::parse_elf_binary_raw(vector<uint8_t> buf) {
	uint16_t						   obj_type;
	XParse::ELF::raw_elf_file_header_t ret;

	ret.addr_size = (XParse::ELF::raw_elf_addr_size_t)buf[0x4];
	ret.endianness = (XParse::ELF::raw_elf_endianness_t)buf[0x5];
	
	if (ret.addr_size != XParse::ELF::ELF_32
		&& ret.addr_size != XParse::ELF::ELF_64) {
		ret.addr_size = XParse::ELF::ELF_INVALID_ADDR_SIZE;
	}
	
	if (ret.endianness != XParse::ELF::ELF_BIG_ENDIAN
		&& ret.endianness != XParse::ELF::ELF_LITTLE_ENDIAN) {
		ret.endianness = XParse::ELF::ELF_INVALID_ENDIANNESS;
	}

	ret.abi = (XParse::ELF::raw_elf_abi_t)buf[0x7];

	if (ret.abi >= XParse::ELF::ELF_ABI__END) {
		ret.abi = XParse::ELF::ELF_ABI_INVALID;
	}

	ret.abi_version = buf[0x8];

	if (ret.endianness == XParse::ELF::ELF_LITTLE_ENDIAN) {
		obj_type = (buf[0x11] << 8) | (buf[0x10]);
	} else {
		obj_type = (buf[0x10] << 8) | (buf[0x11]);
	}

	if (ret.endianness == XParse::ELF::ELF_LITTLE_ENDIAN) {
		ret.isa = (XParse::ELF::raw_elf_isa_t)((buf[0x13] << 8) | (buf[0x12]));
	} else {
		ret.isa = (XParse::ELF::raw_elf_isa_t)((buf[0x12] << 8) | (buf[0x13]));
	}

	if (!((XParse::ELF::ELF_OBJ_TYPE_UNKNOWN <= obj_type) && (obj_type < XParse::ELF::ELF_OBJ_TYPE_INVALID))
		&& !((XParse::ELF::ELF_OBJ_TYPE_RESERVED_OS <= obj_type) && (obj_type <= XParse::ELF::ELF_OBJ_TYPE_END))) {
		obj_type = XParse::ELF::ELF_OBJ_TYPE_INVALID;
	}

	ret.obj_type = (XParse::ELF::raw_elf_obj_type_t)obj_type;

out:
	return ret;
}

string XParse::ELF::to_string_raw(XParse::ELF::raw_elf_file_header_t file_header) {
	string ret;

	ret += "Binary Type: ";
	ret += (file_header.addr_size == XParse::ELF::ELF_32) ? "32-bit ELF"
														  : "64-bit ELF";
	ret += (file_header.endianness == XParse::ELF::ELF_LITTLE_ENDIAN) ? " LE\n"
																	  : " BE\n";
	ret += "ABI: " + abi_strs[file_header.abi] + "\n";
	ret += "Object Type: " + ((file_header.obj_type < XParse::ELF::ELF_OBJ_TYPE_INVALID) ? obj_type_strs[file_header.obj_type]
																						 : "OS/Processor Specific") + "\n";
	ret += "ISA: " + isa_strs[file_header.isa] + "\n";

	return ret;
}