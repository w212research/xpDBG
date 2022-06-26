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

#ifndef MACHINE_HPP
#define MACHINE_HPP

#include <cstdint>
#include <vector>
#include <string>

#define XP_PROT_READ (1 << 0)
#define XP_PROT_WRITE (1 << 1)
#define XP_PROT_EXEC (1 << 2)

namespace libxpdbg {
	typedef struct {
		std::string reg_name;
		std::string reg_description;
		uint64_t reg_id;
		uint64_t reg_value;
	} reg_t;

	typedef uint64_t mem_prot_t;

	typedef struct {
		uint64_t addr;
		uint64_t size;
		mem_prot_t prot;
	} mem_reg_t;

	class Machine {
		public:
			virtual std::vector<reg_t> get_registers() = 0;
			virtual std::vector<mem_reg_t> get_memory_regions() = 0;
			virtual bool map_memory(mem_reg_t memory_region) = 0;
			virtual bool unmap_memory(mem_reg_t memory_region) = 0;
			virtual int find_memory_region(uint64_t addr) = 0;
			virtual bool write_memory(uint64_t addr, uint8_t* data, uint64_t size) = 0;
			virtual bool read_memory(uint64_t addr, uint8_t* data, uint64_t size) = 0;
			virtual bool exec_code(uint64_t addr, uint64_t size) = 0;
			virtual bool exec_code_ninsns(uint64_t addr, uint64_t num) = 0;
			virtual bool exec_code_step() = 0;
//			virtual bool step_instruction() = 0;
//			virtual bool run_instructions(uint64_t addr, uint64_t count) = 0;
	};
}

#endif