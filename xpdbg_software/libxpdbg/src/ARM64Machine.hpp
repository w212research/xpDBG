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

#ifndef ARM64MACHINE_HPP
#define ARM64MACHINE_HPP

#include "libxpdbg.hpp"
#include "Machine.hpp"
#include <vector>

namespace libxpdbg {
	class ARM64Machine : public Machine {
		public:
			ARM64Machine();
			~ARM64Machine();
			std::vector<reg_t> get_registers();
			std::vector<mem_reg_t> get_memory_regions();
			bool map_memory(mem_reg_t);
			bool unmap_memory(mem_reg_t);
			int find_memory_region(uint64_t addr);
			bool write_memory(uint64_t addr, uint8_t* data, uint64_t size);
			bool read_memory(uint64_t addr, uint8_t* data, uint64_t size);
			bool exec_code_addr(uint64_t addr, uint64_t size);
			bool exec_code_addr_ninsns(uint64_t addr, uint64_t num);
			bool exec_code_ninsns(uint64_t num);
			bool exec_code_step();
			bool set_register(reg_t reg);
			std::vector<insn_t> disassemble_memory(uint64_t addr, uint64_t size);
		protected:
			std::vector<mem_reg_t>	memory_regions;
			std::vector<reg_t>		registers;
			csh						handle;
			uc_engine			   *uc;
	};
}

#endif