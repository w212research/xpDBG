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

#ifndef LIBXPDBG_HPP
#define LIBXPDBG_HPP

#include "libxpdbg.hpp"
#include "Machine.hpp"
#include <vector>

namespace libxpdbg {
	class ARMv7Machine : public Machine {
		public:
			ARMv7Machine();
			~ARMv7Machine();
			std::vector<reg_t> get_registers();
			std::vector<mem_reg_t> get_memory_regions();
			bool map_memory(mem_reg_t);
			bool unmap_memory(mem_reg_t);
			int find_memory_region(uint64_t addr);
		protected:
			uc_engine			   *uc;
			std::vector<reg_t>		registers;
			std::vector<mem_reg_t>	memory_regions;
	};
}

#endif