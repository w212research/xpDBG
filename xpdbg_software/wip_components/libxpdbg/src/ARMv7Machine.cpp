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

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include "ARMv7Machine.hpp"
#include "libxpdbg.hpp"
#include <cstdio>

using namespace libxpdbg;

ARMv7Machine::ARMv7Machine() {
	uc_err err;
	reg_t  reg;

	err = uc_open(UC_ARCH_ARM,
				  UC_MODE_THUMB,
				  &this->uc);

	reg.reg_description = "r0";
	reg.reg_name = "r0";
	reg.reg_id = 0;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r1";
	reg.reg_name = "r1";
	reg.reg_id = 1;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r2";
	reg.reg_name = "r2";
	reg.reg_id = 2;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r3";
	reg.reg_name = "r3";
	reg.reg_id = 3;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r4";
	reg.reg_name = "r4";
	reg.reg_id = 4;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r5";
	reg.reg_name = "r5";
	reg.reg_id = 5;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r6";
	reg.reg_name = "r6";
	reg.reg_id = 6;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r7";
	reg.reg_name = "r7";
	reg.reg_id = 7;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r8";
	reg.reg_name = "r8";
	reg.reg_id = 8;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r9";
	reg.reg_name = "r9";
	reg.reg_id = 9;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r10";
	reg.reg_name = "r10";
	reg.reg_id = 10;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "r11";
	reg.reg_name = "r11";
	reg.reg_id = 11;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "ip";
	reg.reg_name = "ip";
	reg.reg_id = 12;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "sp";
	reg.reg_name = "sp";
	reg.reg_id = 13;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "lr";
	reg.reg_name = "lr";
	reg.reg_id = 14;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "pc";
	reg.reg_name = "pc";
	reg.reg_id = 15;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);	
}

ARMv7Machine::~ARMv7Machine() {
	uc_close(this->uc);
}

std::vector<reg_t> ARMv7Machine::get_registers() {
	return this->registers;
}

std::vector<mem_reg_t> ARMv7Machine::get_memory_regions() {
	return this->memory_regions;
}

bool ARMv7Machine::map_memory(mem_reg_t memory_region) {
	bool	 ret = true;
	uint32_t prot;
	uc_err	 err;

	prot |= (memory_region.prot & XP_PROT_READ) ? UC_PROT_READ : 0;
	prot |= (memory_region.prot & XP_PROT_WRITE) ? UC_PROT_WRITE : 0;
	prot |= (memory_region.prot & XP_PROT_EXEC) ? UC_PROT_EXEC : 0;

	err = uc_mem_map(this->uc, memory_region.addr, memory_region.size, prot);

	if (err) {
		fprintf(stderr, "uc_mem_map failed: %u (%s)\n", err, uc_strerror(err));
		return false;
	} else {
		this->memory_regions.push_back(memory_region);
	}

	return ret;
}