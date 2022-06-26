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

uc_arm_reg normal_regs[] = {
	UC_ARM_REG_R0,
	UC_ARM_REG_R1,
	UC_ARM_REG_R2,
	UC_ARM_REG_R3,
	UC_ARM_REG_R4,
	UC_ARM_REG_R5,
	UC_ARM_REG_R6,
	UC_ARM_REG_R7,
	UC_ARM_REG_R8,
	UC_ARM_REG_R9,
	UC_ARM_REG_R10,
	UC_ARM_REG_R11,
	UC_ARM_REG_R12,
	UC_ARM_REG_R13,
	UC_ARM_REG_R14,
	UC_ARM_REG_R15,
};

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
	for (int i = 0; i < sizeof(normal_regs) / sizeof(normal_regs[0]); i++) {
		uint32_t val;
		uc_reg_read(this->uc, normal_regs[i], &val);
		this->registers[i].reg_value = val;
	}
	return this->registers;
}

std::vector<mem_reg_t> ARMv7Machine::get_memory_regions() {
	std::vector<mem_reg_t>	regions;
	uc_mem_region		   *uc_style_memory_regions;
	uint32_t				count;

	uc_mem_regions(this->uc, &uc_style_memory_regions, &count);

	for (int i = 0; i < count; i++) {
		mem_reg_t region;
		region.addr = uc_style_memory_regions[i].begin;
		region.size = uc_style_memory_regions[i].end - region.addr;
		region.prot = 0;
		region.prot |= (uc_style_memory_regions[i].perms & UC_PROT_READ) ? XP_PROT_READ : 0;
		region.prot |= (uc_style_memory_regions[i].perms & UC_PROT_WRITE) ? XP_PROT_WRITE : 0;
		region.prot |= (uc_style_memory_regions[i].perms & UC_PROT_EXEC) ? XP_PROT_EXEC : 0;
		regions.push_back(region);
	}

	return regions;
}

bool ARMv7Machine::map_memory(mem_reg_t memory_region) {
	bool	 ret = true;
	uint32_t prot = 0;
	uc_err	 err;

	prot |= (memory_region.prot & XP_PROT_READ) ? UC_PROT_READ : 0;
	prot |= (memory_region.prot & XP_PROT_WRITE) ? UC_PROT_WRITE : 0;
	prot |= (memory_region.prot & XP_PROT_EXEC) ? UC_PROT_EXEC : 0;

	err = uc_mem_map(this->uc, memory_region.addr, memory_region.size, prot);

	if (err) {
		fprintf(stderr, "uc_mem_map failed: %u (%s)\n", err, uc_strerror(err));
		return false;
	}

	return ret;
}

int ARMv7Machine::find_memory_region(uint64_t addr) {
	std::vector<mem_reg_t> regions;
	int					   index = 0;

	regions = this->get_memory_regions();

	for (mem_reg_t& i : regions) {
		uint64_t start_addr = i.addr;
		uint64_t end_addr = i.addr + i.size;
		if (addr >= start_addr && addr < end_addr) {
			return index;
		}
		index++;
	}

	return -1;
}

bool ARMv7Machine::unmap_memory(mem_reg_t memory_region) {
	bool ret = true;

	ret = (uc_mem_unmap(this->uc, memory_region.addr, memory_region.size) == UC_ERR_OK) ? true : false;

	return ret;
}

bool ARMv7Machine::read_memory(uint64_t addr, uint8_t* data, uint64_t size) {
	bool ret = true;

	ret = (uc_mem_read(this->uc, addr, data, size) == UC_ERR_OK) ? true : false;

	return ret;
}

bool ARMv7Machine::write_memory(uint64_t addr, uint8_t* data, uint64_t size) {
	bool ret = true;

	ret = (uc_mem_write(this->uc, addr, data, size) == UC_ERR_OK) ? true : false;

	return ret;
}

bool ARMv7Machine::exec_code(uint64_t addr, uint64_t size) {
	bool ret = true;

	ret = (uc_emu_start(uc, addr, addr + size, 0, 0) == UC_ERR_OK) ? true : false;

	return ret;
}

bool ARMv7Machine::exec_code_ninsns(uint64_t addr, uint64_t num) {
	bool ret = true;

	ret = (uc_emu_start(uc, addr, 0xffffffffffffffffL, 0, num) == UC_ERR_OK) ? true : false;

	return ret;
}

bool ARMv7Machine::exec_code_step() {
	uint32_t val;
	bool	 ret = true;

	uc_reg_read(uc, UC_ARM_REG_PC, &val);

	ret = (uc_emu_start(uc, val, 0xffffffffffffffffL, 0, 1) == UC_ERR_OK) ? true : false;

	return ret;
}