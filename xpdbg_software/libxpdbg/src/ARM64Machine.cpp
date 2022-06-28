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
#include "ARM64Machine.hpp"
#include "libxpdbg.hpp"
#include <cstring>
#include <cstdio>

using namespace libxpdbg;

/*
 *  "normal" registers, contains the registers returned by get_registers.
 */
uc_arm64_reg normal_regs[] = {
	UC_ARM64_REG_X0,
	UC_ARM64_REG_X1,
	UC_ARM64_REG_X2,
	UC_ARM64_REG_X3,
	UC_ARM64_REG_X4,
	UC_ARM64_REG_X5,
	UC_ARM64_REG_X6,
	UC_ARM64_REG_X7,
	UC_ARM64_REG_X8,
	UC_ARM64_REG_X9,
	UC_ARM64_REG_X10,
	UC_ARM64_REG_X11,
	UC_ARM64_REG_X12,
	UC_ARM64_REG_X13,
	UC_ARM64_REG_X14,
	UC_ARM64_REG_X15,
	UC_ARM64_REG_X16,
	UC_ARM64_REG_X17,
	UC_ARM64_REG_X18,
	UC_ARM64_REG_X19,
	UC_ARM64_REG_X20,
	UC_ARM64_REG_X21,
	UC_ARM64_REG_X22,
	UC_ARM64_REG_X23,
	UC_ARM64_REG_X24,
	UC_ARM64_REG_X25,
	UC_ARM64_REG_X26,
	UC_ARM64_REG_X27,
	UC_ARM64_REG_X28,
	UC_ARM64_REG_FP,
	UC_ARM64_REG_SP,
	UC_ARM64_REG_PC,
};

ARM64Machine::ARM64Machine() {
	uc_err err;
	reg_t  reg;

	/*
	 *  open unicorn handle as thumb, that works for ARM code as well.
	 */
	err = uc_open(UC_ARCH_ARM64,
				  UC_MODE_ARM,
				  &this->uc);
	/*
	 *  create descriptions for all of the registers we intend to "publish"
	 */

	reg.reg_id = 0;

	reg.reg_description = "x0";
	reg.reg_name = "x0";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x1";
	reg.reg_name = "x1";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x2";
	reg.reg_name = "x2";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x3";
	reg.reg_name = "x3";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x4";
	reg.reg_name = "x4";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x5";
	reg.reg_name = "x5";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x6";
	reg.reg_name = "x6";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x7";
	reg.reg_name = "x7";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x8";
	reg.reg_name = "x8";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x9";
	reg.reg_name = "x9";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x10";
	reg.reg_name = "x10";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x11";
	reg.reg_name = "x11";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x12";
	reg.reg_name = "x12";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x13";
	reg.reg_name = "x13";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x14";
	reg.reg_name = "x14";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x15";
	reg.reg_name = "x15";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x16";
	reg.reg_name = "x16";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x17";
	reg.reg_name = "x17";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x18";
	reg.reg_name = "x18";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x19";
	reg.reg_name = "x19";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x20";
	reg.reg_name = "x20";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x21";
	reg.reg_name = "x21";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x22";
	reg.reg_name = "x22";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x23";
	reg.reg_name = "x23";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x24";
	reg.reg_name = "x24";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x25";
	reg.reg_name = "x25";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x26";
	reg.reg_name = "x26";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x27";
	reg.reg_name = "x27";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "x28";
	reg.reg_name = "x28";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "fp";
	reg.reg_name = "fp";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "sp";
	reg.reg_name = "sp";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	reg.reg_description = "pc";
	reg.reg_name = "pc";
	reg.reg_id++;
	reg.reg_value = 0;
	
	this->registers.push_back(reg);

	/*
	 *  open capstone handles for ARM64 code.
	 */
	cs_open(CS_ARCH_ARM64,
			(cs_mode)(CS_MODE_ARM),
			&handle);
}