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

#ifndef ARMV7_H
#define ARMV7_H

uint32_t armv7_regs[] = {
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

const char* armv7_reg_string_raw[] {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
};

const char* armv7_reg_string_normal[] {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"fp",
	"ip",
	"sp",
	"lr",
	"pc",
};

#endif
