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

#include <unicorn/unicorn.h>
#include <cstdio>

#define BASE_ADDY 0x0

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

void hook_code(uc_engine   *uc,
			   uint64_t		address,
			   uint32_t		size,
			   void		   *user_data) {
	uint32_t regs[16];

	int i = 0;
	uc_reg_read(uc, UC_ARM_REG_R0, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R1, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R2, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R3, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R4, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R5, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R6, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R7, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R8, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R9, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R10, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R11, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R12, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R13, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R14, &regs[i++]);
	uc_reg_read(uc, UC_ARM_REG_R15, &regs[i++]);

	i = 0;

	printf("Register all the things!\n");
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	printf("0x%08x\n", regs[i++]);
	getchar();
}

int main(int	argc,
		 char  *argv[]) {
	printf("Unicorn Testing...\n");
	uc_engine  *uc;
	uc_hook		hook1;
	uc_err		err;

	err = uc_open(UC_ARCH_ARM,
				  UC_MODE_THUMB,
				  &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
			   err,
               uc_strerror(err));
        return -1;
    }

	uc_mem_map(uc, BASE_ADDY, 0x100000, UC_PROT_ALL);
	uc_mem_write(uc, BASE_ADDY, test_arm_thumb_code, sizeof(test_arm_thumb_code));

	uc_hook_add(uc, &hook1, UC_HOOK_CODE, (void*)hook_code, NULL, BASE_ADDY, BASE_ADDY + sizeof(test_arm_thumb_code));

	err = uc_emu_start(uc, BASE_ADDY | 1, BASE_ADDY + sizeof(test_arm_thumb_code), 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned: %u\n",
			   err);
	}

    uc_close(uc);

	return 0;
}
