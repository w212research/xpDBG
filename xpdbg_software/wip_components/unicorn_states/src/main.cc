#include <unicorn/unicorn.h>
#include "macros.h"
#include "state.h"
#include "armv7.h"
#include <cstdio>

#define BASE_ADDY 0x0

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,						//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,			//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,			//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,			//	sub		r0,	r0,	r1
	0x01,0x44,						//	add		r1,	r1,	r0
};

armv7_state_change_t* states = NULL;

void hook_code(uc_engine*   uc,
			   uint64_t     address,
			   uint32_t     size,
			   void*        user_data) {
	uint32_t regs[16];

	for (int i = 0; i < len_of(armv7_regs); i++) {
		uc_reg_read(uc, armv7_regs[i], &regs[i]);
	}

	printf("Register all the things!\n");
	for (int i = 0; i < len_of(armv7_regs); i++) {
		uc_reg_read(uc, armv7_regs[i], &regs[i]);
		printf("%s:\t0x%08x\n", armv7_reg_string_normal[i], regs[i]);
	}

	getchar();
}

int main(int	argc,
		 char  *argv[]) {
	printf("Unicorn Testing...\n");
	uc_engine  *uc;
	uc_hook		hook1;
	uc_err		err;

	states = (armv7_state_change_t*)calloc(0x1000, sizeof(armv7_state_change_t));

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

	free(states);

	return 0;
}
