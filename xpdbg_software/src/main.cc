#include <capstone/capstone.h>
#include <cstdio>

uint8_t test_arm_thumb_code[] = {
	0x41,0x20,				//	movs	r0,	#0x41
	0x40,0xF2,0x20,0x40,	//	movw	r0,	#0x420
	0x40,0xF2,0x69,0x01,	//	movw	r1,	#0x69
	0xA0,0xEB,0x01,0x00,	//	sub		r0,	r0,	r1
	0x01,0x44,				//	add		r1,	r1,	r0
};

int main(int argc,
		 char* argv[]) {
	cs_insn	   *insn;
	size_t		count;
	csh			handle;
	int			i;

	/*
	 *  open capstone handle
	 *  CS_MODE_THUMB as this is thumb code
	 */
	cs_open(CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB),
			&handle);

	/*
	 *  disassemble it
	 */
	count = cs_disasm(handle,
					  test_arm_thumb_code,
					  sizeof(test_arm_thumb_code),
					  0x1000,
					  0,
					  &insn);

	/*
	 *  print it
	 */
	if (count > 0) {
		for (i = 0; i < count; i++) {
			printf("0x%016lx:\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
		}

		/*
		 * no memory leaks here, sir
		 */
		cs_free(insn, count);
	}

	/*
	 *  good little programmers, we are
	 */
	cs_close(&handle);

	return 0;
}
