#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <LIEF/LIEF.hpp>
#include <cstdio>

#define BASE_ADDY 0x0

uc_engine* uc_global;

int main(int argc, char* argv[]) {
	uc_err err;

	err = uc_open(UC_ARCH_ARM,
				  UC_MODE_THUMB,
				  &uc_global);

	if (err) {
		printf("Failed on uc_open() with error returned: %u (%s)\n",
			   err,
			   uc_strerror(err));
		return -1;
	}

	uc_mem_map(uc_global, BASE_ADDY, 0x100000, UC_PROT_ALL);

	uc_close(uc_global);

	return 0;
}