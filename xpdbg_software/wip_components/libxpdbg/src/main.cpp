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