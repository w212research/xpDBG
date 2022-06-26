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
#include <LIEF/LIEF.hpp>
#include "libxpdbg.hpp"
#include <cstdio>
#include <vector>

using namespace std;

#define BASE_ADDY 0x0

uc_engine* uc_global;

class Base {
public:
	virtual void print() = 0;
};

class Test1 : public Base {
	public:
		void print() {
			this->str1 = "Hello, world! str1";
			printf("%s\n", this->str1);
		}
	protected:
		char* str1;
};

class Test2 : public Base {
	public:
		void print() {
			this->str2 = "Hello, world! str2";
			printf("%s\n", this->str2);
		}
	protected:
		char* str2;
};

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

//	libxpdbg::Machine machine;

//	machine.hello();

/*
	Test1 test1;
	Test2 test2;

	test1.print();
	test2.print();
	*/

	libxpdbg::ARMv7Machine armv7_machine;

	vector<libxpdbg::mem_reg_t> memory_regions = armv7_machine.get_memory_regions();
	for (libxpdbg::mem_reg_t& i : memory_regions) {
		printf("%lx %lx %lx\n", i.addr, i.size, i.prot);
	}

	libxpdbg::mem_reg_t region;

	region.addr = 0x0;
	region.size = 0x10000;
	region.prot = XP_PROT_READ | XP_PROT_WRITE | XP_PROT_EXEC;

	printf("map\n");
	armv7_machine.map_memory(region);

	memory_regions = armv7_machine.get_memory_regions();
	for (libxpdbg::mem_reg_t& i : memory_regions) {
		printf("%lx %lx %lx\n", i.addr, i.size, i.prot);
	}

	region.addr = 0x0;
	region.size = 0x7777;
	region.prot = XP_PROT_READ | XP_PROT_WRITE | XP_PROT_EXEC;

	printf("map\n");
	armv7_machine.map_memory(region);

	memory_regions = armv7_machine.get_memory_regions();
	for (libxpdbg::mem_reg_t& i : memory_regions) {
		printf("%lx %lx %lx\n", i.addr, i.size, i.prot);
	}

	region.addr = 0x20000;
	region.size = 0x10000;

	printf("map\n");
	armv7_machine.map_memory(region);

	memory_regions = armv7_machine.get_memory_regions();
	for (libxpdbg::mem_reg_t& i : memory_regions) {
		printf("%lx %lx %lx\n", i.addr, i.size, i.prot);
	}

	region.addr = 0x8000;
	region.size = 0x8000;
	printf("unmap\n");
	armv7_machine.unmap_memory(region);

	memory_regions = armv7_machine.get_memory_regions();
	for (libxpdbg::mem_reg_t& i : memory_regions) {
		printf("%lx %lx %lx\n", i.addr, i.size, i.prot);
	}

	return 0;
}