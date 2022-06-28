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

#include <cstdint>
#include <fstream>
#include <cstdio>
#include <vector>

using namespace std;

#define NORMAL_TEST_ELF_PATH "../../submodules/binary-samples/elf-Linux-x64-bash"
#define NORMAL_TEST_MACHO_PATH "../../submodules/binary-samples/MachO-OSX-x64-ls"

int main(int argc, char* argv[]) {
	ifstream f(NORMAL_TEST_ELF_PATH, ios::binary);
	vector<uint8_t> buf(istreambuf_iterator<char>(f), {});

	bool is_elf = false;

	f.close();

	return 0;
}