/*
 *  half stolen from https://github.com/lief-project/LIEF/blob/master/examples/cpp/elf_reader.cpp
 */

#include <LIEF/LIEF.hpp>
#include <iostream>
#include <assert.h>
#include <stdio.h>
#include <memory>

using namespace std;

int main(int argc, char* argv[]) {
#if 0
	if (argc < 2) {
		fprintf(stderr, "usage: %s [path to binary]\n", argv[0]);
		exit(-1);
	}
#endif

	char* path_to_binary = "/bin/cat";

	unique_ptr<const Binary> binary = unique_ptr<const Binary>{ Parser::parse(path_to_binary) };
	binary->functions();

	printf("Binary: %s\n", binary->name().c_str());
	printf("Interpreter: %s\n", binary->interpreter().c_str());
	printf("== Header ==\n");
	printf("%s\n", binary.header().c_str());

	return 0;
}