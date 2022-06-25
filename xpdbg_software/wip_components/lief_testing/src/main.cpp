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

	char* path_to_binary = (char*)"/bin/cat";

	unique_ptr<const LIEF::ELF::Binary> binary = unique_ptr<const LIEF::ELF::Binary>{ LIEF::ELF::Parser::parse(path_to_binary) };
	binary->functions();

	cout << "Binary: " << binary->name() << '\n';
	cout << "Interpreter: " << binary->interpreter() << '\n';
	cout << "== Header ==" << '\n';
	cout << binary->header() << '\n';
	cout << "== Sections ==" << '\n';
	for (const LIEF::ELF::Section& section : binary->sections()) {
		cout << section << '\n';
	}

	return 0;
}