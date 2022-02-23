#include <LIEF/LIEF.hpp>
#include <iostream>
#include <assert.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s [path to binary]\n", argv[0]);
		exit(-1);
	}

	char* path_to_binary = argv[1];
	FILE* fp = fopen(path_to_binary, "rb");

	assert(fp != NULL);

	return 0;
}