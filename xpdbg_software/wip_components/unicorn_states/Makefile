CPP=clang++
CPPFLAGS=--std=c++17

all: bin/main
	#

create_folders:
	sh -c "rm -rf bin; mkdir bin; mkdir bin/armv7"

clean: create_folders

bin/main: bin/main.o
	${CPP} ${CPPFLAGS} -lcapstone -lunicorn $^ -o $@

bin/%.o: src/%.cc
	${CPP} ${CPPFLAGS} $< -c -o $@
