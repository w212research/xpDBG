CPP=clang++
CPPFLAGS=--std=c++17

all: bin bin/main

bin:
	sh -c "mkdir bin"

clean:
	rm -rf bin

bin/main: bin/main.o bin/XParse.o bin/ELF.o
	${CPP} ${CPPFLAGS} $^ -o $@

bin/%.o: src/%.cpp
	${CPP} ${CPPFLAGS} $< -c -o $@
