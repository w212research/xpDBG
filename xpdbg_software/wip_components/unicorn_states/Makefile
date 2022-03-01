CPP=clang++
CPPFLAGS=--std=c++17

all: bin bin/main

bin:
	sh -c "mkdir bin"

clean:
	rm -rf bin

bin/main: bin/main.o
	${CPP} ${CPPFLAGS} -lcapstone -lunicorn $^ -o $@

bin/%.o: src/%.cc
	${CPP} ${CPPFLAGS} $< -c -o $@
