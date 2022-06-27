CPP=g++
CPPFLAGS=--std=c++17

all: bin bin/main

bin:
	sh -c "mkdir bin"

clean:
	rm -rf bin

bin/main: bin/main.o bin/ARMv7Machine.o
	${CPP} ${CPPFLAGS} -lLIEF -lkeystone -lunicorn -lcapstone $^ -o $@

bin/%.o: src/%.cpp
	${CPP} ${CPPFLAGS} $< -c -o $@
