ifdef CPP
	# don't re-define
else
	CPP=g++
endif
CPPFLAGS=--std=c++17 `pkg-config gtkmm-3.0 --cflags`

all: bin/main
	#

create_folders:
	sh -c "rm -rf bin; mkdir bin"

clean: create_folders

bin/main: bin/main.o bin/logging.o bin/xpDBG_window.o
	${CPP} ${CPPFLAGS} `pkg-config gtkmm-3.0 --cflags --libs` $^ -o $@

bin/%.o: src/%.cc
	${CPP} ${CPPFLAGS} $< -c -o $@