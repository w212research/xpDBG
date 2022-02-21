#!/bin/bash

CC=gcc

rm -rf bin
mkdir bin
$CC -D_GNU_SOURCE src/main.c src/xpDBG_window.c src/logging.c -lcapstone `pkg-config gtk+-3.0 --cflags --libs` -o bin/main
