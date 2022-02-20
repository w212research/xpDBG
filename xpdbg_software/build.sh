#!/bin/bash

CPP=g++

rm -rf bin
mkdir bin
$CPP src/main.cc src/xpDBG_window.cc src/logging.cc -lcapstone `pkg-config gtkmm-3.0 --cflags --libs` -o bin/main
