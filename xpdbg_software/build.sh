#!/bin/bash

CPP=g++

rm -rf bin
mkdir bin
$CPP src/main.cc -lcapstone `pkg-config --cflags --libs gtk+-3.0` -o bin/main
