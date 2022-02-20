#!/bin/bash

CPP=g++

rm -rf bin
mkdir bin
$CPP src/main.cc -lcapstone -o bin/main
