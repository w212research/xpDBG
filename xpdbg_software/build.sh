#!/bin/bash

CC=gcc

rm -rf bin
mkdir bin
$CC src/main.c -o bin/main
