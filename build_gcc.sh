#!/bin/sh

mkdir -p ./out/linux
gcc -s -Ofast -flto -o ./out/linux/scee_london.elf ./src/scee_london.c
