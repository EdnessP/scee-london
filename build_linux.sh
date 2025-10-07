#!/usr/bin/env bash

mkdir -p ./out/linux
gcc -s -DNDEBUG -Ofast -flto -o ./out/linux/scee_london ./src/scee_london.c
# there is some known rare oddball case with a custom .PKF file that causes
# stack smashing to be detected after exiting main() if compiled with -flto
# (small single byte zlib stream whose last byte is outside the init chunk)
printf "Done! Output written to %s\n" $(realpath "./out/linux")
