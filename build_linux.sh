#!/usr/bin/env bash

mkdir -p ./out/linux

if [[ $1 == clang ]]; then
    build=clang
else
    build=gcc
fi
# all of the functions I use require glibc between 2.2.5 and 2.14,
# it's only the __libc_start_main entrypoint which bumps it way up
# and since the Windows (ucrt) build should work from Vista up and
# macOS build should be OSX 10.6 or newer, why not do it here too.

# https://github.com/AmanoTeam/obggcc/releases/latest/download/x86_64-unknown-linux-gnu.tar.xz
# minimal extraction (to ~/) if you don't want to unpack the entire thing (2.5GB decompressed)
# tar -C ~/ -xvf x86_64-unknown-linux-gnu.tar.xz obggcc/include obggcc/lib obggcc/x86_64-unknown-linux-gnu obggcc/x86_64-unknown-linux-gnu2.15
# for gcc, technically only obggcc/x86_64-unknown-linux-gnu2.15
# is needed despite that it'd have a ton of unresolved symlinks
obggcc=~/obggcc/x86_64-unknown-linux-gnu2.15
# __libc_start_main in 2.15 is 2.2.5 anyway
if [ -d $obggcc ]; then
    # gcc also technically doesn't need sysroot overriden
    sysroot=--sysroot=$obggcc
    export CPATH=$obggcc/include
    export LIBRARY_PATH=$obggcc/lib
    # ignore all this, I thought obggcc wasn't working with
    # clang, but I just didn't extract everything it needed
    #if [[ $1 == clang ]] && [ ! -d $obggcc/usr ]; then
    #    mkdir -p $obggcc/usr
    #    ln -s $obggcc/include $obggcc/usr/include
    #    ln -s $obggcc/lib $obggcc/usr/lib
    #fi
fi

$build -s $sysroot -DBUILDDATE="\"$(date -u +%Y-%m-%d)\"" -DNDEBUG -Ofast -flto -o ./out/linux/scee_london ./src/scee_london.c
# there is some known rare oddball case with a custom .PKF file that causes
# stack smashing to be detected after exiting main() if compiled with -flto
# (small single byte zlib stream whose last byte is outside the init chunk)
printf "Done! Output written to %s\n" $(realpath "./out/linux")
