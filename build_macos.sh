#!/usr/bin/env bash

if [[ $1 == darling ]]; then # building from linux (see build_all.sh)
    # point to the Xcode libs, xcode-select doesn't properly work with the full version
    xcode_lib=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
    xcode_bin=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain
    sysroot=--sysroot=$xcode_lib
    export CPATH=$xcode_lib/usr/include
    export LIBRARY_PATH=$xcode_lib/usr/lib
    #if ! [[ "$PATH" == ?(*:)"$xcode_bin"?(:*) ]]; then
    export PATH=$xcode_bin/usr/bin:$PATH
    #fi
fi
mkdir -p ./out/macos
# "ld: warning: option -s is obsolete and being ignored"
# except it isn't ignored and clearly does strip symbols
# even though codegen was virtually identical between 10.6 and 10.16 (11)
# building without macosx-version-min gave Illegal instruction: 4 on 10.7
clang -arch arm64 -arch x86_64 -s $sysroot -DBUILDDATE="\"$(date -u +%Y-%m-%d)\"" -DNDEBUG -Ofast -flto -mmacosx-version-min=10.6 -o ./out/macos/scee_london ./src/scee_london.c
if [[ $1 != darling ]]; then
    echo "Done! Output written to ./out/macos" # $(realpath "./out/macos")
fi
