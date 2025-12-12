#!/usr/bin/env bash

if ! [[ $1 == msvc ]]; then
    # if not called from a visual studio post-build event
    ./build_win64.sh
fi
./build_linux.sh
if command -v darling; then
    # build and install Darling https://github.com/darlinghq/darling
    # extract Xcode 12.5.1 https://github.com/bitcoin-core/apple-sdk-tools
    # because the version xcode-select --install gives is too old (9.0.0)
    # one upside of v9 is it generates significantly less empty space though
    darling shell ./build_osx.sh darling
    printf "Done! Output written to %s\n" $(realpath "./out/macos")
fi
#echo Done! Output written to
cp -p ./readme.txt ./out
python3 -c '__import__("shutil").make_archive("scee_london", "zip", "./out")'
printf "Done! Packaged output to %s\n" $(realpath "./scee_london.zip")
