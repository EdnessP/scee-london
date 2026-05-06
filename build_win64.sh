#!/usr/bin/env bash

mkdir -p ./out/win64
# x86_64-w64-mingw32-gcc generates a very bloated .exe using msvcrt
# because it statically compiles a whole bunch of kernel functions,
# so check for x86_64-w64-mingw32ucrt-gcc availability first (ucrt)
# although msvc builds are still smaller and (very slightly) faster
if command -v x86_64-w64-mingw32ucrt-gcc; then
    # for ubuntu wsl ucrt mingw needs to be manually setup
    # https://packages.debian.org/sid/gcc-mingw-w64-ucrt64
    mingw=x86_64-w64-mingw32ucrt-gcc
else
    # and bc ubuntu 24.04 apt mingw is too old for ucrt64's deps
    # https://packages.debian.org/sid/gcc-mingw-w64-x86-64-win32
    mingw=x86_64-w64-mingw32-gcc
fi
# the equivalent of setting that variable to %BUILDDATE% for building natively on Windows, because date /t is bad:
# for /f "tokens=* USEBACKQ" %%f in (`python -c "print(__import__('datetime').datetime.now().strftime('%%Y-%%m-%%d'))"`) do set BUILDDATE=%%f
# or on PowerShell, which is what Visual Studio also utilises: $([System.DateTime]::UtcNow.ToString("yyyy-MM-dd"))
$mingw -s -DBUILDDATE="\"$(date -u +%Y-%m-%d)\"" -DNDEBUG -municode -Ofast -flto -o ./out/win64/scee_london.exe ./src/scee_london.c
printf "Done! Output written to %s\n" $(realpath "./out/win64")
