// Written by Edness   2024-07-13 - 2024-10-08
#pragma once
#include <stdint.h>

#define print_err(msg) printf("\nERROR: %s", msg) // printf("\nERROR: " msg) also works but...


#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
    #define HELP_USAGE_IN "X:\\path\\to\\pack.pkd"
    #define HELP_USAGE_OUT "X:\\path\\to\\out_dir"
    #define PATH_LEN 259 // some testing shows it to be 259 not 260? (w/ null, so 258)
    #define PATH_SEP "\\"
    #include <windows.h>

    #define is_path_sep(c) c == '\\' || c == '/'
    #define create_dir(path) CreateDirectoryA(path, NULL)
    #define get_abspath(path, out) GetFullPathNameA(path, PATH_LEN, out, NULL)

    #define IS_WINDOWS 1

#elif defined(__unix__) || defined(__APPLE__)
    #define HELP_USAGE_IN "/path/to/pack.pkd"
    #define HELP_USAGE_OUT "/path/to/out_dir"
    #define PATH_LEN 0x1000
    #define PATH_SEP "/"
    #include <sys/stat.h>

    #define is_path_sep(c) c == '/'
    #define create_dir(path) mkdir(path, 0755)
    #define get_abspath(path, out) realpath(path, out) // i wish this was better
    // realpath apparently doesn't exist on osx, is there some native alternative?

    #define IS_POSIX 1

#endif
