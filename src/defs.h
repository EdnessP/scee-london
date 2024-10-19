// Written by Edness   2024-07-13 - 2024-10-19
#pragma once
#include <stdint.h>

#define u(text) u ## text // UTF-16 text (u"")
//#define MACRO(...) do { __VA_ARGS__; } while (0)

#define print_err(msg) printf("\nERROR: %s", msg) // printf("\nERROR: " msg) also works but...


// this used to be a lot cleaner at one point, but then I wanted "proper" Windows support
#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
    #define HELP_USAGE_IN "X:\\path\\to\\pack.pkd"
    #define HELP_USAGE_OUT "X:\\path\\to\\out_dir"
    // before reworking it to support windows wchar paths properly, i randomly
    // found out the max path len is actually 259 for the ascii funcs, not 260
    #define PATH_LEN 260
    #define PATH_SEP '\\'
    // string literals with different character kinds cannot be concatenated :nerd:
    // otherwise i would've just kept it as `"%s" PATH_SEP "%s"` but oh well
    // the u() macro expands it into `u"%s" "\\" "%s"` before concatenating.
    #define PATH_JOIN "%s\\%hs"
    typedef uint16_t path_t;
    #include <windows.h>

    #define is_path_sep(c) (c == '\\' || c == '/')
    #define fopen(path, mode) _wfopen(path, u(mode))
    #define create_dir(path) CreateDirectoryW(path, NULL)
    #define get_abspath(path, out) GetFullPathNameW(path, PATH_LEN, out, NULL)
    // this should be a MACRO() but i need the return value to know if it's too long.
    // the fact that it's named swprintf and not snwprintf or something alike is also
    // confusing, but it does in fact need the buffer size, unlike sprintf or wprintf
    // (microsoft has _snwprintf which doesn't null terminate for whatever reason...)
    #define snprintf_path(out, len, str, ...) swprintf(out, len, u(str), __VA_ARGS__)
    #define printf_path(str, ...) wprintf(u(str), __VA_ARGS__)
    #define main wmain

    #define IS_WINDOWS 1

#elif defined(__unix__) // || defined(__APPLE__)
    #define HELP_USAGE_IN "/path/to/pack.pkd"
    #define HELP_USAGE_OUT "/path/to/out_dir"
    #define PATH_LEN 0x1000
    #define PATH_SEP '/'
    #define PATH_JOIN "%s/%s"
    typedef char path_t; // clang was not happy about u/int8_t
    #include <sys/stat.h>

    #define is_path_sep(c) (c == '/')
    #define fopen fopen
    #define create_dir(path) mkdir(path, 0755)
    #define get_abspath realpath // i wish this was better
    #define snprintf_path snprintf
    #define printf_path printf
    #define main main

    #define IS_POSIX 1

#endif
