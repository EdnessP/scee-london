// Written by Edness   2024-07-13 - 2025-10-05
#pragma once
#include <stdint.h>
#include <stdbool.h>

// not using T() (L"") because it can be either UTF-16 or UTF-32
#define u(text) u ## text // UTF-16 text (u"")
#define MACRO(...) do { __VA_ARGS__ } while (false)
#define min(x, y) (x < y ? x : y) // C-only min() in stdlib.h doesn't exist on gcc/clang?

// the sizeof(arg) includes the null terminator so i don't need to +1 these here
#define is_opt_arg(arg, l_arg, s_arg) (!strncmp_path(arg, l_arg, sizeof(l_arg)) || !strncmp_path(arg, s_arg, sizeof(s_arg)))

#define print_err(msg) fprintf(stderr, "\nERROR: %s", msg) // ("\nERROR: " msg) also works but...
#define print_warn(msg) fprintf(stderr, "\nWARNING: %s", msg) // ("\nWARNING: " msg)


// this used to be a lot cleaner at one point, but then I wanted "proper" Windows support
#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
    #define HELP_USAGE_IN "X:\\path\\to\\pack.pkd"
    #define HELP_USAGE_OUT "X:\\path\\to\\out_dir"
    #define HELP_PATH_SEP "\\"
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
    #include <conio.h>

    #define is_path_sep(c) (c == '\\' || c == '/')
    #define fopen(path, mode) _wfopen(path, u(mode))
    #define fseek _fseeki64
    #define ftell _ftelli64
    #define create_dir(path) CreateDirectoryW(path, NULL)
    #define get_abspath(path, out) GetFullPathNameW(path, PATH_LEN, out, NULL)
    // this should be a MACRO() but i need the return value to know if it's too long.
    // the fact that it's named swprintf and not snwprintf or something alike is also
    // confusing, but it does in fact need the buffer size, unlike sprintf or wprintf
    // (microsoft has _snwprintf which doesn't null terminate for whatever reason...)
    #define snprintf_path(out, len, str, ...) swprintf(out, len, u(str), __VA_ARGS__)
    #define printf_path(str, ...) wprintf(u(str), __VA_ARGS__)
    #define strncmp_path(str, cmp, ...) wcsncmp(str, u(cmp), __VA_ARGS__)
    #define strnlen_path wcsnlen
    //#define sscanf_path(str, fmt, ...) swscanf(str, u(fmt), __VA_ARGS__)
    #define main wmain

    #define IS_WINDOWS 1

#elif defined(__unix__) || defined(__APPLE__)
    #define HELP_USAGE_IN "/path/to/pack.pkd"
    #define HELP_USAGE_OUT "/path/to/out_dir"
    #define HELP_PATH_SEP "/"
    #define PATH_LEN 0x1000
    #define PATH_SEP '/'
    #define PATH_JOIN "%s/%s"
    typedef char path_t; // clang was not happy about u/int8_t
    #include <sys/stat.h>

    #define is_path_sep(c) (c == '/')
    #define fopen fopen
    #define fseek fseeko
    #define ftell ftello
    #define create_dir(path) mkdir(path, 0755)
    #define get_abspath realpath // i wish this was better
    #define snprintf_path snprintf
    #define printf_path printf
    #define strncmp_path strncmp
    #define strnlen_path strnlen
    //#define sscanf_path sscanf
    #define main main

    #define IS_POSIX 1

#endif


#define ERR_ALLOC            "Failed to allocate memory!\n"

#define ERR_NO_ARGS          "Not enough arguments!\n"
#define ERR_BAD_ARGS         "Invalid arguments!\n"
#define ERR_BAD_ARG_DRMKEY   "Provided PACKAGE key is invalid!\n"
#define ERR_BAD_ARG_IN_FILE  "Failed to open the input file!\n"
#define ERR_BAD_ARG_OUT_PATH "Provided output path is invalid!\n"

#define ERR_PKG_KEY_UNKNOWN  "Failed to determine PACKAGE encryption key!\n"
#define ERR_PKG_BAD_CONFIG   "Invalid PACKAGE header configuration!\n"
#define ERR_PKG_BAD_NAME     "Failed to read PACKAGE file name!\n"
#define ERR_PKG_FILE_READ    "Failed to read PACKAGE file data!\n"
#define ERR_PKG_FILE_WRITE   "Failed to write output file data!\n"
#define ERR_PKG_PATH_LEN     "File output path is too long!\n"
#define ERR_PKG_FILE_OPEN    "Failed to open the output file! Is it in a read-only location?\n"

#define ERR_ZLIB_BAD_CONFIG  "Invalid compression header configuration!\n"
#define ERR_ZLIB_INIT        "Failed to initialise decompressor!\n"
#define ERR_ZLIB_DECOMPRESS  "Failed to decompress PACKAGE file data!\n"
#define ERR_ZLIB_MEMORY      "Out of decompressor buffer memory!\n"

#define WARN_PKG_BAD_DRMKEY  "Provided PACKAGE key is invalid! Attempting common keys...\n"
