// Written by Edness   2024-07-13 - 2025-12-12
#pragma once
#include <stdint.h>
#include <stdbool.h>

// not using T() (L"") because it can be either UTF-16 or UTF-32
#define u(text) u ## text // UTF-16 text (u""), only for Windows
#define MACRO(...) do { __VA_ARGS__ } while (false)
#define bswap(num) (num >> 24 | num >> 8 & 0xFF00 | (num & 0xFF00) << 8 | (num & 0xFF) << 24)
#define min(x, y) (x < y ? x : y) // C-only min() in stdlib.h doesn't exist on gcc/clang?
#define arrlen(arr) sizeof(arr) / sizeof(arr[0])

// the sizeof(arg) includes the null terminator so i don't need to +1 these here
#define is_opt_arg(arg, l_arg, s_arg) (!strncmp(arg, l_arg, sizeof(l_arg)) || !strncmp(arg, s_arg, sizeof(s_arg)))

// kinda ugly using %hs for windows here but whatever lol
#define print_err(msg) fprintf(stderr, "\n[ERROR] %s", msg) // ("\nERROR: " msg) also works but...
#define print_warn(msg) fprintf(stderr, "\n[WARNING] %s", msg) // ("\nWARNING: " msg)


// this used to be a lot cleaner at one point, but then I wanted "proper" Windows support
#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
    #define HELP_USAGE_IN "X:\\path\\to\\pack.pkd"
    #define HELP_USAGE_OUT "X:\\path\\to\\out_dir"
    // before reworking it to support windows wchar paths properly, i randomly
    // found out the max path len is actually 259 for the ascii funcs, not 260
    //#define PATH_LEN 260 // FILENAME_MAX is C standard unlike MAX_PATH / PATH_MAX
    #define PATH_SEP_C '\\'
    #define PATH_SEP_S "\\"
    #define STR "%hs"

    #define main wmain
    typedef uint16_t path_t;
    #include <windows.h>
    #include <fcntl.h>
    #include <conio.h>
    #include <io.h>

    #define is_path_sep(c) (c == '\\' || c == '/')
    #define fopen(path, mode) _wfopen(path, u(mode))
    #define fseek _fseeki64
    #define ftell _ftelli64
    #define create_dir(path) CreateDirectoryW(path, NULL)
    #define get_abspath(path, out) GetFullPathNameW(path, FILENAME_MAX, out, NULL)
    // this should be a MACRO() but i need the return value to know if it's too long.
    // the fact that it's named swprintf and not snwprintf or something alike is also
    // confusing, but it does in fact need the buffer size, unlike sprintf or wprintf
    // (microsoft has _snwprintf which doesn't null terminate for whatever reason...)
    #define printf(str, ...) wprintf(u(str), ##__VA_ARGS__) // mingw dies without ##?
    #define fprintf(f, str, ...) fwprintf(f, u(str), u(__VA_ARGS__))
    #define snprintf(out, len, str, ...) swprintf(out, len, u(str), __VA_ARGS__)
    #define strncmp(str, cmp, ...) wcsncmp(str, u(cmp), __VA_ARGS__)
    #define strnlen wcsnlen
    #define puts _putws
    //#define fputs fputws
    //#define perror _wperror
    //#define sscanf(str, fmt, ...) swscanf(str, u(fmt), __VA_ARGS__)

    #define IS_WINDOWS 1

#elif defined(__unix__) || defined(__APPLE__)
    #define HELP_USAGE_IN "/path/to/pack.pkd"
    #define HELP_USAGE_OUT "/path/to/out_dir"
    //#define PATH_LEN 0x1000 // 0x400 on OSX, using FILENAME_MAX
    #define PATH_SEP_C '/'
    #define PATH_SEP_S "/"
    #define STR "%s"

    //#define main main
    typedef char path_t; // clang was not happy about u/int8_t
    #include <sys/stat.h>

    #define is_path_sep(c) (c == '/')
    //#define fopen fopen
    #define fseek fseeko
    #define ftell ftello
    #define create_dir(path) mkdir(path, 0755)
    #define get_abspath realpath // i wish this was better
    // these identical redefs for consistency w/ the windows redefs don't
    // really harm anything, apart from osx having another snprintf redef
    // to __builtin___snprintf_chk in secure/_stdio.h (-Wmacro-redefined)
    //#define printf printf
    //#define fprintf fprintf
    //#define snprintf snprintf
    //#define strncmp strncmp
    //#define strnlen strnlen
    //#define puts puts
    //#define fputs fputs
    //#define perror perror
    ////#define sscanf sscanf

    #define IS_POSIX 1

#endif


#define ERR_ALLOC            "Failed to allocate memory!\n"

#define ERR_NO_ARGS          "Not enough arguments!\n"
#define ERR_BAD_ARGS         "Invalid argument: "
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

#define WARN_PKG_BAD_DRM_KS  "Failed to read PACKAGE keystore!\n"
#define WARN_PKG_KS_ENCRYPT  "PACKAGE keystores currently cannot be signed!\n"
#define WARN_PKG_BAD_DRMKEY  "Keystore PACKAGE key is invalid! Attempting common keys...\n"
