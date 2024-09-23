// Written by Edness   2024-09-17 - 2024-09-23
#pragma once
#include <stdint.h>

#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME

#define MINIZ_HAS_64BIT_REGISTERS 1
#define MINIZ_LITTLE_ENDIAN 1
#define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 1

#include "miniz/miniz.h"
#include "miniz/miniz.c"


// extreme upper bound - 0x10*0x408, per https://stackoverflow.com/questions/26922482/
#define MAX_DEC_SIZE 0x4080

// PACKAGEs use CRC-32/JAMCRC for filename hashes, which just means the final output isn't NORed
// this is probably slower since mz_crc32 already returns it NORed per standard CRC-32, but meh.
// Update: nope, it seems like compilers just inline this whole thing and omit the last NOR, lol
#define get_jamcrc(buf, buf_len) ~(uint32_t)mz_crc32(MZ_CRC32_INIT, buf, buf_len - 1)

// snake_case miniz func defs because muh ocd /s
#define mz_inflate_init mz_inflateInit
//#define mz_inflate_reset mz_inflateReset
#define mz_inflate_end mz_inflateEnd
