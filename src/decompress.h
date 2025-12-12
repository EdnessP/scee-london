// Written by Edness   2024-09-17 - 2025-10-08
#pragma once
#include <stdint.h>
#include <stdbool.h>

//#if defined(__APPLE__)
//    #include <zlib.h>
//#else
    #define MINIZ_NO_ARCHIVE_APIS
    #define MINIZ_NO_ARCHIVE_WRITING_APIS
    #define MINIZ_NO_DEFLATE_APIS
    #define MINIZ_NO_STDIO
    #define MINIZ_NO_TIME

    #define MINIZ_HAS_64BIT_REGISTERS 1
    #define MINIZ_LITTLE_ENDIAN 1
    #if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || defined(_M_AMD64)
        #define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 1
    #endif

    #include "miniz/miniz.h"
    #include "miniz/miniz.c"
//#endif


// extreme upper bound - 0x10*0x408, per Mark Adler here https://stackoverflow.com/questions/26922482/
// 0x8*0x408 (0x2040) is most likely safe, a max init 0x10 byte ERDA chunk likely won't give anything.
// UPDATE: upon further testing, ERDA decompression occasionally goes beyond 0x2040 (max known 0x23C9)
// seems to be caused by unaligned chunks, flushing the previous constant byte stream along a new one?
#define MAX_DEC_SIZE 0x4080

// snake_case zlib func defs because muh ocd /s
#define inflate_init inflateInit
//#define inflate_reset inflateReset
#define inflate_end inflateEnd


static bool decompress_chunk(z_stream *mz, uint8_t **buf, uint32_t *size) {
    //uint8_t *buf = *in_buf;
    //uint32_t size = *in_size;

    mz->next_in = *buf;
    mz->avail_in = *size;
    // the zlib streams have intentionally corrupt footers
    // by SCEE but those shouldn't raise these errors here
    if (inflate(mz, Z_NO_FLUSH) < Z_OK) {
        print_err(ERR_ZLIB_DECOMPRESS);
        return false;
    }
    if (!mz->avail_out) { // is this even possible?
        // mz_inflate will eventually fail at the end when i tested with
        // a small buffer, so maybe there is a proper way to handle this
        print_err(ERR_ZLIB_MEMORY);
        return false;
    }
    //if (mz->avail_out == MAX_DEC_SIZE) return 0; // nothing to write
    // reset to the base of malloc'd block, and point to unpacked data
    *size = MAX_DEC_SIZE - mz->avail_out;
    mz->avail_out = MAX_DEC_SIZE;
    mz->next_out -= *size;
    *buf = mz->next_out;

    return true;
}
