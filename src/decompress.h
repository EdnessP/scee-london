// Written by Edness   2024-09-17 - 2024-09-28
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
// 0x8*0x408 (0x2040) is most likely safe, a max init 0x10 byte ERDA chunk likely won't give anything.
// UPDATE: upon further testing, ERDA decompression occasionally goes beyond 0x2040 (max known 0x23C9)
// seems to be caused by unaligned chunks, flushing the previous constant byte stream along a new one?
#define MAX_DEC_SIZE 0x4080

// PACKAGEs use CRC-32/JAMCRC for filename hashes, which just means the final output isn't NORed
// this is probably slower since mz_crc32 already returns it NORed per standard CRC-32, but meh.
// UPDATE: nope, it seems like compilers just inline this whole thing and omit the last NOR, lol
#define get_jamcrc_hash(buf, buf_len) ~(uint32_t)mz_crc32(MZ_CRC32_INIT, buf, buf_len - 1)

// snake_case miniz func defs because muh ocd /s
#define mz_inflate_init mz_inflateInit
//#define mz_inflate_reset mz_inflateReset
#define mz_inflate_end mz_inflateEnd


static char decompress_chunk(mz_stream *mz, uint8_t **buf, uint32_t *size) {
    //uint8_t *buf = *in_buf;
    //uint32_t size = *in_size;

    mz->next_in = *buf;
    mz->avail_in = *size;
    // the zlib streams have intentionally corrupt footers
    // by SCEE but those shouldn't raise these errors here
    if (mz_inflate(mz, MZ_NO_FLUSH) < MZ_OK) {
        print_err("Failed to decompress PACKAGE file data!\n");
        return -1;
    }
    if (!mz->avail_out) { // is this even possible?
        // mz_inflate will eventually fail at the end when i tested with
        // a small buffer, so maybe there is a proper way to handle this
        print_err("Out of decompressor buffer memory!\n");
        return -1;
    }
    //if (mz->avail_out == MAX_DEC_SIZE) return 0; // nothing to write
    // reset to the base of malloc'd block
    *size = MAX_DEC_SIZE - mz->avail_out;
    mz->avail_out = MAX_DEC_SIZE;
    mz->next_out -= *size;
    *buf = mz->next_out;

    return 0;
}
