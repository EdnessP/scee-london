// Written by Edness   2024-07-29 - 2024-10-19
#pragma once
#include <stdint.h>

#define NAME_LEN 0x100


//////////////////
// FILE READERS //
//////////////////

union {
    uint64_t xor;
    uint8_t buf[8];
} pkd = {0};


static inline char read_chunk(FILE *file, const uint8_t size, const int8_t encrypted, const uint32_t iv, const uint32_t *key) {

    if (!fread(pkd.buf, size, 1, file)) {
        print_err("Failed to read PACKAGE file data!\n");
        return -1;
    }
    if (encrypted)
        pkd.xor ^= get_xtea_xor_key(iv, key);

    return 0;
}


static inline char write_chunk(FILE *file, uint8_t *buf, uint32_t size, const int8_t compressed, mz_stream *mz) {

    if (compressed) {
        if (decompress_chunk(mz, &buf, &size))
            return -1;
        if (!size) return 0; // nothing to write
    }
    if (!fwrite(buf, size, 1, file)) {
        print_err("Failed to write output file data!\n");
        return -1;
    }

    return 0;
}


////////////////////
// BUFFER READERS //
////////////////////

// null-terminated string
static inline int32_t read_str(const uint8_t *buf, uint32_t offs, uint8_t *dst) {

    for (int i = 0; i < NAME_LEN; i++) {
        // should always be lowercase and backslashed (normalised to hash)
        // but allowing the full valid ASCII range just in case to be safe
        if ((buf[offs] > 0x00 && buf[offs] < 0x20) || buf[offs] > 0x7E)
            return -1;
        dst[i] = buf[offs];
        if (!buf[offs++]) return ++i;
    }
    //dst[NAME_LEN - 1] = '\x00';
    return -1;
}


// 32-bit little endian integer (unaligned reads lol)
static inline int32_t read_32le(const uint8_t *buf, const uint32_t offs) {
    return *(int32_t *)&buf[offs];
}


// 32-bit big endian integer
static inline int32_t read_32be(const uint8_t *buf, const uint32_t offs) {
    return buf[offs] << 24 | buf[offs + 1] << 16 | buf[offs + 2] << 8 | buf[offs + 3];
}


// 16-bit big endian integer
static inline int16_t read_16be(const uint8_t *buf, const uint32_t offs) {
    return buf[offs] << 8 | buf[offs + 1];
}


// variable big endian integer (should probs just have it call 32/64-bit reads directly)
static inline int64_t read_be(const uint8_t *buf, uint32_t offs, const uint8_t size) {
    int64_t val = 0;

    for (int i = 0; i < size; i++) {
        val <<= 8;
        val |= buf[offs++];
    }

    return val;
}
