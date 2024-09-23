// Written by Edness   2024-07-29 - 2024-09-23
#pragma once
#include <stdint.h>

#define NAME_LEN 0x100


union {
    uint64_t xor;
    uint8_t buf[8];
} pkd = {0};


/****************/
/* FILE READERS */
/****************/

static inline char read_chunk(FILE *in_file, const uint8_t read, const int8_t encrypted, const uint32_t iv, const uint32_t key) {

    if (!fread(pkd.buf, read, 1, in_file)) {
        printf("Failed to read PACKAGE file data!\n");
        return -1;
    }
    if (encrypted)
        pkd.xor ^= get_xtea_xor_key(iv, keys[key]);

    return 0;
}


static inline char write_chunk(FILE *out_file, uint8_t *buf, uint32_t buf_size, const int8_t compressed, mz_streamp mz, uint8_t *mz_buf) {

    if (compressed) {
        // this bit is kinda horrible i think, pending rewrite maybe
        mz->next_in = buf;
        mz->avail_in = buf_size;
        // the zlib streams have intentionally corrupt footers
        // by SCEE but those shouldn't raise these errors here
        if (mz_inflate(mz, 0) < 0) {
            printf("Failed to decompress PACKAGE file data!\n");
            return -1;
        }
        if (mz->avail_out == MAX_DEC_SIZE)
            return 0; // nothing to write
        buf = mz_buf;
        buf_size = MAX_DEC_SIZE - mz->avail_out;
        mz->next_out = mz_buf;
        mz->avail_out = MAX_DEC_SIZE;
    }
    if (!fwrite(buf, buf_size, 1, out_file)) {
        printf("Failed to write output file data!\n");
        return -1;
    }

    return 0;
}


/******************/
/* BUFFER READERS */
/******************/

// null-terminated string
static int32_t read_str(const uint8_t *buf, uint32_t offs, char *dst) {
    //do {} while (buf[offs]);
    for (int i = 0; i < NAME_LEN; i++) { // should be always ASCII i think
        if ((buf[offs] > 0x00 && buf[offs] < 0x20) || buf[offs] > 0x7E) return -1;
        dst[i] = buf[offs];
        if (!buf[offs++]) return ++i;
    }
    //dst[NAME_LEN - 1] = '\x00';
    return -1;
}


// 32-bit little endian integer
static int32_t read_32le(const uint8_t *buf, const uint32_t offs) {
    return *(uint32_t *)&buf[offs];
}


// 32-bit big endian integer
static int32_t read_32be(const uint8_t *buf, uint32_t offs) {
    uint32_t val = 0;

    for (int i = 0; i < 4; i++) {
        val <<= 8;
        val |= buf[offs++];
    }

    return val;
}


// 16-bit big endian integer
static int16_t read_16be(const uint8_t *buf, const uint32_t offs) {
    return buf[offs] << 8 | buf[offs + 1];
}


// variable big endian integer
static int64_t read_be(const uint8_t *buf, uint32_t offs, const uint8_t size) {
    uint64_t val = 0;

    for (int i = 0; i < size; i++) {
        val <<= 8;
        val |= buf[offs++];
    }

    return val;
}
