// Written by Edness   2024-07-29 - 2025-10-05
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define NAME_LEN 0x100
#define BUF_SIZE 0x8

typedef struct {
    FILE *fp_in;
    FILE *fp_out;

    bool encrypted;
    uint32_t const *key;
    uint32_t iv;

    bool compressed;
    mz_stream *mz;

    union {
        uint64_t xor;
        uint8_t buf[BUF_SIZE];
    };
} pkg_t;

typedef union {
    uint64_t *i;
    uint8_t *c;
} buf_t;


//////////////////
// FILE READERS //
//////////////////

static inline bool read_chunk(pkg_t *pkg, uint8_t *buf, const uint8_t size) {

    if (!fread(buf, size, 1, pkg->fp_in)) {
        print_err(ERR_PKG_FILE_READ);
        return false;
    }
    if (pkg->encrypted)
        pkg->xor ^= get_xtea_xor_key(pkg->iv, pkg->key);

    return true;
}


static inline bool write_chunk(pkg_t *pkg, uint8_t *buf, uint32_t size) {

    if (pkg->compressed) {
        if (!decompress_chunk(pkg->mz, &buf, &size))
            return false;
        if (!size) return true; // nothing to write
    }
    if (!fwrite(buf, size, 1, pkg->fp_out)) {
        print_err(ERR_PKG_FILE_WRITE);
        return false;
    }

    return true;
}


// read chunks to buffer; if buf is nonexistent, write to fp_out
#define write_buffer(pkg, offs, size) read_buffer(pkg, NULL, offs, size)

#define __read_write_buffer(pkg_buf, size) MACRO ( \
    if (!read_chunk(pkg, pkg_buf, size)) return false; \
    if (buf) buf[i++] = pkg->xor; \
    else if (!write_chunk(pkg, pkg_buf, size)) return false; \
)

static bool read_buffer(pkg_t* pkg, uint64_t* buf, uint64_t offs, uint64_t size) {
    uint8_t start_skip, start_read, end_read;
    uint32_t /*start_chunk,*/ end_chunk;
    uint64_t /*start_offs,*/ end_offs;
    int i = 0;

    // file is empty
    if (!size) return true;


    start_skip = offs & 0x7;
    //start_offs = offs - start_skip;
    start_read = 0x8 - start_skip;

    end_offs = offs + size;
    end_read = end_offs & 0x7;
    // not aligning end offset, because it will be outside of the loop

    end_chunk = end_offs >> 3;
    pkg->iv = offs >> 3; // start_chunk

    // i cba to deal with non-standardized 64-bit seeks
    //fsetpos(pkg->fp_in, (fpos_t *)&start_offs);
    fseek(pkg->fp_in, offs, SEEK_SET);


    //if (!read_chunk(pkg, pkg->buf, BUF_SIZE)) return false;
    //if (!write_chunk(pkg, pkg->buf, BUF_SIZE)) return false;
    //if (buf) buf[i++] = pkg->xor;

    // file is small enough to fit in a single chunk
    if (size <= start_read) {
        __read_write_buffer(&pkg->buf[start_skip], size);
        return true;
    }

    // unaligned start chunk
    if (start_skip) {
        __read_write_buffer(&pkg->buf[start_skip], start_read);
        pkg->iv++;
    }

    // aligned main chunks
    for (; pkg->iv < end_chunk; pkg->iv++)
        __read_write_buffer(pkg->buf, BUF_SIZE);

    // unaligned end chunk
    if (end_read)
        __read_write_buffer(pkg->buf, end_read);

    return true;
}


////////////////////
// BUFFER READERS //
////////////////////

// null-terminated string
static inline int32_t read_str(uint8_t *buf, uint32_t *offs, uint8_t **dst) {
    *dst = &buf[*offs]; // no need to copy, just point to it

    for (int i = 0; i < NAME_LEN; i++) {
        // should always be lowercase and backslashed (normalised to hash)
        // but allowing the full valid ASCII range just in case to be safe
        if ((buf[*offs] > 0x00 && buf[*offs] < 0x20) || buf[*offs] > 0x7E)
            return -1;
        //dst[i] = buf[offs];
        if (!buf[(*offs)++]) return i; // read but not count the null char
    }
    //dst[NAME_LEN - 1] = '\x00';
    return -1;
}


// 32-bit little endian integer
static inline int32_t get_32le(const uint8_t *buf, const uint32_t offs) {
    //return *(int32_t *)&buf[offs]; // causes clang to infinite loop elsewhere w/ -O2
    // or read from undefined memory addresses on older versions because the buffer is
    // accessed either as uint8_t or uint64_t, throwing int32_t into the mix kills it.
    return buf[offs] | buf[offs + 1] << 8 | buf[offs + 2] << 16 | buf[offs + 3] << 24;
}

static inline int32_t read_32le(const uint8_t *buf, uint32_t *offs) {
    int32_t val = get_32le(buf, *offs);
    *offs += 0x4;
    return val;
}


// 32-bit big endian integer
static inline int32_t get_32be(const uint8_t *buf, const uint32_t offs) {
    return buf[offs] << 24 | buf[offs + 1] << 16 | buf[offs + 2] << 8 | buf[offs + 3];
}

static inline int32_t read_32be(const uint8_t *buf, uint32_t *offs) {
    uint32_t val = get_32be(buf, *offs);
    *offs += 0x4;
    return val;
}


// 16-bit big endian integer
static inline int16_t get_16be(const uint8_t *buf, const uint32_t offs) {
    return buf[offs] << 8 | buf[offs + 1];
}

static inline int16_t read_16be(const uint8_t *buf, uint32_t *offs) {
    int16_t val = get_16be(buf, *offs);
    *offs += 0x2;
    return val;
}


// variable big endian integer (should probs just have it call 32/64-bit reads directly)
static inline int64_t get_be(const uint8_t *buf, uint32_t offs, const uint8_t size) {
    int64_t val = 0;

    for (int i = 0; i < size; i++) {
        val <<= 8;
        val |= buf[offs++];
    }

    return val;
}

static inline int64_t read_be(const uint8_t *buf, uint32_t *offs, const uint8_t size) {
    int64_t val = get_be(buf, *offs, size);
    *offs += size;
    return val;
}
