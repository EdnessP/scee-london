// Written by Edness   2024-09-17 - 2026-05-09
#ifndef _HASH_H_
#define _HASH_H_
#include <stdint.h>
#include <stdbool.h>
#include "defs.h"
#include "decompress.h"

// PACKAGEs use CRC-32/JAMCRC for filename hashes, which just means the final output isn't NOT'd
// this is probably slower since mz_crc32 already returns it NOT'd per standard CRC-32, but meh.
// UPDATE: nope, it seems like compilers just inline this whole thing and omit the last NOT, lol
#define crc32_jamcrc(buf, size) ~(uint32_t)crc32(0x00000000, buf, size)
// using the zlib/miniz supplied CRC-32 function, no point in having it twice in the source code


///////////
// SHA-1 //
///////////

// a customised SHA-1 implementation for just 32-bit operations
// (the games use what appears to be standard SHA-1 regardless)

// and then it got a bit more complicated when i wanted to hash
// from a file, and im left wondering if this was even worth it
// over a plain old standard sha1 implementation :^) (totally!)

typedef struct {
    union {
        uint32_t buf_32[0x10];
        uint8_t  buf_fp[0x40];
    };
    uint32_t hash[0x5];
    uint64_t size;
} sha_t;


#define sha1_init_32 sha1_init
#define sha1_init_fp sha1_init
#define sha1_transform_32 sha1_transform


static inline bool sha1_compare(sha_t *sha, uint32_t *hash) {
    return (
        sha->hash[0] == hash[0] &&
        sha->hash[1] == hash[1] &&
        sha->hash[2] == hash[2] &&
        sha->hash[3] == hash[3] &&
        sha->hash[4] == hash[4]
    );
}


static inline void sha1_copy(sha_t *sha, uint32_t *hash) {
    hash[0] = sha->hash[0];
    hash[1] = sha->hash[1];
    hash[2] = sha->hash[2];
    hash[3] = sha->hash[3];
    hash[4] = sha->hash[4];
}


static inline void sha1_init(sha_t *sha) {
    sha->hash[0] = 0x67452301;
    sha->hash[1] = 0xEFCDAB89;
    sha->hash[2] = 0x98BADCFE;
    sha->hash[3] = 0x10325476;
    sha->hash[4] = 0xC3D2E1F0;
    sha->size = 0;
}


#define __sha1_buf_iter(i) sha->buf_32[i & 0xF] = rol((sha->buf_32[(i - 0x3) & 0xF] ^ sha->buf_32[(i - 0x8) & 0xF] ^ sha->buf_32[(i - 0xE) & 0xF] ^ sha->buf_32[i & 0xF]), 1)
#define __sha1_iter(x, y) MACRO( \
    f = rol(a, 5) + sha->buf_32[i & 0xF] + e + x + (y); \
    e = d; d = c; c = rol(b, 30); b = a; a = f; \
)

static void sha1_transform(sha_t *sha) {
    uint32_t a, b, c, d, e, f;

    a = sha->hash[0];
    b = sha->hash[1];
    c = sha->hash[2];
    d = sha->hash[3];
    e = sha->hash[4];

    // msvc unrolls all these, gcc/clang only partially, w/e
    int i = 0;
    for (; i < 16; i++)
        __sha1_iter(0x5A827999, b & c | ~b & d);
    for (; i < 20; i++) {
        __sha1_buf_iter(i);
        __sha1_iter(0x5A827999, b & c | ~b & d);
    }
    for (; i < 40; i++) {
        __sha1_buf_iter(i);
        __sha1_iter(0x6ED9EBA1, b ^ c ^ d);
    }
    for (; i < 60; i++) {
        __sha1_buf_iter(i);
        __sha1_iter(0x8F1BBCDC, b & c | b & d | c & d);
    }
    for (; i < 80; i++) {
        __sha1_buf_iter(i);
        __sha1_iter(0xCA62C1D6, b ^ c ^ d);
    }

    sha->hash[0] += a;
    sha->hash[1] += b;
    sha->hash[2] += c;
    sha->hash[3] += d;
    sha->hash[4] += e;
}

#undef __sha1_buf_iter
#undef __sha1_iter


//////////////
// SHA-1 32 //
//////////////

static void sha1_update_32(sha_t *sha, uint32_t *buf, uint64_t size) {
    int i = sha->size & 0xF;
    int init_size = 0x10 - i;
    sha->size += size;

    if (size < init_size) {
        memcpy(&sha->buf_32[i], buf, size << 2);
        return;
    }

    if (i) { // unaligned copy
        memcpy(&sha->buf_32[i], buf, init_size << 2);
        sha1_transform_32(sha);
        size -= init_size;
        i = init_size;
    }
    for (; size >= 0x10; size -= 0x10) {
        memcpy(&sha->buf_32, &buf[i], 0x40);
        sha1_transform_32(sha);
        i += 0x10;
    }
    memcpy(&sha->buf_32, &buf[i], size << 2);
}


static void sha1_end_32(sha_t *sha) {
    int i = sha->size & 0xF;
    sha->size <<= 5; // bits

    sha->buf_32[i++] = 0x80000000;

    if (i >= 0xE) {
        for (; i < 0x10; i++)
            sha->buf_32[i] = 0x00000000;
        sha1_transform_32(sha);
        i = 0;
    }

    for (; i < 0xE; i++)
        sha->buf_32[i] = 0x00000000;
    sha->buf_32[0xE] = sha->size >> 32;
    sha->buf_32[0xF] = (uint32_t)sha->size;
    sha1_transform_32(sha);
}


// unified wrapper if the data to hash is in a continuous block
static inline void sha1_32(sha_t *sha, uint32_t *buf, uint64_t size) {
    sha1_init_32(sha);
    sha1_update_32(sha, buf, size);
    sha1_end_32(sha);
}


//////////////
// SHA-1 fp //
//////////////

static inline void sha1_transform_fp(sha_t *sha) {
    for (int i = 0; i < 0x10; i++)
        sha->buf_32[i] = bswap(sha->buf_32[i]);
    sha1_transform(sha);
}


static bool sha1_update_fp(sha_t *sha, FILE *fp, uint64_t size) {
    int i = sha->size & 0x3F;
    int init_size = 0x40 - i;
    sha->size += size;

    if (size < init_size) {
        if (!fread(&sha->buf_fp[i], size, 1, fp))
            return false;
        return true;
    }

    if (i) { // unaligned read
        if (!fread(&sha->buf_fp[i], init_size, 1, fp))
            return false;
        sha1_transform_fp(sha);
        size -= init_size;
    }
    for (; size >= 0x40; size -= 0x40) {
        if (!fread(&sha->buf_fp, 0x40, 1, fp))
            return false;
        sha1_transform_fp(sha);
    }
    if (size && !fread(&sha->buf_fp, size, 1, fp))
        return false;

    return true;
}


static void sha1_end_fp(sha_t *sha) {
    int i = sha->size >> 2 & 0xF;
    sha->size <<= 3; // bits
    int j = sha->size & 0x1F;

    sha->buf_32[i] = (sha->buf_32[i] & ((1 << j) - 1)) | (0x80 << j);
    i++;

    for (int k = 0; k < i; k++)
        sha->buf_32[k] = bswap(sha->buf_32[k]);

    if (i > 0xE) {
        for (; i < 0x10; i++)
            sha->buf_32[i] = 0x00000000;
        sha1_transform(sha);
        i = 0;
    }

    for (; i < 0xE; i++)
        sha->buf_32[i] = 0x00000000;
    sha->buf_32[0xE] = sha->size >> 32;
    sha->buf_32[0xF] = (uint32_t)sha->size;
    sha1_transform(sha);
}


// unified wrapper if the data to hash is in a continuous block
static inline bool sha1_fp(sha_t *sha, FILE *fp, uint64_t size) {
    sha1_init_fp(sha);
    if (!sha1_update_fp(sha, fp, size))
        return false;
    sha1_end_fp(sha);
    return true;
}

#endif
