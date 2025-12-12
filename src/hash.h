// Written by Edness   2024-09-17 - 2025-12-12
#pragma once
#include <stdint.h>
#include <stdbool.h>

// PACKAGEs use CRC-32/JAMCRC for filename hashes, which just means the final output isn't NOT'd
// this is probably slower since mz_crc32 already returns it NOT'd per standard CRC-32, but meh.
// UPDATE: nope, it seems like compilers just inline this whole thing and omit the last NOT, lol
#define crc32_jamcrc(buf, size) ~(uint32_t)crc32(0x00000000, buf, size)
// using the zlib/miniz supplied CRC-32 function, no point in having it twice in the source code


///////////
// SHA-1 //
///////////

// a simplified SHA-1 implementation for just 32-bit operations
// (the games use what appears to be standard SHA-1 regardless)

typedef struct {
    uint32_t buf[0x10];
    uint32_t hash[0x5];
    uint64_t size;
} sha_t;


//#define rol(num, bits) ((num << bits) | (num >> (32 - bits)))
// inlined function instead of a macro to force it to pre-calculate num
// slightly better codegen for msvc, but mingw/gcc/clang are unaffected
static inline uint32_t rol(uint32_t num, uint32_t bits) {
    return (num << bits) | (num >> (32 - bits));
}


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


#define __sha1_buf_iter(i) sha->buf[i & 0xF] = rol((sha->buf[(i - 0x3) & 0xF] ^ sha->buf[(i - 0x8) & 0xF] ^ sha->buf[(i - 0xE) & 0xF] ^ sha->buf[i & 0xF]), 1)
#define __sha1_iter(x, y) MACRO( \
    f = rol(a, 5) + sha->buf[i & 0xF] + e + x + (y); \
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


static void sha1_update(sha_t *sha, uint32_t *buf, uint64_t size) {
    int i = sha->size & 0xF;
    int init_size = 0x10 - i;
    sha->size += size;

    if (size < init_size) {
        memcpy(&sha->buf[i], buf, size << 2);
        return;
    }

    if (i) { // unaligned copy
        memcpy(&sha->buf[i], buf, init_size << 2);
        sha1_transform(sha);
        size -= init_size;
        i = init_size;
    }
    while (size > 0xF) {
        memcpy(&sha->buf, &buf[i], 0x40);
        sha1_transform(sha);
        size -= 0x10;
        i += 0x10;
    }
    memcpy(&sha->buf, &buf[i], size << 2);
}


static inline void sha1_end(sha_t *sha) {
    int i = sha->size & 0xF;
    sha->size <<= 5;

    sha->buf[i++] = 0x80000000;

    if (i > 0xD) {
        for (; i < 0x10; i++)
            sha->buf[i] = 0x00000000;
        sha1_transform(sha);
        i = 0;
    }

    for (; i < 0xE; i++)
        sha->buf[i] = 0x00000000;
    sha->buf[0xE] = sha->size >> 32;
    sha->buf[0xF] = (uint32_t)sha->size;
    sha1_transform(sha);
}


// unified wrapper if the data to hash is in a continuous block
static inline void sha1(sha_t *sha, uint32_t *buf, uint64_t size) {
    // most of the keystore SHA1 operations are very small
    // with this being inlined, compilers seem to optimise
    // which variant to use on a case by case basis anyway
    if (size < 0xD) {
        int i;
        // also a lazy way of skipping a temp
        // array copy for PSID double hashing
        // (but we don't talk about that lol)
        // UPDATE: nvm, had to copy it anyway
        for (i = 0; i < size; i++)
            sha->buf[i] = buf[i];
        sha->buf[i++] = 0x80000000;
        for (; i < 0xF; i++)
            sha->buf[i] = 0x00000000;
        sha->buf[0xF] = size << 5;

        sha1_init(sha);
        sha1_transform(sha);
        return;
    }
    sha1_init(sha);
    sha1_update(sha, buf, size);
    sha1_end(sha);
}
