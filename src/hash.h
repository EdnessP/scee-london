// Written by Edness   2024-09-17 - 2026-07-03
#ifndef _HASH_H_
#define _HASH_H_
#include <stdint.h>
#include <stdbool.h>
#include "defs.h"
#include "decompress.h"

///////////
// CRC32 //
///////////

// PACKAGEs use CRC-32/JAMCRC for filename hashes, which just means the final output isn't NOT'd
// this is probably slower since mz_crc32 already returns it NOT'd per standard CRC-32, but meh.
// UPDATE: nope, it seems like compilers just inline this whole thing and omit the last NOT, lol
//#define crc32_jamcrc(buf, size) ~(uint32_t)crc32(0x00000000, buf, size)
// using the zlib/miniz supplied CRC-32 function, no point in having it twice in the source code
// UPDATE 2: reworking stuff made it more logical to just have my own implementation, oh well...

static const uint32_t crc_hash_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};


// this will completely fall apart for any unicode chars, but who cares amirite
static inline uint32_t crc32_jamcrc(path_t *buf) {
    uint32_t hash = 0xFFFFFFFF;
    int i = 0;

    while (buf[i])
        hash = hash >> 8 ^ crc_hash_table[buf[i++] ^ hash & 0xFF];

    return hash; // crc32 would return ~hash;
}


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
    // should also be skipped on BE platfs but w/e
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
    int j = sha->size & 0x1F; // 0x18

    sha->buf_32[i] = (sha->buf_32[i] & ((1 << j) - 1)) | (0x80 << j);
    i++;

    for (j = 0; j < i; j++)
        sha->buf_32[j] = bswap(sha->buf_32[j]);

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
