// Written by Edness   2024-07-29 - 2024-07-31
#pragma once
#include <stdint.h>


// null-terminated string
static int32_t read_str(const uint8_t *buf, uint32_t offs, char *dst) {
    //do {} while (buf[offs]);
    for (int i = 0; i < 256; i++) {
        dst[i] = buf[offs];
        if (!buf[offs++]) return ++i;
    }

    dst[255] = 0x00;
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
