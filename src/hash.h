// Written by Edness   2024-09-17 - 2024-09-28

// PACKAGEs use CRC-32/JAMCRC for filename hashes, which just means the final output isn't NOT'd
// this is probably slower since mz_crc32 already returns it NOT'd per standard CRC-32, but meh.
// UPDATE: nope, it seems like compilers just inline this whole thing and omit the last NOT, lol
#define get_jamcrc_hash(buf, size) ~(uint32_t)mz_crc32(MZ_CRC32_INIT, buf, size - 1)
// using the zlib/miniz supplied CRC-32 function, no point in having it twice in the source code
