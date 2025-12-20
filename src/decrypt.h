// Written by Edness   2024-07-13 - 2025-12-20
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define NO_ALLOCS
#define HAVE_C99INCLUDES
#define MAX_FIXED_BIT_LENGTH 2048

#include "bigdigits/bigdigits.h"
#include "bigdigits/bigdigits.c"


#define KS_CHUNKS 0x40
#define ID_SDRM 0x5344524D

// David Ireland's BigDigits - same library SCEE themselves also used
#define rsa_sign(msg, exp, mod) mpModExp(msg, msg, exp, mod, KS_CHUNKS)
#define rsa_verify(msg, exp, mod) mpModExp(msg, msg, exp, mod, KS_CHUNKS)

typedef struct {
    uint32_t psid[4]; // OpenPSID keystore key
    uint32_t drm_key[4]; // final .PKG.DRM key
    uint32_t keystore[KS_CHUNKS];
    bool has_psid;
} drm_t;


// keys.edat normally contains 3 public keys (e = 65537)
// but only this one is used for DRM keystore decryption
// (however it does on some rare occasions switch to the
// 2nd public key in keys.edat observed while debugging)
// SingStar Vol. 1 has one more different rsakey modulus
static uint32_t rsa_modulus[KS_CHUNKS] = { // not const because BigDigits mpShiftLeft will segfault
    0xD9425983, 0x0B4C6BB4, 0x740B4B22, 0xD8708CD5, 0xBC7C7341, 0x2B4EC341, 0xD9E6EF17, 0x92944487,
    0xB52A19BA, 0xD1EA4FAE, 0x9AD37F15, 0x482706F5, 0x0843D556, 0xE4DFF9D6, 0x9C8A19FC, 0x67D89622,
    0xA58B42DB, 0xCE562145, 0x5E6CFB4A, 0xA292E651, 0xD7955EDE, 0xA8C552EF, 0xDE2B8957, 0x27E37927,
    0x17E113E7, 0xB542999F, 0x024E2E2D, 0xBD57FA8F, 0x63BBDB15, 0x6DBF1FB0, 0xBF7BD7BB, 0xDA3C9C16,
    0x84B40979, 0xB84E6BDE, 0xFC640D39, 0xEF92F957, 0xF27B3E1B, 0x5E6F06B4, 0xDF2084BF, 0xC3F6395C,
    0x0E453F99, 0xAE6913B0, 0x7653A391, 0x2FEA1729, 0x83DD5F2E, 0x451C236D, 0x27E8072D, 0xCAD467DA,
    0xDA8A044E, 0xCD9D8C51, 0xCF0DB3BE, 0xBE32F500, 0x8B24FD71, 0x0684F15F, 0x0D146D06, 0x74EF64D8,
    0xA77C5D37, 0x1952BC1E, 0x246815D1, 0x5CFBB71E, 0x14E8BD44, 0xC09623F8, 0x14D2AE65, 0xDD3CFCF8
};

// Shout-out to the Redump.org community for making this possible
static const uint32_t drm_keys[][4] = {
    {0xE2AC48C5, 0x1C511D8E, 0x8158606D, 0x8086ED1D}, // SingStar (Europe) (Pack0.pkd)
    {0xD2229BCB, 0xE9D5207A, 0x88960EEB, 0x7A848797}, // SingStar (Europe) (Pack1.pkd)
    {0x283A57E8, 0x0AF6634E, 0x0EF89D6E, 0x91F4DBF6}, // SingStar (France) (Pack0.pkd)
    {0xB370301E, 0x6AB604B3, 0xA141CE8D, 0xB901D782}, // SingStar (France) (Pack1.pkd)
    {0x5413789E, 0xFD0D1A78, 0x03E298F2, 0x6FA496BD}, // SingStar (Germany) (Pack0.pkd)
    {0x6A738A85, 0x077231A7, 0xDE34B9B2, 0xB1EF5267}, // SingStar (Germany) (Pack1.pkd)
    {0x26AE137C, 0x77B72FA7, 0xE17CC61B, 0xEF655BB5}, // SingStar (Norway) (Pack0.pkd)
    {0x511D8C65, 0x46E18707, 0x2C5429C7, 0xEC547829}, // SingStar (Norway) (Pack1.pkd)
    {0xA2796382, 0x3F1C41CD, 0xE0F313BA, 0x608C428C}, // SingStar (Spain) (Pack0.pkd)
    {0x2345B083, 0xC41236D0, 0xD6FA981C, 0x6283311C}, // SingStar (Spain) (Pack1.pkd)
    {0x281446BC, 0xB01F295D, 0x09C2221E, 0xEE62AA61}, // SingStar (USA) (Pack0.pkd)
    {0xC37BA848, 0xB74458BB, 0x4B76918A, 0x8F3FF005}, // SingStar (USA) (Pack1.pkd)

    {0x2483FFDC, 0x047F8CAD, 0xF60BB511, 0xDE5A6FA2}, // SingStar Vol. 2 (Europe) (Pack0.pkd)
    {0xABB91BF7, 0xF7878BCD, 0xDC5E5E70, 0x6BAD1B53}, // SingStar Vol. 2 (Europe) (Pack1.pkd)
    {0xA78BD9D2, 0x64EC0B1D, 0xAF1B864D, 0xD748FC01}, // SingStar Vol. 2 (Europe) (Pack2.pkd)
    {0x29FDD214, 0xF800E98D, 0x4F27CD54, 0x92C90B5D}, // SingStar Vol. 2 (Germany) (Pack0.pkd)
    {0x724D1992, 0x08F6098A, 0xA217280A, 0xB78FF59B}, // SingStar Vol. 2 (Germany) (Pack1.pkd)
    {0x8CF91E93, 0x205C6579, 0x8717D03A, 0xBCD381A8}, // SingStar Vol. 2 (Germany) (Pack2.pkd)
    {0xE2C2DC1C, 0x5BE0EB60, 0x8E5A25CE, 0x231AB94E}, // SingStar Vol. 2 (Italy) (Pack0.pkd)
    {0x7CF309D6, 0x42F2BF27, 0xF13D34A9, 0xD44E40C0}, // SingStar Vol. 2 (Italy) (Pack1.pkd)
    {0xF67ECBE0, 0x59C79B2F, 0xD484C5BA, 0x339ACD6E}, // SingStar Vol. 2 (Italy) (Pack2.pkd)
    {0xD7D1D111, 0x9CF4E35E, 0x078F63E6, 0x8952F1A6}, // SingStar Vol. 2 (Spain) (Pack0.pkd)
    {0x52FBCF90, 0x870127F1, 0x93EB12DA, 0x3DEACB34}, // SingStar Vol. 2 (Spain) (Pack1.pkd)
    {0x16050B5E, 0xD8E1AE59, 0x4D7EBFD9, 0xE0DFD4ED}, // SingStar Vol. 2 (Spain) (Pack2.pkd)

    /* LegacyPS2Discs.pkd
     * SingStar A Tutto Pop (Italy)
     * SingStar ABBA (Europe, Spain, USA)
     * SingStar Hits (France)
     * SingStar Hits 2 (France)
     * SingStar Pop 2009 (Spain)
     * SingStar Pop Edition (Australia, Europe, Germany)
     * SingStar SuomiPop (Finland)
     * SingStar Queen (Europe)
     * SingStar Vol. 2 (USA)
     * SingStar Vol. 3 (Europe, Germany, Italy, Spain) */
    {0x7C828270, 0x7C82C530, 0xFFFFFFFF, 0x7C82C529},

    /* LegacyPS2Discs.pkd
     * SingStar Chart Hits (Australia)
     * SingStar Chartbreaker (Europe)
     * SingStar Dance (Europe, Spain, USA)
     * SingStar Fussballhits (Germany)
     * SingStar Guitar (Australia, Europe, Germany, Spain)
     * SingStar Intro (Italy)
     * SingStar Kent (Scandinavia)
     * SingStar Latino (USA)
     * SingStar Made in Germany (Germany)
     * SingStar Mallorca Party (Germany)
     * SingStar Mecano (Spain)
     * SingStar Morangos com Acucar (Portugal)
     * SingStar Motown (Europe)
     * SingStar Polskie Hity (Poland)
     * SingStar Polskie Hity 2 (Poland)
     * SingStar Portugal Hits (Portugal)
     * SingStar Queen (USA)
     * SingStar Starter Pack (Europe, Germany, Netherlands, Spain)
     * SingStar Studio 100 (Netherlands)
     * SingStar SuomiHitit (Finland)
     * SingStar Svenska Stjaernor (Sweden)
     * SingStar Take That (Europe)
     * SingStar Vasco (Italy)
     * SingStar Viewer (World) (v01.00) */
    {0x7C828290, 0x7C82C550, 0xFFFFFFFF, 0x7C82C549},

    /* SingStar Afrikaanse Treffers (South Africa)
     * SingStar Apres-Ski Party 2 (Germany)
     * SingStar Cantautori Italiani (Italy)
     * SingStar Danske Hits (Denmark)
     * SingStar Patito Feo (Spain)
     * SingStar The Wiggles (Australia) */
    {0x7D61F218, 0x7D624BC8, 0xFFFFFFFF, 0x7D624BC1},

    /* DanceStar Party (Europe, Germany, Spain)
     * Everybody Dance (USA)
     * SingStar Back to the 80s (Europe)
     * SingStar Grandes Exitos (Spain)
     * SingStar Return to the 80s (Netherlands)
     * SingStar SuomiSuosikit (Finland)
     * SingStar Viewer (World) (v07.00) */
    {0x7D61F218, 0x7D624BC0, 0xFFFFFFFF, 0x7D624BB9},

    /* DanceStar Digital (World)
     * DanceStar Party Hits (Europe, Germany, Spain)
     * Everybody Dance 2 (Latin America)
     * Everybody Dance 3 (Latin America)
     * Everybody Dance Digital (World)
     * SingStar Digital (World)
     * SingStar SuomiHelmet (Finland)
     * SingStar SuomiHuiput (Finland) */
    {0x7D61F218, 0x7D624728, 0xFFFFFFFF, 0x7D624721},

    /* SingStar Koroli vecherinok (Russia)
     * SingStar MegaHits (Spain)
     * SingStar Mistrzowska Impreza (Poland)
     * SingStar Nova Geracao (Portugal)
     * SingStar SuomiBileet (Finland)
     * SingStar Ultimate Party (Europe, Germany) */
    {0x7734DFA5, 0x68000068, 0x00000017, 0x00000000},

    /* SingStar Die Eiskoenigin - Voellig unverfroren (Germany)
     * SingStar Frozen - El Reino del Hielo (Spain)
     * SingStar Frozen - Il Regno di Ghiaccio (Italy)
     * SingStar Frozen - Kraina Lodu (Poland)
     * SingStar Frozen - O Reino do Gelo (Portugal) */
    {0x7755DFA5, 0x68000068, 0x00000017, 0x00000000},

    /* Errata_0.pkd
     * Errata_1.pkd
     * Errata_2.pkd
     * LegacyPS2Discs.pkd
     * Pak_W.pak */
    {0x00000000, 0x00000000, 0x00000000, 0x00000000}
};


#define __do_xtea_rounds(rounds) MACRO( \
    for (int i = 0; i < rounds; i++) { \
        v0 += (v1 << 4 ^ v1 >> 5) + v1 ^ sum + key[sum & 3]; \
        sum += 0x9E3779B9; /* const uint32_t delta; */ \
        v1 += (v0 << 4 ^ v0 >> 5) + v0 ^ sum + key[sum >> 11 & 3]; \
    } \
)

// PACKAGE uses a slightly "custom" implementation of XTEA encryption
// using the block offset index as the IV with a constant first half,
// encrypting that with XTEA, and using the result to XOR said block.
// (v0 technically isn't hardcoded in the games but yk optimizations)
static uint64_t get_xtea_xor_key(uint32_t v1, const uint32_t *key, const bool is_dlc) {
    // Reimplemented from the function at 004C8454 in
    // the Polish release of SingStar: Ultimate Party
    uint32_t v0 = 0x12345678; // iv[0] const
    uint32_t sum = 0;

    // compilers unroll these much more nicely this way
    __do_xtea_rounds(8); // standard (8 rounds)
    if (is_dlc)
        __do_xtea_rounds(12); // DLC (20 rounds)

    return (uint64_t)v1 << 32 | v0;
}

#undef __do_xtea_rounds


static uint32_t const *get_package_key(drm_t *drm, const uint64_t target_hdr) {

    if (drm->has_psid) { // pkg.is_dlc
        if (get_xtea_xor_key(0, drm->drm_key, true) == target_hdr)
            return drm->drm_key;
        print_warn(WARN_PKG_BAD_DRMKEY); // maybe return NULL?
    }
    for (int i = 0; i < arrlen(drm_keys); i++) {
        if (get_xtea_xor_key(0, drm_keys[i], false) == target_hdr)
            return drm_keys[i];
    }

    return NULL;
}


// purely to not have to copy the same thing over and over again
static inline void hash_keystore(sha_t *sha, uint32_t *keystore) {
    sha1_init(sha);
    sha1_update(sha, &keystore[0x1D], 0x23); // 0x74~x100 (0x8C bytes)
    sha1_update(sha, &keystore[0x00], 0x18); // 0x00~0x60 (0x60 bytes)
    sha1_end(sha);
}


static void reverse_keystore(uint32_t *keystore) {
    for (int i = 0; i < KS_CHUNKS >> 1; i++) {
        int o = KS_CHUNKS - 1 - i; // i opposite
        uint32_t ks_tmp = keystore[o];
        keystore[o] = keystore[i];
        keystore[i] = ks_tmp;
    }
}


static bool decrypt_keystore(drm_t *drm) {
    // Reimplemented from the functions at 004BF144 and
    // 004BFC58 in the Polish release of Ultimate Party
    uint32_t psid_hash[5] = {0};
    sha_t sha;

    // skip RSA decryption if it was only dumped reencrypted without signing
    if (drm->keystore[0x3F] != ID_SDRM) {
        uint32_t exponent[KS_CHUNKS] = {0x10001};

        reverse_keystore(drm->keystore);

        // verify (decrypt) signed keystore
        rsa_verify(drm->keystore, exponent, rsa_modulus);

        // should have an SDRM header id if successfully decrypted (validated later)
        //if (keystore[0x00] != ID_SDRM || keystore[0x13] || keystore[0x3F])
        //    return false;
        reverse_keystore(drm->keystore);
    }

    // 0x00~0x04: 00000000, 007F0000 in universal DLC?
    // 0x04~0x5F: unk (file hash?) (technically starts at 0x02?)
    // 0x5F~0x60: 0x14 (XTEA rounds? 0x00 for pkd keystores)
    // 0x60~0x74: wraparound SHA-1 of 0x74~0x60 (0x74~0x100 + 0x00~0x60)
    // 0x74~0x84: F33964A9 46BD983F 6B1B6306 73E79E0B (XTEA key related?)
    // 0x84~0x98: SHA-1 related to the decrypted XTEA key? or encrypted file hash?
    // 0x98~0x9C: 0301FF01 (first byte 0x03 is used for some drmkey decryption state?)
    // 0x9C~0xB0: zero length SHA-1 of some user data? DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
    // 0xB0~0xB4: 00000000
    // 0xB4~0xC4: encrypted XTEA key
    // 0xC4~0xD8: SHA-1 of the PSID (blank for pkd keystores)
    // 0xD8~0xE8: 5D4C6E15 44015809 AC35AC16 575FC123 (XTEA key related?)
    // 0xE8~0xF8: ECD56806 BA777B7F 685A55ED 78114B9A (XTEA key related?)
    // 0xF8~0xFC: 00FE0601 (version? v01.06, -512?)
    // 0xFC~x100: SDRM

    // is 0x3E keystore version? (v1.06 -512?) the game has code for various versions but only
    // v1.06 is ever used? <1.00 (00xxA000), 1.00 (0100A000), 1.05 (0105FE00), 1.06 (0106FE00)
    if (drm->keystore[0x3F] != ID_SDRM || drm->keystore[0x3E] != 0x00FE0601) // || drm->keystore[0x2C] || drm->keystore[0x00]
        return false;

    // verify SHA-1 of the whole keystore block (v1.06 variant)
    hash_keystore(&sha, drm->keystore);
    if (!sha1_compare(&sha, &drm->keystore[0x18])) // 0x60~0x74
        return false;

    // verify SHA-1 of the PSID (all 0 if universal - not signed to one system, which does rarely occur)
    // (also of note is a later function that derives the final XTEA key checks if this isn't -1 either,
    // so psid_hash in that case should be initialised to -1 as well, but during init only all 0 passes)
    if (drm->keystore[0x31] || drm->keystore[0x32] || drm->keystore[0x33] || drm->keystore[0x34] || drm->keystore[0x35]) {
        sha1(&sha, drm->psid, 0x4); // PSID hash is used for XTEA key decryption
        sha1_copy(&sha, psid_hash);
        // hashes the result again for v0.05+ (not v1.05+, typo/bug?)
        sha1(&sha, psid_hash, 0x5); // PSID hash-hash is stored in the keystore
        if (!sha1_compare(&sha, &drm->keystore[0x31])) // 0xC4~0xD8
            return false;
    }

    // it then hashes something of zero length and i'm not sure what it is
    // but since the keystores have a seemingly constant zero length SHA-1
    // at 0x9C [0x27], might as well just use that (and hope for the best)
    sha1_init(&sha); sha1_end(&sha);
    if (!sha1_compare(&sha, &drm->keystore[0x27])) // 0x9C~0xB0
        return false;

    sha1_init(&sha);
    sha1_update(&sha, psid_hash, 0x5);
    sha1_update(&sha, &drm->keystore[0x27], 0x5);
    sha1_end(&sha);
    // result is also used to decrypt the final XTEA key
    // (unsure whether or not to bswap here already tho)
    drm->keystore[0x2D] ^= sha.hash[0];
    drm->keystore[0x2E] ^= sha.hash[1];
    drm->keystore[0x2F] ^= sha.hash[2];
    drm->keystore[0x30] ^= sha.hash[3];

    // wipe PSID from the keystore for datting (incl. from the key)
    // sample files i've gotten, where the files are 100% identical
    // but with different keystores only had this data chunk differ
    drm->keystore[0x31] = 0x00000000;
    drm->keystore[0x32] = 0x00000000;
    drm->keystore[0x33] = 0x00000000;
    drm->keystore[0x34] = 0x00000000;
    drm->keystore[0x35] = 0x00000000;
    // otherwise if even the DRM key was different, then
    // 0x04~0x5F and 0x84~0x98 SHA-1 were also different

    // and update the new keystore hash accordingly
    hash_keystore(&sha, drm->keystore);
    sha1_copy(&sha, &drm->keystore[0x18]); // 0x60~0x74

    drm->drm_key[0] = bswap(drm->keystore[0x2D]);
    drm->drm_key[1] = bswap(drm->keystore[0x2E]);
    drm->drm_key[2] = bswap(drm->keystore[0x2F]);
    drm->drm_key[3] = bswap(drm->keystore[0x30]);

    return true;
}


static bool encrypt_keystore(drm_t *drm) {
    // see decrypt_keystore above for docs
    uint32_t psid_hash[5] = {0};
    sha_t sha;


    if (drm->keystore[0x3F] != ID_SDRM || drm->keystore[0x3E] != 0x00FE0601) // || drm->keystore[0x2C] || drm->keystore[0x00]
        return false;

    if (drm->keystore[0x31] || drm->keystore[0x32] || drm->keystore[0x33] || drm->keystore[0x34] || drm->keystore[0x35])
        return false;

    hash_keystore(&sha, drm->keystore);
    if (!sha1_compare(&sha, &drm->keystore[0x18])) // 0x60~0x74
        return false;

    drm->drm_key[0] = bswap(drm->keystore[0x2D]); // 0xB4~0xC4
    drm->drm_key[1] = bswap(drm->keystore[0x2E]);
    drm->drm_key[2] = bswap(drm->keystore[0x2F]);
    drm->drm_key[3] = bswap(drm->keystore[0x30]);


    if (drm->has_psid) {
        sha1(&sha, drm->psid, 0x4);
        sha1_copy(&sha, psid_hash);
        sha1(&sha, psid_hash, 0x5);
        sha1_copy(&sha, &drm->keystore[0x31]); // 0xC4~0xD8
    }

    sha1_init(&sha);
    sha1_update(&sha, psid_hash, 0x5);
    sha1_update(&sha, &drm->keystore[0x27], 0x5); // 0x9C~0xB0
    sha1_end(&sha);

    drm->keystore[0x2D] ^= sha.hash[0]; // 0xB4~0xC4
    drm->keystore[0x2E] ^= sha.hash[1];
    drm->keystore[0x2F] ^= sha.hash[2];
    drm->keystore[0x30] ^= sha.hash[3];

    hash_keystore(&sha, drm->keystore);
    sha1_copy(&sha, &drm->keystore[0x18]); // 0x60~0x74


    print_warn(WARN_PKG_KS_ENCRYPT);
    // the original private key is unlikely to ever be discovered
    // so instead maybe create our own RSA priv/pub key pairs and
    // patch them into keys.edat? requires resigning all DLC then
    //reverse_keystore(drm->keystore);
    //rsa_sign(drm->keystore, rsa_priv_exp, rsa_modulus);
    //reverse_keystore(drm->keystore);

    return true;
}
