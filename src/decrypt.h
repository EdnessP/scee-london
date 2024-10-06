// Written by Edness   2024-07-13 - 2024-10-06
#pragma once
#include <stdint.h>

#define NUM_KEYS sizeof(keys) / sizeof(keys[0])


// TODO: Info on how the keys are derived
// A 0x100 byte block is loaded from ...somewhere, I'm not entirely sure where.
// It's treated as an array of 64 x 32-bit integers, and the array is reversed.
// That block is then decrypted, and from the result of that, starting with the
// data at 0xB4 of the decrypted block, the final PKD key is eventually derived

// Shout-out to the Redump.org community for making this possible
static const uint32_t keys[][4] = {
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
     * SingStar A Tutto Pop
     * SingStar ABBA
     * SingStar Hits
     * SingStar Hits 2
     * SingStar Pop 2009
     * SingStar Pop Edition
     * SingStar SuomiPop
     * SingStar Queen
     * SingStar Vol. 2 (USA)
     * SingStar Vol. 3 */
    {0x7C828270, 0x7C82C530, 0xFFFFFFFF, 0x7C82C529},

    /* LegacyPS2Discs.pkd
     * SingStar Chart Hits
     * SingStar Chartbreaker
     * SingStar Dance
     * SingStar Fussballhits
     * SingStar Guitar
     * SingStar Intro
     * SingStar Kent
     * SingStar Latino
     * SingStar Made in Germany
     * SingStar Mallorca Party
     * SingStar Mecano
     * SingStar Morangos com Acucar
     * SingStar Motown
     * SingStar Polskie Hity
     * SingStar Polskie Hity 2
     * SingStar Portugal Hits
     * SingStar Queen
     * SingStar Starter Pack
     * SingStar Studio 100
     * SingStar SuomiHitit
     * SingStar Svenska Stjaernor
     * SingStar Take That
     * SingStar Vasco
     * SingStar Viewer (v01.00) */
    {0x7C828290, 0x7C82C550, 0xFFFFFFFF, 0x7C82C549},

    /* SingStar Afrikaanse Treffers
     * SingStar Apres-Ski Party 2
     * SingStar Cantautori Italiani
     * SingStar Danske Hits
     * SingStar Patito Feo
     * SingStar The Wiggles */
    {0x7D61F218, 0x7D624BC8, 0xFFFFFFFF, 0x7D624BC1},

    /* DanceStar Party
     * Everybody Dance
     * SingStar Back to the 80s
     * SingStar Grandes Exitos
     * SingStar Return to the 80s
     * SingStar SuomiSuosikit
     * SingStar Viewer (v07.00) */
    {0x7D61F218, 0x7D624BC0, 0xFFFFFFFF, 0x7D624BB9},

    /* DanceStar Digital
     * DanceStar Party Hits
     * Everybody Dance 2
     * Everybody Dance 3
     * Everybody Dance Digital
     * SingStar Digital
     * SingStar SuomiHelmet
     * SingStar SuomiHuiput */
    {0x7D61F218, 0x7D624728, 0xFFFFFFFF, 0x7D624721},

    /* SingStar Koroli vecherinok
     * SingStar MegaHits
     * SingStar Mistrzowska Impreza
     * SingStar Nova Geracao
     * SingStar SuomiBileet
     * SingStar Ultimate Party */
    {0x7734DFA5, 0x68000068, 0x00000017, 0x00000000},

    /* SingStar Die Eiskoenigin - Voellig unverfroren
     * SingStar Frozen - El Reino del Hielo
     * SingStar Frozen - Il Regno di Ghiaccio
     * SingStar Frozen - Kraina Lodu
     * SingStar Frozen - O Reino do Gelo */
    {0x7755DFA5, 0x68000068, 0x00000017, 0x00000000},

    /* Errata_0.pkd
     * Errata_1.pkd
     * Errata_2.pkd
     * LegacyPS2Discs.pkd */
    {0x00000000, 0x00000000, 0x00000000, 0x00000000}
};


// PACKAGE uses a slightly "custom" implementation of XTEA encryption
// using the block offset index as the IV with a constant first half,
// encrypting that with XTEA, and using the result to XOR said block.
// (v0 technically isn't hardcoded in the games but yk optimizations)
static uint64_t get_xtea_xor_key(uint32_t v1, const uint32_t *key) {
    // Reimplemented from the function at 004C8454 in
    // the Polish release of SingStar: Ultimate Party
    uint32_t v0 = 0x12345678; // iv[0] const
    uint32_t sum = 0;

    for (int i = 0; i < 8; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += 0x9E3779B9; // const uint32_t delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    return (uint64_t)v1 << 32 | v0;
}
