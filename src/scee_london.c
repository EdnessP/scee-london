// SCEE London Studio PS3 PACKAGE tool
// Copyright (C) 2024-2025  Edness
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// Written by Edness   2024-07-13 - 2025-12-16

#define VERSION "v1.4.1"
#ifndef BUILDDATE
    // shoudn't be an issue if you're using the provided build scripts
    #error Please pre-define the current date in ISO 8601/RFC 3339
#endif

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"

#include "decompress.h"
#include "hash.h"
#include "decrypt.h"
#include "reader.h"

#define ID_PACKAGE 0x204547414B434150
#define ID_ZLIB 0x42494C5A
#define ID_ERDA 0x41445245

#define HDR_SIZE 0x18


static FILE *create_file(const path_t *base_path, uint8_t *file_path) {
    path_t out_path[FILENAME_MAX];
    FILE *fp_out;
    int path_len;
    int i = 0;


    if (file_path) {
#if IS_POSIX
        // PACKAGE filenames normally use backslashes
        while (file_path[i]) {
            if (file_path[i] == '\\')
                file_path[i] = PATH_SEP_C;
            i++;
        }
        i = 0;
#endif
        path_len = snprintf(out_path, FILENAME_MAX, "%s" PATH_SEP_S STR, base_path, file_path);
    }
    else {
        path_len = snprintf(out_path, FILENAME_MAX, "%s", base_path); //strnlen;
    }

    if (path_len < 0 || path_len >= FILENAME_MAX) { // swprintf returns -1 instead???
        print_err(ERR_PKG_PATH_LEN);
        return NULL;
    }

    // ignoring warnings given by create_dir(); fopen()
    // will fail regardless if any serious issues arise
    while (out_path[i]) {
        if (is_path_sep(out_path[i])) {
            out_path[i] = '\x00';
            create_dir(out_path);
            out_path[i] = PATH_SEP_C;
        }
        i++;
    }

    fp_out = fopen(out_path, "wb");
    if (!fp_out) {
        print_err(ERR_PKG_FILE_OPEN);
        return NULL; // technically not needed since fp_out is already NULL
    }

    return fp_out;
}


static inline int64_t get_filesize(FILE *fp) {
    fseek(fp, 0x0, SEEK_END);
    return ftell(fp);
}


static void endian_swap_keystore(uint32_t *keystore) {
    //ks_t ks = {.c = keystore};
    ks_t ks = {NULL}; ks.i = keystore;
    // ensure it's in big endian, should be skipped from
    // compiling on BE archs but i think it works anyway
    for (int i = 0; i < KS_CHUNKS; i++)
        ks.i[i] = get_32be(ks.c, i << 2);
}


static bool read_keystore(FILE *fp, uint32_t *keystore) {
    // 0x100 keystore by EOF + 0x12 min PACKAGE header
    if (get_filesize(fp) < 0x112)
        return false;

    fseek(fp, -(KS_CHUNKS << 2), SEEK_END);
    //if (fread(keystore, 0x4, KS_CHUNKS, fp) != KS_CHUNKS)
    if (!fread(keystore, KS_CHUNKS << 2, 1, fp))
        return false;
    endian_swap_keystore(keystore);

    return true;
}


static bool write_keystore(FILE *fp, uint32_t *keystore) {

    endian_swap_keystore(keystore);
    //if (fwrite(keystore, 0x4, KS_CHUNKS, fp) != KS_CHUNKS)
    if (!fwrite(keystore, KS_CHUNKS << 2, 1, fp)) {
        print_err(ERR_PKG_FILE_WRITE);
        return false;
    }

    return true;
}


static bool dump_package(pkg_t *pkg, drm_t *drm, const path_t *out_path) {
    int64_t size;

    pkg->fp_out = create_file(out_path, NULL);
    if (!pkg->fp_out) goto fail;

    size = get_filesize(pkg->fp_in);
    if (pkg->is_dlc) size -= 0x100;

    if (!pkg->encrypted) {
        // encrypt with the zero-xtea key if needed (TODO: improve?)
        pkg->key = pkg->is_dlc ? drm->drm_key : drm_keys[arrlen(drm_keys) - 1];
        pkg->encrypted = true;
    }

    if (!write_buffer(pkg, 0x0, size)) goto fail;

    if (pkg->is_dlc && !write_keystore(pkg->fp_out, drm->keystore))
        goto fail;

    fclose(pkg->fp_out);
    return true;

fail:
    if (pkg->fp_out)
        fclose(pkg->fp_out);
    return false;
}


static bool extract_package(pkg_t *pkg, const path_t *out_path) {
    uint8_t size;
    uint16_t flags;
    uint32_t hdr_size, hdr_align, hdr_offs;

    buf_t hdr = {NULL};
    uint8_t *_hdr = NULL;
    uint8_t *mz_buf = NULL;


    ////////////////////
    // INITIALISATION //
    ////////////////////
    hdr.c = (uint8_t *)malloc(HDR_SIZE);
    if (!hdr.c) {
        print_err(ERR_ALLOC);
        goto fail;
    }

    // technically 0x12/0x16 max, but the file is bad anyway if this fails
    if (!read_buffer(pkg, hdr.i, 0x0, HDR_SIZE)) goto fail;

    /*
    printf("%08X\n", get_32le(hdr.c, 0x8));
    printf("%04X\n", get_16be(hdr.c, 0xC));
    printf("%08X\n", get_32be(hdr.c, 0xE));
    printf("%016llX\n", get_be(hdr.c, 0xE, 8));
    */
    hdr_offs = 0x8; // skip "PACKAGE "
    if (read_32le(hdr.c, &hdr_offs) != 0x1) {
        print_err(ERR_PKG_BAD_CONFIG);
        goto fail;
    }
    flags = read_16be(hdr.c, &hdr_offs);
    // bit 0 is a 64-bit integer flag
    size = (flags & 0x1) ? 0x4 : 0x8;
    // bits 1 and 2 are always set?  the rest are always zero?
    if ((flags & ~0x1) != 0x6) {
        // better optimised than what compilers make of the check
        //  (!(flags & 0x2) || !(flags & 0x4) || (flags & ~0x7))
        print_err(ERR_PKG_BAD_CONFIG);
        goto fail;
    }

    hdr_size = read_be(hdr.c, &hdr_offs, size) + hdr_offs;
    hdr_align = hdr_size + (0x8 - (hdr_size & 0x7));

    _hdr = (uint8_t *)realloc(hdr.c, hdr_align);
    if (!_hdr) {
        print_err(ERR_ALLOC);
        goto fail;
    }
    hdr.c = _hdr;

    // skip re-reading the first 0x18 bytes for the full header
    if (!read_buffer(pkg, &hdr.i[3], HDR_SIZE, hdr_size - HDR_SIZE))
        goto fail;


    ////////////////
    // EXTRACTION //
    ////////////////
    uint8_t *file_name = NULL;
    uint8_t _tmp[HDR_SIZE] = {0};
    buf_t tmp = {NULL}; tmp.c = _tmp;
    //buf_t tmp = {.c = _tmp};
    uint32_t tmp_offs, tmp_size;
    z_stream mz = {0};

    pkg->mz = &mz;

    mz_buf = (uint8_t *)malloc(MAX_DEC_SIZE);
    if (!mz_buf) {
        print_err(ERR_ALLOC);
        goto fail;
    }

    while (hdr_offs < hdr_size) {
        int32_t name_size;
        uint32_t name_hash;
        uint64_t file_offs, file_size;
        uint32_t file_hdr, dec_size;

        pkg->compressed = false;


        /////////////////////////////////////////
        // read file metadata and prepare data //
        /////////////////////////////////////////
        name_hash = read_32be(hdr.c, &hdr_offs);
        name_size = read_str(hdr.c, &hdr_offs, &file_name);
        //printf("%s = 0x%08X, jamcrc = 0x%08X\n", file_name, name_hash, crc32_jamcrc(file_name, name_size));
        if (name_size < 1 || crc32_jamcrc(file_name, name_size) != name_hash) {
            print_err(ERR_PKG_BAD_NAME);
            goto fail;
        }

        file_offs = read_be(hdr.c, &hdr_offs, size);
        file_size = read_be(hdr.c, &hdr_offs, size);

        //hdr_offs += 4 + size * 2 + name_size;
        //printf("Read 0x%08X bytes from 0x%08X for %s that hashes to 0x%08X\n", file_size, file_offs, file_name, name_hash);

        // single line progress bar extraction test (kinda buggy with long names?)
        //printf("Extracting %3d%% %s\r", (hdr_offs * 100) / hdr_size, file_name);

        pkg->fp_out = create_file(out_path, file_name);
        if (!pkg->fp_out) goto fail;

        // printing here after the path separators get fixed up by create_file
        // one small downside is if the output path is too long, you won't see
        // how long the filename is to try and guess how many dirs to go back.
        // (but like anyone is gonna do that, longest path seen is ~135 chars)
        printf("[%3d%%] Extracting: " STR "\n", hdr_offs * 100 / hdr_size, file_name);


        /////////////////////////////////////////
        // decrypt, decompress, and write data //
        /////////////////////////////////////////

        // ZLIB header is 0xC, ERDA header is 0x8 (+0x8 min with an empty zlib stream)
        if (file_size >= 0x10) {
            tmp_offs = file_offs & 0x7;
            tmp_size = min(file_size, HDR_SIZE - tmp_offs);

            if (!read_buffer(pkg, tmp.i, file_offs, tmp_size))
                goto fail;

            //file_hdr = get_32be(tmp.c, file_offs);
            //if (file_hdr == 'ZLIB' || file_hdr == 'ERDA') { // -Wmultichar warning
            file_hdr = get_32le(tmp.c, tmp_offs);
            if (file_hdr == ID_ZLIB || file_hdr == ID_ERDA) {
                tmp_offs += 0x4;

                if (read_32be(tmp.c, &tmp_offs) != 0x1) {
                    print_err(ERR_ZLIB_BAD_CONFIG);
                    goto fail;
                }

                if (inflate_init(&mz)) {
                    print_err(ERR_ZLIB_INIT);
                    goto fail;
                }
                mz.next_out = mz_buf;
                mz.avail_out = MAX_DEC_SIZE;

                pkg->compressed = true;

                if (file_hdr == ID_ZLIB) { // ERDA doesn't store size
                    dec_size = read_32be(tmp.c, &tmp_offs);
                    file_offs += 0x4;
                    file_size -= 0x4;
                    tmp_size -= 0x4;
                }
                // only process the zlib stream when writing the file
                file_offs += 0x8;
                file_size -= 0x8;
                tmp_size -= 0x8;
            }
            // dump from the buffer to avoid rereading the data twice
            if (!write_chunk(pkg, &tmp.c[tmp_offs], tmp_size))
                goto fail;
            file_offs += tmp_size;
            file_size -= tmp_size;
        }

        if (!write_buffer(pkg, file_offs, file_size)) goto fail;

        if (pkg->compressed) {
            if (file_hdr == ID_ZLIB && dec_size != mz.total_out) {
                print_err(ERR_ZLIB_DECOMPRESS);
                goto fail;
            }
            inflate_end(&mz);
        }
        fclose(pkg->fp_out);
    }


    free(hdr.c);
    free(mz_buf);
    return true;

fail:
    if (pkg->fp_out)
        fclose(pkg->fp_out);
    if (pkg->compressed)
        inflate_end(&mz);
    free(hdr.c);
    free(mz_buf);
    return false;
}


static bool read_package(drm_t *drm, FILE *fp_in, const path_t *out_path, const bool dump_only) {
    uint64_t target_hdr = ID_PACKAGE;
    pkg_t pkg = {0};

    dump_only // also prevents printing a triple-newline if it fails before extracting anything
        ? printf("Dumping PACKAGE file...\n")
        : printf("Reading PACKAGE file...\n");

    pkg.fp_in = fp_in;

    /////////////////////
    // KEY DETERMINING //
    /////////////////////
    if (!read_chunk(&pkg, pkg.buf, BUF_SIZE)) return false;

    pkg.encrypted = (pkg.xor != target_hdr);

    // drm.is_dlc is if PSID is present, pkg.is_dlc is actual
    // status to avoid printing a warn when not expecting one
    // (always check for SingStore DLC DRM keystore presence)
    pkg.is_dlc = read_keystore(fp_in, drm->keystore);
    if (!pkg.is_dlc && drm->is_dlc) {
        print_warn(WARN_PKG_BAD_DRM_KS);
        drm->is_dlc = false;
    }

    if (pkg.encrypted) {
        if (pkg.is_dlc) {
            pkg.is_dlc = decrypt_keystore(drm);
            if (!pkg.is_dlc && drm->is_dlc)
                print_warn(WARN_PKG_BAD_DRM_KS);
        }
        drm->is_dlc = pkg.is_dlc;

        target_hdr ^= pkg.xor;
        pkg.key = get_package_key(drm, target_hdr);
        if (!pkg.key) {
            print_err(ERR_PKG_KEY_UNKNOWN);
            return false;
        }
    }
    else if (pkg.is_dlc && dump_only) {
        pkg.is_dlc = encrypt_keystore(drm);
        if (!pkg.is_dlc && drm->is_dlc)
            print_warn(WARN_PKG_BAD_DRM_KS);
    }

    return dump_only
        ? dump_package(&pkg, drm, out_path)
        : extract_package(&pkg, out_path);
}


// this used to get inlined all the time anyway, when it was a standalone function
// (now it's a macro to allow for automatically converting it to wchar on windows)
#define print_err_usage(...) MACRO( \
    printf( \
        "Usage:  ." PATH_SEP_S "scee_london  \"" HELP_USAGE_IN "\"  [options]\n" \
        "Options:\n" \
        "   -o | --output  <str>  \"" HELP_USAGE_OUT "\"\n" \
        "   -k | --drmkey  <str>  0123456789ABCDEF0123456789ABCDEF\n" \
        "   -d | --dump           Only decrypt or encrypt PACKAGE file\n" \
    ); \
    print_err(__VA_ARGS__); \
)

int main(int argc, path_t **argv) {
    path_t abs_path[FILENAME_MAX];
    path_t out_path[FILENAME_MAX];
    FILE *fp_in = NULL;
    drm_t drm = {0};

    bool has_out_path = false, dump_only = false;

#if IS_WINDOWS //#include <io.h>
    // huh, apparently _O_U8TEXT also just works? i thought wprintf
    // would only work properly with _O_U16TEXT for the final path.
    // HOWEVER wprintf is now no longer line buffered and looks bad
    (void)_setmode(_fileno(stdout), _O_WTEXT);
    (void)_setmode(_fileno(stderr), _O_WTEXT);
    // WriteConsoleW does still remain line buffered, but that's such
    // a braindead way to print anything it's not even worth using it
#endif


    printf(
        "SCEE London Studio PACKAGE tool\n"
        "Written by Edness   " VERSION "\n"
        "2024-07-13 - " BUILDDATE "\n\n"
    );


    if (argc < 2) {
        print_err_usage(ERR_NO_ARGS);
        goto fail;
    }

    fp_in = fopen(argv[1], "rb");
    if (!fp_in) {
        print_err_usage(ERR_BAD_ARG_INFILE);
        goto fail;
    }


    for (int i = 2; i < argc; i++) {
        // another option for plain pkd-pkf decrypt (or recrypt)
        // or alternatively an {enc|dec|rec} switch at the start
        if (is_opt_arg(argv[i], "--dump", "-d")) {
            dump_only = true;
        }
        else if (is_opt_arg(argv[i], "--output", "-o")) {
            const path_t *path = argv[++i];

            // it'll fail if it's too long during the extraction process
            if (i >= argc || strnlen(path, FILENAME_MAX) <= 0) {
                print_err_usage(ERR_BAD_ARG_OUT_PATH);
                goto fail;
            }

            snprintf(out_path, FILENAME_MAX, "%s", path);
            has_out_path = true;
        }
        else if (is_opt_arg(argv[i], "--drmkey", "-k")) {
            const path_t *key = argv[++i];

            // todo: allow longer inputs, filter out spaces
            if (i >= argc || strnlen(key, 0x21) != 0x20) {
                print_err_usage(ERR_BAD_ARG_DRMKEY);
                goto fail;
            }

            for (int j = 0; j < 4; j++) {
                //sscanf(key, "%08X", &psid[j]);
                uint32_t segment = 0x00000000;

                for (int k = j * 8; k < j * 8 + 8; k++) {
                    uint8_t nybble;

                    if (key[k] >= '0' && key[k] <= '9')
                        nybble = key[k] - '0';
                    else if (key[k] >= 'A' && key[k] <= 'F')
                        nybble = key[k] - 'A' + 10;
                    else if (key[k] >= 'a' && key[k] <= 'f')
                        nybble = key[k] - 'a' + 10;
                    else {
                        print_err_usage(ERR_BAD_ARG_DRMKEY);
                        goto fail;
                    }

                    segment <<= 4;
                    segment |= nybble;
                }
                drm.psid[j] = segment;
                //printf("psid[%d] = 0x%08X\n", j, psid[j]);
            }
            drm.is_dlc = true;
        }
        else {
            print_err_usage(ERR_BAD_ARGS, argv[i]);
            goto fail;
        }
    }

    if (!has_out_path) {
        //snprintf(out_path, FILENAME_MAX, dump_only ? "%s.dmp" : "%s_out", argv[1]);
        dump_only // would've preferred the above, but whatever (windows redefs jank)
            ? snprintf(out_path, FILENAME_MAX, "%s.dmp", argv[1])
            : snprintf(out_path, FILENAME_MAX, "%s_out", argv[1]);
    }

    // due to linux/posix shenanigans, the initial absolute path has to be pregenerated here
    // because unlike windows, i can't easily generate a proper canonical path. if there are
    // multiple nonexistent subdirs user wants to dump this to, it'll only go to the 1st one
    get_abspath(out_path, abs_path);


    if (!read_package(&drm, fp_in, abs_path, dump_only))
        goto fail;

    //path_t print_buf[FILENAME_MAX];
    //int print_len = snprintf(print_buf, FILENAME_MAX, "\nDone! Output written to %s\n", abs_path));
    //WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), print_buf, print_len, NULL, NULL);
    printf("\nDone! Output written to %s\n", abs_path);

    fclose(fp_in);
    return 0;

fail:
    if (fp_in)
        fclose(fp_in);
#if IS_WINDOWS
    // user might've drag-dropped it on the .EXE and thus won't see the error
    printf("\nPress any key to continue...\n");
    // the C standard getchar() also doesn't behave quite the same as getch()
    while (!_getch()); //#include <conio.h>
#endif
    return -1;
}

#undef print_err_usage
