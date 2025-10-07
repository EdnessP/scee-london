// SCEE London Studio PS3 PACKAGE extractor   Written by Edness
#define BUILDDATE "2024-07-13 - 2025-10-05"
#define VERSION "v1.4"

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"

#include "decompress.h"
#include "decrypt.h"
#include "hash.h"
#include "reader.h"

#define ID_PACKAGE 0x204547414B434150
#define ID_ZLIB 0x42494C5A
#define ID_ERDA 0x41445245

#define HDR_SIZE 0x18


static FILE *create_file(const path_t *base_path, uint8_t *file_path) {
    path_t out_path[PATH_LEN];
    FILE *fp_out;
    int path_len;
    int i = 0;


    if (file_path) {
#if IS_POSIX
        // PACKAGE filenames normally use backslashes
        while (file_path[i]) {
            if (file_path[i] == '\\')
                file_path[i] = PATH_SEP;
            i++;
        }
        i = 0;
#endif
        path_len = snprintf_path(out_path, PATH_LEN, PATH_JOIN, base_path, file_path);
    }
    else {
        path_len = snprintf_path(out_path, PATH_LEN, "%s", base_path); //strnlen_path;
    }

    if (path_len < 0 || path_len >= PATH_LEN) { // swprintf returns -1 instead???
        print_err(ERR_PKG_PATH_LEN);
        return NULL;
    }

    // ignoring warnings given by create_dir(); fopen()
    // will fail regardless if any serious issues arise
    while (out_path[i]) {
        if (is_path_sep(out_path[i])) {
            out_path[i] = '\x00';
            create_dir(out_path);
            out_path[i] = PATH_SEP;
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


static bool dump_package(pkg_t *pkg, const path_t *out_path) {
    int64_t size;

    pkg->fp_out = create_file(out_path, NULL);
    if (!pkg->fp_out) goto fail;

    size = get_filesize(pkg->fp_in);
    if (has_psid_key) size -= 0x100;

    if (!write_buffer(pkg, 0x0, size)) goto fail;

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

    buf_t hdr = {0};
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
    buf_t tmp = {0}; tmp.c = _tmp;
    uint32_t tmp_offs, tmp_size;
    mz_stream mz = {0};

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
        if (name_size < 1 || get_jamcrc_hash(file_name, name_size) != name_hash) {
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
        printf("[%3d%%] Extracting: %s\n", hdr_offs * 100 / hdr_size, file_name);


        /////////////////////////////////////////
        // decrypt, decompress, and write data //
        /////////////////////////////////////////

        // ZLIB header is 0xC, ERDA header is 0x8 (+0x8 min with an empty zlib stream)
        if (file_size >= 0x10) {
            tmp_offs = file_offs & 0x7;
            tmp_size = min(file_size, HDR_SIZE - tmp_offs);

            if (!read_buffer(pkg, tmp.i, file_offs, tmp_size))
                goto fail;

            // this can work around the potential unaligned reads, but meh
            // some testing showed there is either no or next to no impact
            //file_hdr = get_32be(tmp.c, file_offs);
            //if (file_hdr == 'ZLIB' || file_hdr == 'ERDA') { // -Wmultichar warning
            file_hdr = get_32le(tmp.c, tmp_offs);
            if (file_hdr == ID_ZLIB || file_hdr == ID_ERDA) {
                tmp_offs += 0x4;

                if (read_32be(tmp.c, &tmp_offs) != 0x1) {
                    print_err(ERR_ZLIB_BAD_CONFIG);
                    goto fail;
                }

                if (mz_inflate_init(&mz)) {
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
            write_chunk(pkg, &tmp.c[tmp_offs], tmp_size);
            file_offs += tmp_size;
            file_size -= tmp_size;
        }

        if (!write_buffer(pkg, file_offs, file_size)) goto fail;

        if (pkg->compressed) {
            if (file_hdr == ID_ZLIB && dec_size != mz.total_out) {
                print_err(ERR_ZLIB_DECOMPRESS);
                goto fail;
            }
            mz_inflate_end(&mz);
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
        mz_inflate_end(&mz);
    free(hdr.c);
    free(mz_buf);
    return false;
}


static bool read_package(FILE *fp_in, const path_t *out_path, const bool dump_only) {
    uint64_t target_hdr = ID_PACKAGE;
    pkg_t pkg = {0};

    pkg.fp_in = fp_in;

    /////////////////////
    // KEY DETERMINING //
    /////////////////////
    if (!read_chunk(&pkg, pkg.buf, BUF_SIZE)) return false;

    pkg.encrypted = (pkg.xor != target_hdr);

    // assigning the correct key pointer avoids it having
    // to calculate the pointer on each read+decrypt call
    if (pkg.encrypted) {
        if (has_psid_key) {
            // read last 256 bytes of the file, attempt to
            // decrypt and derive the final pkd keystore
            //has_psid_key = false; // fail
        }

        target_hdr ^= pkg.xor;
        pkg.key = get_package_key(target_hdr);
        if (pkg.key == NULL) {
            print_err(ERR_PKG_KEY_UNKNOWN);
            return false;
        }
    }

    return dump_only
        ? dump_package(&pkg, out_path)
        : extract_package(&pkg, out_path);
}


static void print_err_usage(const char *msg) {
    printf(
        "Usage:  ." HELP_PATH_SEP "scee_london  \"" HELP_USAGE_IN "\"  [options]\n"
        "Options:\n"
        "   -o | --output  <str>  \"" HELP_USAGE_OUT "\"\n"
        "   -k | --drmkey  <str>  0123456789ABCDEF0123456789ABCDEF\n"
        "   -d | --dump           Only decrypt or encrypt PACKAGE file\n"
    );
    print_err(msg);
}


int main(int argc, path_t **argv) {
    FILE *fp_in = NULL;
    path_t abs_path[PATH_LEN];
    path_t out_path[PATH_LEN];

    bool has_out_path = false, dump_only = false;


    printf(
        "SCEE London Studio PACKAGE extractor\n"
        "Written by Edness   " VERSION "\n"
        BUILDDATE "\n\n"
    );


    if (argc < 2) {
        print_err_usage(ERR_NO_ARGS);
        goto fail;
    }

    fp_in = fopen(argv[1], "rb");
    if (!fp_in) {
        print_err_usage(ERR_BAD_ARG_IN_FILE);
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
            if (i >= argc || strnlen_path(path, PATH_LEN) <= 0) {
                print_err_usage(ERR_BAD_ARG_OUT_PATH);
                goto fail;
            }

            snprintf_path(out_path, PATH_LEN, "%s", path);
            has_out_path = true;
        }
        else if (is_opt_arg(argv[i], "--drmkey", "-k")) {
            const path_t *key = argv[++i];

            // todo: allow longer inputs, filter out spaces
            if (i >= argc || strnlen_path(key, 0x21) != 0x20) {
                print_err_usage(ERR_BAD_ARG_DRMKEY);
                goto fail;
            }

            for (int j = 0; j < 4; j++) {
                //sscanf_path(key, "%08X", &psid[j]);
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
                psid[j] = segment;
                //printf("psid[%d] = 0x%08X\n", j, psid[j]);
            }
            has_psid_key = true;
        }
        else {
            // wanted to do %s - args[i], but this is too jankily made
            print_err_usage(ERR_BAD_ARGS);
            goto fail;
        }
    }

    if (!has_out_path)
        snprintf_path(out_path, PATH_LEN, "%s_out", argv[1]);

    // due to linux/posix shenanigans, the initial absolute path has to be pregenerated here
    // because unlike windows, i can't easily generate a proper canonical path. if there are
    // multiple nonexistent subdirs user wants to dump this to, it'll only go to the 1st one
    get_abspath(out_path, abs_path);


    // this printf just prevents a triple-newline if it fails before extracting anything lol
    printf("Reading PACKAGE file...\n");
    if (!read_package(fp_in, abs_path, dump_only))
        goto fail;

    // this still prints question marks on windows, but w/e
    printf_path("\nDone! Output written to %s\n", abs_path);
    //WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), abs_path, PATH_LEN, &a, NULL);
    fclose(fp_in);
    return 0;

fail:
    if (fp_in)
        fclose(fp_in);
#if IS_WINDOWS
    // user might've drag-dropped it on the .EXE and thus won't see the error
    printf("\nPress any key to continue...\n");
    // the C standard getchar() also doesn't behave quite the same as getch()
    while (!_getch());
#endif
    return -1;
}
