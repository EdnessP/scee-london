// SCEE London Studio PS3 PACKAGE extractor   Written by Edness
#define BUILDDATE "2024-07-13 - 2024-10-19"
#define VERSION "v1.3"

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdint.h>
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

#define HEADER_SIZE 0x18


static FILE *create_file(const path_t *base_path, uint8_t *file_path) {
    path_t out_path[PATH_LEN];
    FILE *out_file;
    int path_len;
    int i = 0;


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
    if (path_len < 0 || path_len >= PATH_LEN) { // swprintf returns -1 instead???
        print_err("File output path is too long!\n");
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

    out_file = fopen(out_path, "wb");
    if (!out_file) {
        print_err("Failed to open the output file! Is it in a read-only location?\n");
        return NULL; // technically not needed since out_file is already NULL
    }

    return out_file;
}


static int extract_package(FILE *in_file, const path_t *out_path) {
    uint8_t size;
    uint16_t flags;
    uint32_t hdr_size, hdr_align, hdr_offs;
    uint8_t hdr_end_read;

    uint32_t iv = 0x00000000;

    char compressed = 0;
    char encrypted = 1;
    uint32_t const *key = NULL;
    uint64_t target_hdr = ID_PACKAGE;

    uint8_t *hdr_c = NULL;
    uint64_t *hdr_i = NULL;
    uint8_t *mz_buf = NULL;

    FILE *out_file = NULL;


    /////////////////////
    // KEY DETERMINING //
    /////////////////////
    if (!fread(pkd.buf, sizeof(pkd.buf), 1, in_file)) {
        print_err("Invalid PACKAGE file!\n");
        goto fail;
    }
    if (pkd.xor == target_hdr) {
        //printf("File is already decrypted!\n");
        encrypted = 0;
    }

    // assigning the correct key pointer avoids it having
    // to calculate the pointer on each read+decrypt call
    if (encrypted) {
        int target_key = -1;

        target_hdr ^= pkd.xor;
        for (int i = 0; i < NUM_KEYS; i++) {
            if ((get_xtea_xor_key(iv, keys[i])) == target_hdr) {
                target_key = i;
                break;
            }
        }
        if (target_key == -1) {
            print_err("Failed to determine PACKAGE encryption key!\n");
            goto fail;
        }

        key = keys[target_key];
    }

    fseek(in_file, 0x0, SEEK_SET);


    ////////////////////
    // INITIALISATION //
    ////////////////////
    hdr_c = (uint8_t *)malloc(HEADER_SIZE);
    hdr_i = (uint64_t *)hdr_c;
    if (!hdr_c) {
        print_err("Failed to allocate memory!\n");
        goto fail;
    }

    for (/*iv = 0*/; iv < 3; iv++) {
        if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, key)) goto fail;
        hdr_i[iv] = pkd.xor;
    }

    /*
    printf("%08X\n", read_32le(hdr_c, 0x8));
    printf("%04X\n", read_16be(hdr_c, 0xC));
    printf("%08X\n", read_32be(hdr_c, 0xE));
    printf("%016llX\n", read_be(hdr_c, 0xE, 8));
    */
    if (read_32le(hdr_c, 0x8) != 1) {
        print_err("Invalid PACKAGE header configuration!\n");
        goto fail;
    }
    flags = read_16be(hdr_c, 0xC);
    // bit 0 is a 64-bit integer flag
    size = (flags & 0x1) ? 0x4 : 0x8;
    // bits 1 and 2 are always set?  the rest are always zero?
    if ((flags & ~0x1) != 0x6) {
        // better optimised than what compilers make of the check
        //  (!(flags & 0x2) || !(flags & 0x4) || (flags & ~0x7))
        print_err("Invalid PACKAGE header configuration!\n");
        goto fail;
    }

    hdr_offs = 0xE + size;
    hdr_size = read_be(hdr_c, 0xE, size) + hdr_offs;
    hdr_end_read = hdr_size & 0x7;
    hdr_align = hdr_size + (0x8 - hdr_end_read);

    hdr_c = (uint8_t *)realloc(hdr_c, hdr_align);
    hdr_i = (uint64_t *)hdr_c;
    if (!hdr_c) {
        print_err("Failed to allocate memory!\n");
        goto fail;
    }

    //hdr_align >>= 3; // div 8
    hdr_align = hdr_size >> 3;
    for (/*iv = 3*/; iv < hdr_align; iv++) {
        if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, key)) goto fail;
        hdr_i[iv] = pkd.xor;
    }
    if (hdr_end_read) {
        if (read_chunk(in_file, hdr_end_read, encrypted, iv, key)) goto fail;
        hdr_i[iv] = pkd.xor;
    }


    ////////////////
    // EXTRACTION //
    ////////////////
    uint8_t file_name[NAME_LEN];
    uint8_t tmp_c[HEADER_SIZE] = {0};
    uint64_t *tmp_i = (uint64_t *)tmp_c;
    mz_stream mz = {0};

    mz_buf = (uint8_t *)malloc(MAX_DEC_SIZE);
    if (!mz_buf) {
        print_err("Failed to allocate memory!\n");
        goto fail;
    }

    while (hdr_offs < hdr_size) {
        int32_t name_size;
        uint32_t name_hash;
        uint64_t file_offs, file_size;
        //uint64_t start_align, end_align;

        uint32_t end_chunk;
        uint64_t start_offs, end_offs;
        uint8_t start_skip, start_read, end_read;

        uint32_t file_hdr;
        uint32_t d_file_size;

        compressed = 0;


        /////////////////////////////////////////
        // read file metadata and prepare data //
        /////////////////////////////////////////
        name_hash = read_32be(hdr_c, hdr_offs); hdr_offs += 4;
        name_size = read_str(hdr_c, hdr_offs, file_name); hdr_offs += name_size;
        //printf("%s = 0x%08X, jamcrc = 0x%08X\n", file_name, name_hash, crc32_jamcrc(file_name, name_size));
        if (name_size < 2 || get_jamcrc_hash(file_name, name_size) != name_hash) {
            print_err("Failed to read PACKAGE file name!\n");
            goto fail;
        }

        // maybe make the reads auto-advance the offset with &hdr_offs
        file_offs = read_be(hdr_c, hdr_offs, size); hdr_offs += size;
        file_size = read_be(hdr_c, hdr_offs, size); hdr_offs += size;

        //hdr_offs += 4 + size * 2 + name_size;
        //printf("Read 0x%08X bytes from 0x%08X for %s that hashes to 0x%08X\n", file_size, file_offs, file_name, name_hash);

        // single line progress bar extraction test (kinda buggy with long names?)
        //printf("Extracting %3d%% %s\r", (hdr_offs * 100) / hdr_size, file_name);


        start_skip = file_offs & 0x7;
        start_offs = file_offs - start_skip;
        start_read = 0x8 - start_skip;

        end_offs = file_offs + file_size;
        end_read = end_offs & 0x7;
        // not aligning end offset, because it will be outside of the loop

        end_chunk = (end_offs - end_read) >> 3;
        iv = start_offs >> 3; // start_chunk

        // i cba to deal with non-standardized 64-bit seeks
        fsetpos(in_file, (fpos_t *)&start_offs);

        out_file = create_file(out_path, file_name);
        if (!out_file) goto fail;

        // printing here after the path separators get fixed up by create_file
        // one small downside is if the output path is too long, you won't see
        // how long the filename is to try and guess how many dirs to go back.
        // (but like anyone is gonna do that, longest path seen is ~135 chars)
        printf("%3d%% | Extracting: %s\n", hdr_offs * 100 / hdr_size, file_name);


        /////////////////////////////////////////
        // decrypt, decompress, and write data //
        /////////////////////////////////////////
        // file is empty
        if (!file_size) goto continue_loop;

        // file is small enough to fit in a single chunk (can't be ZLIB/ERDA)
        // smallest possible size w/ header and an empty zlib stream is 0x14 for ZLIB and 0x10 for ERDA
        if (file_size <= start_read) {
            if (read_chunk(in_file, start_skip + file_size, encrypted, iv, key)) goto fail;
            if (write_chunk(out_file, &pkd.buf[start_skip], file_size, compressed, &mz)) goto fail;
            goto continue_loop;
        }


        for (int i = 0; i < 3; i++) {
            if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv++, key)) goto fail;
            tmp_i[i] = pkd.xor;

            if (iv == end_chunk) {
                if (end_read) {
                    if (read_chunk(in_file, end_read, encrypted, iv, key)) goto fail;
                    tmp_i[++i] = pkd.xor;
                }
                break;
            }
        }

        // this can work around the potential unaligned reads, but meh
        // some testing showed there is either no or next to no impact
        //file_hdr = read_32be(tmp_c, start_skip);
        //if (file_hdr == 'ZLIB' || file_hdr == 'ERDA') { // -Wmultichar warning
        file_hdr = read_32le(tmp_c, start_skip);
        if (file_hdr == ID_ZLIB || file_hdr == ID_ERDA) {
            uint32_t d_start_offs;

            if (read_32be(tmp_c, start_skip + 0x4) != 1) {
                print_err("Invalid compression header configuration!\n");
                goto fail;
            }

            if (mz_inflate_init(&mz)) {
                print_err("Failed to initialise decompressor!\n");
                goto fail;
            }
            mz.next_out = mz_buf;
            mz.avail_out = MAX_DEC_SIZE;

            compressed = 1;

            d_start_offs = 0x8;
            if (file_hdr == ID_ZLIB) { // ERDA doesn't store size
                d_file_size = read_32be(tmp_c, start_skip + 0x8);
                d_start_offs = 0xC;
            }
            // only process the zlib stream
            start_skip += d_start_offs;
            file_size -= d_start_offs;
        }


        if (iv == end_chunk) {
            if (write_chunk(out_file, &tmp_c[start_skip], file_size, compressed, &mz)) goto fail;
            goto continue_loop;
        }

        // unaligned start chunk
        if (write_chunk(out_file, &tmp_c[start_skip], HEADER_SIZE - start_skip, compressed, &mz)) goto fail;
        //if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv++, key)) goto fail;
        //fwrite(&pkd.buf[start_skip], start_read, 1, out_file);

        // aligned main chunks
        for (; iv < end_chunk; iv++) {
            if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, key)) goto fail;
            if (write_chunk(out_file, pkd.buf, sizeof(pkd.buf), compressed, &mz)) goto fail;
        }

        // unaligned end chunk
        // using sizeof(pkd.buf) may cause an EOF error on the final file
        if (end_read) {
            if (read_chunk(in_file, end_read, encrypted, iv, key)) goto fail;
            if (write_chunk(out_file, pkd.buf, end_read, compressed, &mz)) goto fail;
        }

    continue_loop:
        // gotos bad blah blah, im not writing this for each continue;
        if (compressed) {
            if (file_hdr == ID_ZLIB && d_file_size != mz.total_out) {
                print_err("Failed to decompress PACKAGE file data!\n");
                goto fail;
            }
            mz_inflate_end(&mz);
        }
        fclose(out_file);
    }


    free(hdr_c);
    free(mz_buf);
    return 0;

fail:
    if (out_file)
        fclose(out_file);
    if (compressed)
        mz_inflate_end(&mz);
    free(hdr_c);
    free(mz_buf);
    return -1;
}


static void print_err_usage(const char *msg) {
    printf(
        "Usage:    \"" HELP_USAGE_IN "\"\n"
        "Optional: \"" HELP_USAGE_IN "\" \"" HELP_USAGE_OUT "\"\n"
    );
    print_err(msg);
}


int main(int argc, path_t **argv) {
    FILE *in_file = NULL;
    path_t abs_path[PATH_LEN];
    path_t out_path[PATH_LEN];

    printf(
        "SCEE London Studio PACKAGE extractor\n"
        "Written by Edness   " VERSION "\n"
        BUILDDATE "\n\n"
    );


    if (argc < 2) {
        print_err_usage("Not enough arguments!\n");
        goto fail;
    }

    in_file = fopen(argv[1], "rb");
    if (!in_file) {
        print_err_usage("Failed to open the input file!\n");
        goto fail;
    }

    //snprintf(out_path, PATH_LEN, "%s", argc > 2 ? argv[2] : argv[1]);
    if (argc == 2)
        snprintf_path(out_path, PATH_LEN, "%s_out", argv[1]);
    else
        snprintf_path(out_path, PATH_LEN, "%s", argv[2]);
    // due to linux/posix shenanigans, the initial absolute path has to be pregenerated here
    // because unlike windows, i can't easily generate a proper canonical path. if there are
    // multiple nonexistent subdirs user wants to dump this to, it'll only go to the 1st one
    get_abspath(out_path, abs_path);


    // this printf just prevents a triple-newline if it fails before extracting anything lol
    printf("Reading PACKAGE file...\n");
    if (extract_package(in_file, abs_path))
        goto fail;

    // this still prints question marks on windows, but w/e
    printf_path("\nDone! Output written to %s\n", abs_path);
    fclose(in_file);
    return 0;

fail:
    if (in_file)
        fclose(in_file);
#if IS_WINDOWS
    // user might've drag-dropped it on the .EXE and thus won't see the error
    printf("\nPress any key to continue...\n");
    // the C standard getchar() also doesn't behave quite the same as getch()
    while (!getch());
#endif
    return -1;
}
