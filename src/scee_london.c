// SCEE London Studios PS3 PACKAGE tool
#define AUTHOR "Edness"
#define VERSION "v1.2.1"
#define BUILDDATE "2024-07-13 - 2024-09-24"

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "decompress.h"
#include "decrypt.h"
#include "reader.h"

#define ID_PACKAGE 0x204547414B434150
#define ID_ZLIB 0x42494C5A
#define ID_ERDA 0x41445245

#define HEADER_SIZE 0x18


#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
    #define HELP_USAGE_IN "X:\\path\\to\\pack.pkd"
    #define HELP_USAGE_OUT "X:\\path\\to\\out_dir"
    #define PATH_LEN 260
    #define PATH_SEP "\\"
    #include <windows.h>

    #define is_path_sep(c) c == '\\' || c == '/'
    #define create_dir(path) CreateDirectoryA(path, NULL)
    #define get_abspath(path, out) GetFullPathNameA(path, PATH_LEN, out, NULL)

    #define IS_WINDOWS

#elif defined(__unix__) || defined(__APPLE__)
    #define HELP_USAGE_IN "/path/to/pack.pkd"
    #define HELP_USAGE_OUT "/path/to/out_dir"
    #define PATH_LEN 0x1000
    #define PATH_SEP "/"
    #include <sys/stat.h>

    #define is_path_sep(c) c == '/'
    #define create_dir(path) mkdir(path, 0755)
    #define get_abspath(path, out) realpath(path, out) // i wish this was better

    #define IS_UNIX

#endif


static FILE *open_file(const char *base_path, char *file_path) {
    char out_path[PATH_LEN];
    //char *dir = &out_path;
    int i = 0;


#ifdef IS_UNIX
    // PACKAGE filenames normally use backslashes
    while (file_path[i]) {
        if (file_path[i] == '\\')
            file_path[i] = PATH_SEP[0];
        i++;
    }
    i = 0;
#endif
    snprintf(out_path, PATH_LEN, "%s" PATH_SEP "%s", base_path, file_path);

    // ignoring warnings given by create_dir(); fopen()
    // will fail regardless if any serious issues arise
    while (out_path[i]) {
        if (is_path_sep(out_path[i])) {
            out_path[i] = '\x00';
            create_dir(out_path);
            out_path[i] = PATH_SEP[0];
        }
        i++;
    }
    return fopen(out_path, "wb");
}


static int extract_package(FILE *in_file, const char *out_path) {
    uint8_t size;
    uint16_t flags;
    uint32_t hdr_size, hdr_align, hdr_offs;
    uint8_t hdr_end_read;

    uint32_t iv = 0x00000000;

    char compressed = 0;
    char encrypted = 1;
    int target_key = -1;
    //uint32_t key[4] = keys[num_keys - 1];
    uint64_t target_hdr;

    uint8_t *hdr_c = NULL;
    uint64_t *hdr_i = NULL;
    uint8_t *mz_buf = NULL;

    FILE *out_file = NULL;


    //strncpy(pkd.buf, "PACKAGE ", sizeof(pkd.buf));
    target_hdr = ID_PACKAGE; // pkd.xor;


    // find the correct key
    if (!fread(pkd.buf, sizeof(pkd.buf), 1, in_file)) {
        printf("Invalid PACKAGE file!\n");
        goto fail;
    }
    if (pkd.xor == target_hdr) {
        //printf("File is already decrypted!\n");
        encrypted = 0;
    }

    if (encrypted) {
        target_hdr ^= pkd.xor;
        for (int i = 0; i < num_keys; i++) {
            if ((get_xtea_xor_key(iv, keys[i])) == target_hdr) {
                target_key = i;
                break;
            }
        }
        if (target_key == -1) {
            printf("Failed to determine PACKAGE encryption key!\n");
            goto fail;
        }
    }

    fseek(in_file, 0x0, SEEK_SET);


    ////////////////////
    // INITIALISATION //
    ////////////////////
    hdr_c = (uint8_t *)malloc(HEADER_SIZE);
    hdr_i = (uint64_t *)hdr_c;

    if (!hdr_c) {
        printf("Failed to allocate memory!\n");
        goto fail;
    }

    for (/*iv = 0*/; iv < 3; iv++) {
        if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, target_key)) goto fail;
        hdr_i[iv] = pkd.xor;
    }

    /*
    printf("%08X\n", read_32le(hdr_c, 0x8));
    printf("%04X\n", read_16be(hdr_c, 0xC));
    printf("%08X\n", read_32be(hdr_c, 0xE));
    printf("%016llX\n", read_be(hdr_c, 0xE, 8));
    */
    if (read_32le(hdr_c, 0x8) != 1) {
        printf("Invalid PACKAGE header configuration!\n");
        goto fail;
    }
    flags = read_16be(hdr_c, 0xC);
    // bit 0 is a 64-bit integer flag
    size = (flags & 0x1) ? 0x4 : 0x8;
    hdr_offs = 0xE + size;
    // bits 1 and 2 are always set?  the rest are always zero?
    if (!(flags & 0x2) || !(flags & 0x4) || (flags & ~0x7)) {
        printf("Invalid PACKAGE header configuration!\n");
        goto fail;
    }
    hdr_size = read_be(hdr_c, 0xE, size) + hdr_offs;
    hdr_end_read = hdr_size & 0x7;
    hdr_align = hdr_size + (0x8 - hdr_end_read);
    
    hdr_c = (uint8_t *)realloc(hdr_c, hdr_align);
    hdr_i = (uint64_t *)hdr_c;

    if (!hdr_c) {
        printf("Failed to allocate memory!\n");
        goto fail;
    }

    //hdr_align >>= 3; // div 8
    hdr_align = hdr_size >> 3;
    for (/*iv = 3*/; iv < hdr_align; iv++) {
        if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, target_key)) goto fail;
        hdr_i[iv] = pkd.xor;
    }
    if (hdr_end_read) {
        if (read_chunk(in_file, hdr_end_read, encrypted, iv, target_key)) goto fail;
        hdr_i[iv] = pkd.xor;
    }


    ////////////////
    // EXTRACTION //
    ////////////////
    char file_name[NAME_LEN];
    uint8_t tmp_c[HEADER_SIZE] = {0};
    uint64_t *tmp_i = (uint64_t *)tmp_c;
    mz_stream mz = {0};

    mz_buf = (uint8_t *)malloc(MAX_DEC_SIZE);
    if (!mz_buf) {
        printf("Failed to allocate memory!\n");
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

        name_hash = read_32be(hdr_c, hdr_offs); hdr_offs += 4;
        name_size = read_str(hdr_c, hdr_offs, file_name); hdr_offs += name_size;
        //printf("%s = 0x%08X, jamcrc = 0x%08X\n", file_name, name_hash, crc32_jamcrc(file_name, name_size));
        if (name_size < 2 || get_jamcrc_hash(file_name, name_size) != name_hash) {
            printf("Failed to read PACKAGE file name!\n");
            goto fail;
        }

        // maybe make the reads auto-advance the offset with &hdr_offs
        file_offs = read_be(hdr_c, hdr_offs, size); hdr_offs += size;
        file_size = read_be(hdr_c, hdr_offs, size); hdr_offs += size;

        //hdr_offs += 4 + size * 2 + name_size;
        //printf("Read 0x%08X bytes from 0x%08X for %s that hashes to 0x%08X\n", file_size, file_offs, file_name, name_hash);
        printf("Extracting %s\n", file_name);

        out_file = open_file(out_path, file_name);
        if (!out_file) {
            printf("Failed to open the output file! Is it in a read-only location?\n");
            goto fail;
        }


        start_skip = file_offs & 0x7;
        start_offs = file_offs - start_skip;
        start_read = 0x8 - start_skip;

        end_offs = file_offs + file_size;
        end_read = end_offs & 0x7;
        // not aligning end offset, because it will be outside of the loop

        //chunks = (file_size - start_read - end_read) >> 3;
        //chunks = (start_skip + file_size) >> 3;
        end_chunk = (end_offs - end_read) >> 3;
        iv = start_offs >> 3;

        // i cba to deal with non-standardized 64-bit seeks
        fsetpos(in_file, (fpos_t *)&start_offs);

        // file is empty
        if (!file_size) goto continue_loop;

        // file is small enough to fit in a chunk (can't be ZLIB/ERDA)
        // smallest possible size w/ header and an empty zlib stream is 0x14 for ZLIB and 0x10 for ERDA
        if (file_size <= start_read) {
            if (read_chunk(in_file, start_skip + file_size, encrypted, iv, target_key)) goto fail;
            if (write_chunk(out_file, &pkd.buf[start_skip], file_size, compressed, &mz)) goto fail;
            goto continue_loop;
        }


        for (int i = 0; i < 3; i++) {
            if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv++, target_key)) goto fail;
            tmp_i[i] = pkd.xor;

            if (iv == end_chunk && end_read) {
                if (read_chunk(in_file, end_read, encrypted, iv, target_key)) goto fail;
                tmp_i[++i] = pkd.xor;
                break;
            }
        }

        //file_hdr = read_32be(tmp_c, start_skip);
        //if (file_hdr == 'ZLIB' || file_hdr == 'ERDA') { // -Wmultichar warning
        file_hdr = read_32le(tmp_c, start_skip);
        if (file_hdr == ID_ZLIB || file_hdr == ID_ERDA) {
            uint32_t d_start_offs;

            if (read_32be(tmp_c, start_skip + 0x4) != 1) {
                printf("Invalid compression header configuration!\n");
                goto fail;
            }

            if (mz_inflate_init(&mz)) {
                printf("Failed to initialise decompressor!\n");
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
        //if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv++, target_key)) goto fail;
        //fwrite(&pkd.buf[start_skip], start_read, 1, out_file);

        // aligned main chunks
        for (; iv < end_chunk; iv++) {
            if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, target_key)) goto fail;
            if (write_chunk(out_file, pkd.buf, sizeof(pkd.buf), compressed, &mz)) goto fail;
        }

        // unaligned end chunk
        // using sizeof(pkd.buf) may cause an EOF error on the final file
        if (end_read) {
            if (read_chunk(in_file, end_read, encrypted, iv, target_key)) goto fail;
            if (write_chunk(out_file, pkd.buf, end_read, compressed, &mz)) goto fail;
        }

    continue_loop:
        // gotos bad blah blah, i don't wanna write this for each continue;
        if (compressed) {
            if (file_hdr == ID_ZLIB && d_file_size != mz.total_out) {
                printf("Failed to decompress PACKAGE file data!\n");
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

        "\nError: %s\n", msg
    );
}


int main(int argc, char *argv[]) {
    FILE *in_file = NULL;
    char abs_path[PATH_LEN];
    char out_path[PATH_LEN];

    printf(
        "SCEE London Studio PACKAGE extractor\n"
        "Written by " AUTHOR "   " VERSION "\n"
        BUILDDATE "\n\n"
    );


    if (argc < 2) {
        print_err_usage("Not enough arguments!\n");
        return -1;
    }

    //LPWSTR a = GetCommandLineW(); // cba to deal with this
    in_file = fopen(argv[1], "rb");
    if (!in_file) {
        print_err_usage("Failed to open the input file!\n");
#ifdef IS_WINDOWS
        if (strchr(argv[1], '?'))
            printf("Path may contain unicode characters not supported by the current codepage!\n");
#endif
        goto fail;
    }

    //snprintf(out_path, PATH_LEN, "%s", argc > 2 ? argv[2] : argv[1]);
    if (argc == 2)
        snprintf(out_path, PATH_LEN, "%s_out", argv[1]);
    else
        snprintf(out_path, PATH_LEN, "%s", argv[2]);
    // due to linux/posix shenanigans, the initial absolute path has to be pregenerated here
    // because unlike windows, i can't easily generate a proper canonical path. if there are
    // multiple nonexistent subdirs user wants to dump this to, it'll only go to the 1st one
    get_abspath(out_path, abs_path);


    if (extract_package(in_file, abs_path))
        goto fail;

    printf("Done! Output written to %s\n", abs_path);
    fclose(in_file);
    return 0;

fail:
    if (in_file)
        fclose(in_file);
    return -1;
}
