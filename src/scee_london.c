// SCEE London Studios PS3 PACKAGE tool
#define AUTHOR "Edness"
#define VERSION "v1.1"
#define BUILDDATE "2024-07-13 - 2024-09-17"

#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pkd_keys.h"
#include "reader.h"


#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
    #define HELP_USAGE_IN "X:\\path\\to\\pack.pkd"
    #define HELP_USAGE_OUT "X:\\path\\to\\out_dir"
    #define PATH_LEN 260
    #define PATH_SEP "\\/"
    #include <windows.h>

    #define create_dir(path) CreateDirectoryA(path, NULL)
    #define get_abspath(path, out) GetFullPathNameA(path, PATH_LEN, out, NULL)

    #define IS_WINDOWS

#elif defined(__unix__) || defined(__APPLE__)
    #define HELP_USAGE_IN "/path/to/pack.pkd"
    #define HELP_USAGE_OUT "/path/to/out_dir"
    #define PATH_LEN 0x1000
    #define PATH_SEP "/"
    #include <sys/stat.h>

    #define create_dir(path) mkdir(path, 0644)
    #define get_abspath(path, out) realpath(path, out) // i wish this was better

    #define IS_UNIX

#endif


static FILE *open_mkdir(const char *base_path, char *file_path) {
    char out_path[PATH_LEN];
    //char *dir = &out_path;
    int i = 0, j = 0;


#ifdef IS_UNIX
    while (file_path[j]) {
        if (file_path[j] == '\\')
            file_path[j] = '/';
        j++;
    }
#endif
    snprintf(out_path, PATH_LEN, "%s/%s", base_path, file_path);

    // strtok also handles skipping doubles
    /*
    printf("%s\n", out_path);
    dirs = strtok(out_path, PATH_SEP);
    while (dirs) {
        printf("%s\n", dirs);
        dirs = strtok(NULL, PATH_SEP);
    }
    */
    while (out_path[i]) {
        j = 0; // variable amount of valid separators
        while (PATH_SEP[j]) {
            if (out_path[i] == PATH_SEP[j]) {
                out_path[i] = '\x00';
                create_dir(out_path);
                out_path[i] = PATH_SEP[0];
                break;
            }
            j++;
        }
        i++;
    }

    return fopen(out_path, "wb");
}


union {
    uint64_t xor;
    uint8_t buf[8];
} pkd = {0};


static uint64_t get_xtea_xor_key(uint32_t v1, const uint32_t key[4]) {
    uint32_t delta = 0x9E3779B9;
    uint32_t v0 = 0x12345678; // iv[0] const
    uint32_t sum = 0;

    for (int i = 0; i < 8; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    return (uint64_t)v1 << 32 | v0;
}


static inline char read_chunk(FILE *in_file, const uint8_t read, const int8_t encrypted, const uint32_t iv, const uint32_t key) {

    if (!fread(pkd.buf, read, 1, in_file)) {
        printf("Failed to read PACKAGE file data!\n");
        return -1;
    }
    if (encrypted)
        pkd.xor ^= get_xtea_xor_key(iv, keys[key]);

    return 0;
}


static int extract_package(FILE *in_file, const char *out_path) {
    uint8_t size;
    uint16_t flags;
    uint32_t hdr_size, hdr_align, hdr_offs;
    uint8_t hdr_end_read;

    uint32_t iv = 0x00000000;

    char encrypted = 1;
    int target_key = -1;
    //uint32_t key[4] = keys[num_keys - 1];
    uint64_t target_hdr;

    uint8_t *hdr_c = NULL;
    uint64_t *hdr_i = NULL;

    FILE *out_file = NULL;


    //strncpy(pkd.buf, "PACKAGE ", sizeof(pkd.buf));
    target_hdr = 0x204547414B434150; // pkd.xor;


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
            }
        }
        if (target_key == -1) {
            printf("Failed to determine PKD key!\n");
            goto fail;
        }
    }


    // decrypt pkd to pkf
    //_fseeki64(in_file, 0x0, SEEK_END);
    //size = _ftelli64(in_file);
    fseek(in_file, 0x0, SEEK_SET);


    /*
    uint8_t remainder = size & 0x7;

    while (fread(pkd.buf, sizeof(pkd.buf), 1, in_file)) {
        pkd.xor ^= get_xtea_xor_key(iv++, target_key);
        fwrite(pkd.buf, sizeof(pkd.buf), 1, out_file);
    }
    pkd.xor ^= get_xtea_xor_key(iv, target_key);
    fwrite(pkd.buf, remainder, 1, out_file);
    return 0;
    */


    //char header[0x18];
    //union {
    //    uint64_t xor[3];
    //    uint8_t buf[0x18];
    //} hdr = {0};
    //if (!fread(hdr.buf, sizeof(hdr.buf), 1, in_file)) {


    /******************/
    /* INITIALISATION */
    /******************/
    hdr_c = (uint8_t *)malloc(0x18);
    hdr_i = (uint64_t *)hdr_c;

    if (hdr_c == NULL) {
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

    if (hdr_c == NULL) {
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


    /**************/
    /* EXTRACTION */
    /**************/
    char file_name[256];
    while (hdr_offs < hdr_size) {
        uint32_t name_hash;
        //int32_t name_size;
        uint64_t file_offs, file_size;
        //uint64_t start_align, end_align;

        uint32_t end_chunk;
        uint64_t start_offs, end_offs;
        uint8_t start_skip, start_read, end_read;


        name_hash = read_32be(hdr_c, hdr_offs); hdr_offs += 4;
        // strncpy or something, return strlen, also check for -1?
        hdr_offs += read_str(hdr_c, hdr_offs, file_name);

        // maybe make the reads advance the offset with &hdr_offs
        file_offs = read_be(hdr_c, hdr_offs, size); hdr_offs += size;
        file_size = read_be(hdr_c, hdr_offs, size); hdr_offs += size;

        //hdr_offs += 4 + size * 2 + str_len;
        //printf("Read 0x%08X bytes from 0x%08X that hashes to 0x%08X for %s\n", file_size, file_offs, name_hash, file_name);
        printf("Extracting %s\n", file_name);

        out_file = open_mkdir(out_path, file_name);
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
        if (!file_size) {
            fclose(out_file);
            continue;
        }

        // file is small enough to fit in a chunk
        if (file_size <= start_read) {
            if (read_chunk(in_file, start_skip + file_size, encrypted, iv, target_key)) goto fail;
            fwrite(&pkd.buf[start_skip], file_size, 1, out_file);
            fclose(out_file);
            continue;
        }

        // unaligned start chunk
        if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv++, target_key)) goto fail;
        fwrite(&pkd.buf[start_skip], start_read, 1, out_file);

        // if file_size > 8, read both and check if it starts with "ZLIB" or "ERDA"
        //uint32_t zlib = 'ZLIB'; // -Wmultichar warning, whatever

        // aligned main chunks
        for (; iv < end_chunk; iv++) {
            if (read_chunk(in_file, sizeof(pkd.buf), encrypted, iv, target_key)) goto fail;
            fwrite(pkd.buf, sizeof(pkd.buf), 1, out_file);
        }

        // unaligned end chunk
        // using sizeof(pkd.buf) may cause an EOF error on the final file
        if (end_read) {
            if (read_chunk(in_file, end_read, encrypted, iv, target_key)) goto fail;
            fwrite(pkd.buf, end_read, 1, out_file);
        }

        fclose(out_file);
    }


    free(hdr_c);
    return 0;

fail:
    if (out_file)
        fclose(out_file);
    free(hdr_c);
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


    //printf("Decrypting...\n");
    //return extract_package(in_file, out_file);
    if (extract_package(in_file, abs_path) != 0)
        goto fail;

    printf("Done! Output written to %s\n", abs_path);
    fclose(in_file);
    return 0;

fail:
    if (in_file)
        fclose(in_file);
    return -1;
}
