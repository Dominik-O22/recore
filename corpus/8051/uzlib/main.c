/* Deflates a text into a zlib stream and inflates it again. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "uzlib.h"

static const uint8_t text[] = "the quick brown fox jumps over the lazy dog, and the lazy dog lets the quick brown fox";
static uint8_t packed[160], unpacked[128];
static uzlib_hash_entry_t hash_table[1 << 6];

void main(void)
{
    struct uzlib_comp deflater;
    struct uzlib_uncomp inflater;
    uint32_t sum = uzlib_adler32(text, sizeof text, 1);
    int result;

    memset(&deflater, 0, sizeof deflater);
    deflater.dict_size = 256;
    deflater.hash_bits = 6;
    deflater.hash_table = hash_table;
    deflater.outbuf = packed + 2;
    deflater.outsize = sizeof packed - 6;
    packed[0] = 0x78;
    packed[1] = 0x01;
    zlib_start_block(&deflater);
    uzlib_compress(&deflater, text, sizeof text);
    zlib_finish_block(&deflater);
    packed[deflater.outlen + 2] = sum >> 24;
    packed[deflater.outlen + 3] = sum >> 16;
    packed[deflater.outlen + 4] = sum >> 8;
    packed[deflater.outlen + 5] = sum;

    uzlib_init();
    uzlib_uncompress_init(&inflater, NULL, 0);
    inflater.source = packed;
    inflater.source_limit = packed + deflater.outlen + 6;
    inflater.dest_start = inflater.dest = unpacked;
    inflater.dest_limit = unpacked + sizeof unpacked;
    result = uzlib_zlib_parse_header(&inflater);
    if (result >= 0)
        result = uzlib_uncompress_chksum(&inflater);
    printf("%d %08lx %08lx %s\n", result, sum, uzlib_crc32(unpacked, sizeof text, 0),
           memcmp(text, unpacked, sizeof text) ? "differs" : "same");
    for (;;)
        ;
}
