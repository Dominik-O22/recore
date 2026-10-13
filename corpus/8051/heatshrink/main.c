/* Compresses a text and expands it again, a few bytes at a time as a small device would. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "heatshrink_encoder.h"
#include "heatshrink_decoder.h"

static const uint8_t text[] = "the quick brown fox jumps over the lazy dog, and the lazy dog lets the quick brown fox";
static uint8_t packed[128], unpacked[128];

static size_t pack(heatshrink_encoder *encoder)
{
    size_t sunk = 0, polled = 0, count;
    while (sunk < sizeof text) {
        heatshrink_encoder_sink(encoder, (uint8_t *)text + sunk, sizeof text - sunk, &count);
        sunk += count;
        if (sunk == sizeof text)
            heatshrink_encoder_finish(encoder);
        while (heatshrink_encoder_poll(encoder, packed + polled, sizeof packed - polled, &count) == HSER_POLL_MORE)
            polled += count;
        polled += count;
    }
    return polled;
}

static size_t unpack(heatshrink_decoder *decoder, size_t length)
{
    size_t sunk = 0, polled = 0, count;
    while (sunk < length) {
        heatshrink_decoder_sink(decoder, packed + sunk, length - sunk, &count);
        sunk += count;
        while (heatshrink_decoder_poll(decoder, unpacked + polled, sizeof unpacked - polled, &count) == HSDR_POLL_MORE)
            polled += count;
        polled += count;
    }
    heatshrink_decoder_finish(decoder);
    return polled;
}

void main(void)
{
    heatshrink_encoder *encoder = heatshrink_encoder_alloc(8, 4);
    heatshrink_decoder *decoder = heatshrink_decoder_alloc(32, 8, 4);
    size_t length = pack(encoder);
    size_t restored = unpack(decoder, length);
    printf("%u -> %u -> %u: %s\n", (unsigned)sizeof text, (unsigned)length, (unsigned)restored,
           memcmp(text, unpacked, sizeof text) ? "differs" : "same");
    heatshrink_encoder_free(encoder);
    heatshrink_decoder_free(decoder);
    for (;;)
        ;
}
