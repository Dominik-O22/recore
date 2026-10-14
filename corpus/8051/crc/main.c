/* Prints each checksum of one text. */
#include <stdint.h>
#include <stdio.h>
#include "checksum.h"

static const unsigned char text[] = "123456789";

void main(void)
{
    size_t length = sizeof text - 1;
    printf("%02x %04x %04x %04x\n", crc_8(text, length), crc_16(text, length), crc_modbus(text, length), crc_sick(text, length));
    printf("%04x %04x %04x\n", crc_ccitt_1d0f(text, length), crc_ccitt_ffff(text, length), crc_xmodem(text, length));
    printf("%04x %04x\n", crc_dnp(text, length), crc_kermit(text, length));
    for (;;)
        ;
}
