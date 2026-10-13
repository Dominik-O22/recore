/* What `printf` writes through: the serial port, one byte at a time. */
#include <8051.h>

int putchar(int c)
{
    while (!TI)
        ;
    TI = 0;
    SBUF = c;
    return c;
}
