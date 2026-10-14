/* Formats numbers and text of every kind the library knows. */
#include "printf.h"

static void count(char character, void *seen)
{
    (void)character;
    ++*(unsigned *)seen;
}

int main(void)
{
    static char line[48];
    unsigned seen = 0;
    printf("%d %5u %-6ld|%08lx %#o %c %s\n", -42, 42u, 123456L, 0xBEEFUL, 8, 'x', "text");
    printf("%f %8.3f %e %g\n", 3.14159f, -2.5f, 12345.678f, 0.0001f);
    snprintf(line, sizeof line, "%+d %x %.3s %%", 7, 255, "abcdef");
    printf("%s %d\n", line, sprintf(line, "%lld", 123456789LL));
    fctprintf(count, &seen, "%10s|%-10s|", "right", "left");
    printf("%u\n", seen);
    for (;;)
        ;
}
