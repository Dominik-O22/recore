/* `snprintf` over the formatter of SDCC's library, which hands it each character. */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

struct output {
    char *next;
    size_t left;
};

static void store(char character, void *where) __reentrant
{
    struct output *output = where;
    if (output->left > 1) {
        *output->next++ = character;
        output->left--;
    }
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
    struct output output;
    va_list arguments;
    int length;
    output.next = buffer;
    output.left = size;
    va_start(arguments, format);
    length = _print_format(store, &output, format, arguments);
    va_end(arguments);
    if (size)
        *output.next = 0;
    return length;
}
