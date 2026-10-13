// The source of format.elf, which tests/session.rs of the server reads: a function that takes
// a format and a variable number of arguments, and a caller that looks at an argument before
// passing it.
//   gcc -O2 -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o format.elf format.c && strip format.elf
#include <stdarg.h>
#include <stdio.h>

__attribute__((noinline)) int say(char *out, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int count = vsnprintf(out, 64, format, arguments);
    va_end(arguments);
    return count;
}

__attribute__((noinline)) int report(char *out, const char **commit) {
    const char *text = *commit;
    if (!*text) return say(out, "no commit\n");
    return say(out, "built from commit: %s\n", text);
}

int main(int argc, char **argv) {
    char out[64] = {0};
    return report(out, (const char **)argv + (argc > 1));
}
