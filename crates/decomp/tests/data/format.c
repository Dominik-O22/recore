// The source of format.elf, which tests/session.rs of the server reads: a function that takes
// a variable number of arguments, and a caller that looks at an argument before passing it.
//   gcc -O2 -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,-e,start -o format.elf format.c
#include <stdarg.h>

volatile int written;

__attribute__((noinline)) int emit(char *out, const char *format, va_list arguments) {
    written += out[0] + format[0] + va_arg(arguments, int);
    return written;
}

__attribute__((noinline)) int say(char *out, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int count = emit(out, format, arguments);
    va_end(arguments);
    return count;
}

__attribute__((noinline)) int report(char *out, const char **commit) {
    const char *text = *commit;
    if (!*text) return say(out, "no commit\n");
    return say(out, "built from commit: %s\n", text);
}

void start(void) {
    static const char *commit = "abc";
    char out[16] = {0};
    report(out, &commit);
}
