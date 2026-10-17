// The source of imported.so, which tests/session.rs of the server reads: data the C library
// exports, which a shared library reads through its slot in the GOT, and a counter in memory the
// loader zero-fills.
//   gcc -O2 -fPIC -shared -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o imported.so imported.c && strip imported.so
#include <stdio.h>

static long counter;

__attribute__((noinline)) void report(const char *what) {
    counter++;
    fprintf(stderr, "%s %ld\n", what, counter);
}

long reports(void) {
    return counter;
}
