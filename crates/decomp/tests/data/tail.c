// The source of tail.so, which tests/session.rs of the server reads: a function whose last act is
// a call to an import, which the compiler makes a jump to the import's PLT stub.
//   gcc -O2 -fPIC -shared -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o tail.so tail.c && strip tail.so
#include <stdio.h>

int say(const char *text) {
    return puts(text);
}
