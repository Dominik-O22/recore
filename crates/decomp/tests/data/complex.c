// The source of complex.elf, which tests/debug_types.rs reads.
//   gcc -g -O1 -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,-e,start -o complex.elf complex.c
__attribute__((noinline)) float _Complex twice(float _Complex z) {
    return z + z;
}

void start(void) {
    twice(1.0f);
    for (;;) {}
}
