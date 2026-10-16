// The source of lines.elf and lines-moved.elf, which tests/session.rs of the server reads: the
// same function twice, with its assertion on another line of the source, as when lines are
// added above it.
//   gcc -O2 -fno-reorder-blocks-and-partition -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o lines.elf lines.c && strip lines.elf
//   gcc -O2 -DMOVED -fno-reorder-blocks-and-partition -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o lines-moved.elf lines.c && strip lines-moved.elf
#include <assert.h>
#include <stdio.h>

__attribute__((noinline)) int checked(int value) {
#ifdef MOVED
#line 1006
#else
#line 1000
#endif
    assert(value > 0);
    return value * 3 + printf("%d\n", value);
}

int main(int count, char **arguments) {
    (void)arguments;
    return checked(count);
}
