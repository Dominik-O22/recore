// The source of chain.elf, which tests/session.rs of the server reads: `top` calls `near`, which
// jumps to `mid`, which jumps to `leaf`. The others call those two so that they stay functions.
//   gcc -O2 -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -fno-inline -Wl,--build-id=none -o chain.elf chain.c && strip chain.elf
volatile int sink;

int leaf(int x) {
    sink = x;
    return sink + 1;
}

int mid(int x) {
    return leaf(x + 2);
}

int near(int x) {
    return mid(x + 3);
}

int top(int x) {
    return near(x) * 3;
}

int other(int x) {
    return leaf(x) + mid(x) * 5;
}

void _start(void) {
    sink = top(sink) + other(sink);
    __asm__("mov $60, %eax; xor %edi, %edi; syscall");
}
