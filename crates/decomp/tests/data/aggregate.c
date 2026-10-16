// The source of aggregate.elf, which tests/session.rs of the server reads: a structure of more
// than 16 bytes passed by value, which x86-64 System V puts on the stack though registers are free.
//   gcc -O1 -fno-inline -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o aggregate.elf aggregate.c && strip aggregate.elf
struct big {
    long a, b, c, d, e;
};

__attribute__((noinline)) long by_value(long x, long y, struct big v) { return x + y * v.a + v.c - v.e; }

long use(long x) {
    struct big v = { x, 2, 3, 4, x * 2 };
    return by_value(x, 7, v);
}

int main(int n, char **a) {
    (void)a;
    return (int)use(n);
}
