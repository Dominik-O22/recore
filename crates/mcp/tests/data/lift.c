// What tests/lift.rs lifts and runs against the emulator: a 32-bit Windows program, x87 for
// floats, with no C library. Each function is exported so the test finds it by name. Rebuild
// lift.exe with tests/data/build-lift.sh after a change here.

#define EXPORT __declspec(dllexport)

// The linker asks for this symbol from any object that uses floats; the C library defines it.
int _fltused;

typedef union {
    double d;
    unsigned long long u;
} Bits;

// A loop with a branch in it.
EXPORT int collatz(unsigned n) {
    int steps = 0;
    n = n % 1000 + 1;
    while (n != 1 && steps < 500) {
        n = n & 1 ? 3 * n + 1 : n / 2;
        steps++;
    }
    return steps;
}

// A switch dense enough for a jump table.
EXPORT int classify(int x) {
    switch (x & 15) {
    case 0: return 11;
    case 1: return x * 3;
    case 2: return x - 7;
    case 3: return x ^ 0x55;
    case 4: return -x;
    case 5: return x << 2;
    case 6: return x >> 1;
    case 7: return 1234;
    case 9: return x | 0x100;
    default: return 0;
    }
}

// Shifts, rotation, multiplication, division and remainder, signed and not.
EXPORT unsigned mix(unsigned a, unsigned b) {
    unsigned r = (a << 7 | a >> 25) ^ (b * 2654435761u);
    unsigned d = b | 1;
    int s = (int)a / (int)(d & 0xff);
    return r + a / d + a % d + (unsigned)s + (unsigned)((int)b >> 3);
}

// Recursion, so calls go through `dispatch` to the lifted function itself.
EXPORT int fib(int n) {
    n &= 15;
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

// A local array on the stack.
EXPORT int sum_squares(int n) {
    int values[32];
    int total = 0;
    n &= 31;
    for (int i = 0; i < n; i++) values[i] = i * i - n;
    for (int i = n - 1; i >= 0; i--) total += values[i] * (i & 3);
    return total;
}

// A global the function reads and writes.
static unsigned state = 0x12345678;

EXPORT unsigned step(unsigned x) {
    state = state * 1103515245u + 12345u + x;
    return state >> 3;
}

static int negate(int x) { return -x; }
static int twice(int x) { return 2 * x; }
static int square(int x) { return x * x; }

// Calls through a table of functions in data, which only the scan of data words finds.
EXPORT int apply(unsigned which, int x) {
    static int (*const table[])(int) = {negate, twice, square};
    return table[which % 3](x);
}

// x87 arithmetic, a square root and the bits of the result.
EXPORT unsigned length(int a, int b) {
    Bits r;
    r.d = __builtin_sqrt((double)a * a + (double)b * b) / 3.0;
    return (unsigned)(r.u ^ r.u >> 32);
}

// x87 comparisons, and a double cut to an integer.
EXPORT int scaled(int a, int b) {
    double x = a * 1.5, y = b * 0.75 - 2.25;
    int sign = x < y ? -1 : x > y ? 1 : 0;
    return sign * 1000 + (int)(x * y / 64.0);
}

// A float the callee returns in ST0, which the caller goes on to use.
__attribute__((noinline)) static double half(double x) { return x * 0.5; }

EXPORT int halves(int a) {
    double x = a;
    for (int i = 0; i < 4; i++) x = half(x) + 1.0;
    Bits r;
    r.d = x;
    return (int)(r.u >> 20);
}

// The entry point calls nothing; the exports are the functions.
int start(void) { return 0; }
