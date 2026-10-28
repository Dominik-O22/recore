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

// Arms of a branch that each hold a loop, one heavier than the other, so the lighter one nests.
EXPORT int arms(int n, int k) {
    int r = n;
    if (n & 1) {
        for (int i = 0; i < (k & 7); i++) r += i * n;
    } else {
        for (int i = 0; i < (n & 15); i++) {
            if (i & 2) r ^= i * k;
            else r -= k;
            if (r & 0x40) r >>= 1;
        }
        r *= 3;
    }
    while (r & 1) r = r / 3 + (r & 0xff);
    return r;
}

// A switch too sparse for a table: a chain of compares, each one level deeper.
EXPORT int sparse(int x) {
    x &= 0x3f;
    switch (x * 37) {
    case 37: return 10;
    case 259: return x * 2;
    case 555: return -x;
    case 1147: return 7;
    case 1665: return x ^ 0x99;
    case 2072: return x + 300;
    default: return x + 1;
    }
}

// Arithmetic under a control word set to single precision, as a software renderer sets it:
// each quotient and sum rounds to 24 bits until the word is put back.
EXPORT unsigned single(int a, int b) {
    volatile int va = a, vb = b | 1;
    unsigned short saved, narrow;
    __asm__ volatile("fnstcw %0" : "=m"(saved) : : "memory");
    narrow = saved & 0xfcff;
    __asm__ volatile("fldcw %0" : : "m"(narrow) : "memory");
    volatile double x = (double)va / (double)vb + 0.1;
    __asm__ volatile("fldcw %0" : : "m"(saved) : "memory");
    Bits r;
    r.d = x;
    return (unsigned)(r.u ^ r.u >> 32);
}

// The same under a control word that rounds up, as some renderers set it, and a store to a
// 4-byte float that rounds up too.
EXPORT unsigned upward(int a, int b) {
    volatile int va = a, vb = b | 1;
    unsigned short saved, up;
    __asm__ volatile("fnstcw %0" : "=m"(saved) : : "memory");
    up = (saved & 0xf3ff) | 0x0800;
    __asm__ volatile("fldcw %0" : : "m"(up) : "memory");
    volatile double x = (double)va / (double)vb + 0.1;
    volatile float y = (float)x * 3.0f;
    __asm__ volatile("fldcw %0" : : "m"(saved) : "memory");
    Bits r;
    r.d = x;
    union {
        float f;
        unsigned u;
    } s = {y};
    return (unsigned)(r.u ^ r.u >> 32) ^ s.u;
}

// The entry point calls nothing; the exports are the functions.
int start(void) { return 0; }
