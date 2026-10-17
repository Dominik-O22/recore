// The source of oracle.elf, which tests/session.rs of the server runs functions of.
//   gcc -O1 -fno-inline -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o oracle.elf oracle.c
#include <stdlib.h>
#include <string.h>

long weigh(long a, long b, long c, long d, long e, long f, long g, long h) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

unsigned checksum(const unsigned char *p, unsigned n) {
    unsigned sum = 0;
    for (unsigned i = 0; i < n; i++) sum = sum * 31 + p[i];
    return sum;
}

int divide(int a, int b) { return a / b; }

long collatz(long n) {
    long steps = 0;
    while (n != 1) {
        n = n & 1 ? 3 * n + 1 : n / 2;
        steps++;
    }
    return steps;
}

void reverse(char *s) {
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++) {
        char t = s[i];
        s[i] = s[n - 1 - i];
        s[n - 1 - i] = t;
    }
}

// Copies n bytes of s to the stack and adds the first and the last one.
int ends(const char *s, size_t n) {
    char buf[64];
    memcpy(buf, s, n);
    return buf[0] + buf[n - 1];
}

int classify(int c) {
    switch (c) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 35;
    case 3: return 48;
    case 4: return 52;
    case 5: return 67;
    default: return -1;
    }
}

int counter;

int bump(int by) {
    counter += by;
    return counter;
}

int *table(int n) {
    int *t = malloc(n * sizeof *t);
    for (int i = 0; i < n; i++) t[i] = i * i;
    return t;
}

int main(int argc, char **argv) {
    return (int)weigh(argc, 2, 3, 4, 5, 6, 7, 8) + (int)checksum((unsigned char *)argv[0], 3) + divide(argc, 1) + (int)collatz(argc) +
           (reverse(argv[0]), 0) + ends(argv[0], 2) + classify(argc) + bump(argc) + *table(argc);
}

void fill(char *p, int n) { memset(p, 7, n); }

int locked(int *p) { return __sync_fetch_and_add(p, 3); }

int truncate(double d) { return (int)d; }
