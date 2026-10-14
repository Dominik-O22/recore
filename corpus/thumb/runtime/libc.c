/* The part of the C library the programs call that the compiler's helpers do not have: text,
 * numbers, and memory from one static heap. */
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t strlen(const char *s)
{
    const char *end = s;
    while (*end)
        end++;
    return end - s;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (; n; n--, a++, b++)
        if (*a != *b || !*a)
            return (unsigned char)*a - (unsigned char)*b;
    return 0;
}

char *strcpy(char *to, const char *from)
{
    char *start = to;
    while ((*to++ = *from++))
        ;
    return start;
}

char *strncpy(char *to, const char *from, size_t n)
{
    char *start = to;
    for (; n && *from; n--)
        *to++ = *from++;
    for (; n; n--)
        *to++ = 0;
    return start;
}

char *strcat(char *to, const char *from)
{
    strcpy(to + strlen(to), from);
    return to;
}

char *strchr(const char *s, int c)
{
    for (; *s; s++)
        if (*s == (char)c)
            return (char *)s;
    return c ? 0 : (char *)s;
}

char *strrchr(const char *s, int c)
{
    const char *found = 0;
    do
        if (*s == (char)c)
            found = s;
    while (*s++);
    return (char *)found;
}

char *strstr(const char *haystack, const char *needle)
{
    size_t length = strlen(needle);
    for (; *haystack; haystack++)
        if (!strncmp(haystack, needle, length))
            return (char *)haystack;
    return length ? 0 : (char *)haystack;
}

size_t strspn(const char *s, const char *accept)
{
    size_t n = 0;
    while (s[n] && strchr(accept, s[n]))
        n++;
    return n;
}

size_t strcspn(const char *s, const char *reject)
{
    size_t n = 0;
    while (s[n] && !strchr(reject, s[n]))
        n++;
    return n;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;
    for (; n; n--, p++)
        if (*p == (unsigned char)c)
            return (void *)p;
    return 0;
}

int isdigit(int c) { return c >= '0' && c <= '9'; }
int isspace(int c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
int isupper(int c) { return c >= 'A' && c <= 'Z'; }
int islower(int c) { return c >= 'a' && c <= 'z'; }
int isalpha(int c) { return isupper(c) || islower(c); }
int isalnum(int c) { return isalpha(c) || isdigit(c); }
int isxdigit(int c) { return isdigit(c) || ((c | 0x20) >= 'a' && (c | 0x20) <= 'f'); }
int isprint(int c) { return c >= 0x20 && c < 0x7f; }
int toupper(int c) { return islower(c) ? c - 0x20 : c; }
int tolower(int c) { return isupper(c) ? c + 0x20 : c; }

int abs(int n) { return n < 0 ? -n : n; }
long labs(long n) { return n < 0 ? -n : n; }

unsigned long strtoul(const char *s, char **end, int base)
{
    unsigned long value = 0;
    while (isspace(*s))
        s++;
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] | 0x20) == 'x')
        s += 2, base = 16;
    else if (base == 0)
        base = *s == '0' ? 8 : 10;
    for (;; s++) {
        int digit = isdigit(*s) ? *s - '0' : isalpha(*s) ? (*s | 0x20) - 'a' + 10 : base;
        if (digit >= base)
            break;
        value = value * base + digit;
    }
    if (end)
        *end = (char *)s;
    return value;
}

long strtol(const char *s, char **end, int base)
{
    while (isspace(*s))
        s++;
    if (*s == '-')
        return -(long)strtoul(s + 1, end, base);
    return (long)strtoul(*s == '+' ? s + 1 : s, end, base);
}

int atoi(const char *s)
{
    return (int)strtol(s, 0, 10);
}

static unsigned long next_random = 1;

int rand(void)
{
    next_random = next_random * 1103515245 + 12345;
    return (int)(next_random >> 16) & RAND_MAX;
}

void srand(unsigned seed)
{
    next_random = seed;
}

/* Memory comes from one static heap and is never given back, as in many a small device. Each
 * block starts with its size, which is all `realloc` needs to know. */
static uint8_t heap[16 * 1024] __attribute__((aligned(8)));
static size_t used;

void *malloc(size_t size)
{
    size = (size + 7) & ~(size_t)7;
    if (size + 8 > sizeof heap - used)
        return 0;
    *(size_t *)(heap + used) = size;
    used += size + 8;
    return heap + used - size;
}

void *calloc(size_t count, size_t size)
{
    void *p = malloc(count * size);
    if (p)
        memset(p, 0, count * size);
    return p;
}

void *realloc(void *p, size_t size)
{
    void *moved = malloc(size);
    if (p && moved) {
        size_t old = *(size_t *)((uint8_t *)p - 8);
        memcpy(moved, p, old < size ? old : size);
    }
    return moved;
}

void free(void *p)
{
    (void)p;
}

/* Square roots by Newton's method, from a first guess that halves the exponent. */
double sqrt(double x)
{
    double root = x > 1 ? x / 2 : 1;
    if (x <= 0)
        return 0;
    for (int step = 0; step < 40; step++)
        root = (root + x / root) / 2;
    return root;
}

float sqrtf(float x)
{
    return (float)sqrt(x);
}

float fabsf(float x)
{
    return x < 0 ? -x : x;
}

double fabs(double x)
{
    return x < 0 ? -x : x;
}

void abort(void)
{
    __asm volatile("bkpt #0");
    for (;;)
        ;
}

void exit(int status)
{
    (void)status;
    for (;;)
        ;
}

void __assert_fail(const char *expression, const char *file, int line)
{
    (void)expression, (void)file, (void)line;
    abort();
}
