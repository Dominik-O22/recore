/* Exercises SDCC's own library: text, numbers of every width, memory, and floating point. */
#include <ctype.h>
#include <math.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char line[64], other[64];
static jmp_buf escape;

#ifdef WITH_NUMBERS
static int by_value(const void *a, const void *b) __reentrant
{
    return *(const int *)a - *(const int *)b;
}

#endif

#ifdef WITH_TEXT
static void text(const char *input)
{
    char *word;
    strcpy(line, input);
    strncat(line, " and more", sizeof line - strlen(line) - 1);
    memmove(other, line + 4, 20);
    other[20] = 0;
    printf("%u %d %d %s\n", (unsigned)strlen(line), strcmp(line, other), strncmp(line, input, 5), strchr(line, 'q'));
    printf("%s %s %u %u\n", strrchr(line, ' '), strstr(line, "fox"), (unsigned)strspn(line, "the "), (unsigned)strcspn(line, "xyz"));
    for (word = strtok(line, " "); word; word = strtok(NULL, " "))
        putchar(toupper(word[0]));
    printf(" %d %d %d\n", isalnum(input[0]), isspace(input[3]), ispunct(input[1]));
    printf("%p %d\n", memchr(input, 'b', 12), memcmp(input, other, 4));
}

#endif

#ifdef WITH_NUMBERS
static void numbers(const char *input)
{
    int values[6] = {31, -4, 15, 9, -26, 5};
    int key = 9;
    long big = strtol(input, NULL, 0);
    unsigned long ubig = strtoul(input, NULL, 16);
    long long huge = atoll(input) * 1000003LL;
    unsigned long long uhuge = (unsigned long long)ubig * ubig;
    div_t parts = div(atoi(input), 7);
    ldiv_t lparts = ldiv(big, 1000);
    qsort(values, 6, sizeof values[0], by_value);
    printf("%d %d %ld %ld %d\n", parts.quot, parts.rem, lparts.quot, lparts.rem, *(int *)bsearch(&key, values, 6, sizeof key, by_value));
    printf("%ld %lu %ld %ld\n", big / 7, ubig % 1000, labs(-big), big * big);
    printf("%d %d %d\n", (int)(huge / 3), (int)(huge % 1000), (int)(uhuge >> 13));
    printf("%d %u %d\n", abs(values[0]) * values[1], (unsigned)values[2] / 3u, values[3] % 4);
    srand(atoi(input));
    printf("%d %d\n", rand(), rand());
    __itoa(values[0], line, 10);
    __ltoa(big, other, 16);
    printf("%s %s %ld\n", line, other, atol(other));
}

#endif

#ifdef WITH_TEXT
static void memory(void)
{
    char *first = malloc(24), *second = calloc(4, 8);
    if (!first || !second)
        longjmp(escape, 1);
    memset(first, 'a', 23);
    first[23] = 0;
    first = realloc(first, 48);
    memcpy(second, first, 8);
    printf("%s %c\n", first, second[7]);
    free(first);
    free(second);
}

#endif

#ifdef WITH_FLOAT
static void floating(float x)
{
    float y = sqrtf(x) + powf(x, 1.5f) - fabsf(-x);
    int exponent;
    printf("%d %d %d\n", (int)(sinf(x) * 1000), (int)(cosf(x) * 1000), (int)(tanf(x) * 1000));
    printf("%d %d %d\n", (int)(atanf(x) * 1000), (int)(asinf(x / 8) * 1000), (int)(atan2f(x, y) * 1000));
    printf("%d %d %d\n", (int)(expf(x) * 10), (int)(logf(x) * 1000), (int)(log10f(x) * 1000));
    printf("%d %d %d\n", (int)(sinhf(x) * 10), (int)(coshf(x) * 10), (int)(tanhf(x) * 1000));
    printf("%d %d %d %d\n", (int)floorf(y), (int)ceilf(y), (int)(frexpf(y, &exponent) * 1000), (int)ldexpf(x, 3));
    printf("%d %d %d\n", (int)(y * x / 3.0f), (int)(unsigned char)y, (int)(long)(y - x) + (x < y) + (x == y));
    printf("%d\n", (int)(atof("2.5") * 4));
}

#endif

#ifdef WITH_NUMBERS
static void dates(void)
{
    struct tm when;
    time_t stamp = 1791849600UL;
    when = *gmtime(&stamp);
    printf("%d-%d-%d %s", when.tm_year + 1900, when.tm_mon + 1, when.tm_mday, asctime(&when));
    printf("%lu\n", (unsigned long)mktime(&when));
}

#endif

void main(void)
{
    if (setjmp(escape) == 0) {
#ifdef WITH_TEXT
        text("the quick brown fox");
        memory();
#endif
#ifdef WITH_NUMBERS
        numbers("12345");
        dates();
#endif
#ifdef WITH_FLOAT
        floating(1.25f);
#endif
        sprintf(line, "%5d|%-5u|%05x|%c|%s|%lu", -7, 7u, 0xabc, 'z', "end", 100000UL);
        puts(line);
    }
    for (;;)
        ;
}
