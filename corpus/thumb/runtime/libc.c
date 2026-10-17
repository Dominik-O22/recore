/* What the programs need from the C library beyond newlib-nano's text, number and memory
 * functions: the memory `malloc` takes, and the few functions whose newlib versions bring in
 * the system calls or the per-thread state that a bare device has no use for. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Memory for newlib's `malloc` comes from one static heap, as in many a small device. */
static uint8_t heap[16 * 1024] __attribute__((aligned(8)));
static size_t used;

void *_sbrk(ptrdiff_t increment)
{
    if (increment > (ptrdiff_t)(sizeof heap - used) || -increment > (ptrdiff_t)used)
        return (void *)-1;
    used += increment;
    return heap + used - increment;
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
