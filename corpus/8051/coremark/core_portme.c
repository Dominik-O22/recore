/* CoreMark's port to an 8051: the seeds of a performance run, and time from timer 0. */
#include <8051.h>
#include "coremark.h"

volatile ee_s32 seed1_volatile = 0x0;
volatile ee_s32 seed2_volatile = 0x0;
volatile ee_s32 seed3_volatile = 0x66;
volatile ee_s32 seed4_volatile = ITERATIONS;
volatile ee_s32 seed5_volatile = 0;

ee_u32 default_num_contexts = 1;

/* Timer 0 overflows this many times a second at 12 MHz. */
#define TICKS_PER_SECOND 15

static volatile CORE_TICKS ticks;
static CORE_TICKS started, stopped;

void timer0_tick(void) __interrupt(1)
{
    ticks++;
}

static CORE_TICKS now(void)
{
    CORE_TICKS value;
    ET0 = 0;
    value = ticks;
    ET0 = 1;
    return value;
}

void start_time(void)
{
    started = now();
}

void stop_time(void)
{
    stopped = now();
}

CORE_TICKS get_time(void)
{
    return stopped - started;
}

secs_ret time_in_secs(CORE_TICKS elapsed)
{
    return (secs_ret)elapsed / TICKS_PER_SECOND;
}

void portable_init(core_portable *p, int *argc, char *argv[])
{
    (void)argc;
    (void)argv;
    TMOD = 0x21;
    TH1 = 0xFD;
    SCON = 0x52;
    TR0 = TR1 = 1;
    ET0 = EA = 1;
    p->portable_id = 1;
}

void portable_fini(core_portable *p)
{
    p->portable_id = 0;
}
