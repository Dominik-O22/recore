/* CoreMark's port to a Cortex-M: the seeds of a performance run, and time from SysTick. */
#include <stdint.h>
#include "coremark.h"

volatile ee_s32 seed1_volatile = 0x0;
volatile ee_s32 seed2_volatile = 0x0;
volatile ee_s32 seed3_volatile = 0x66;
volatile ee_s32 seed4_volatile = ITERATIONS;
volatile ee_s32 seed5_volatile = 0;

ee_u32 default_num_contexts = 1;

/* SysTick interrupts this many times a second. */
#define TICKS_PER_SECOND 1000

struct systick {
    volatile uint32_t control, reload, value, calibration;
};
#define SYSTICK ((struct systick *)0xE000E010)

static volatile CORE_TICKS ticks;
static CORE_TICKS started, stopped;

void SysTick_Handler(void)
{
    ticks++;
}

void start_time(void)
{
    started = ticks;
}

void stop_time(void)
{
    stopped = ticks;
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
    SYSTICK->reload = 8000000 / TICKS_PER_SECOND - 1;
    SYSTICK->value = 0;
    SYSTICK->control = 7;
    p->portable_id = 1;
}

void portable_fini(core_portable *p)
{
    p->portable_id = 0;
}

/* The notice of barebones/core_portme.c of CoreMark, which this file was changed from. It is
   last so that the lines of the code keep the numbers the corpus's debug records give them.

Copyright 2018 Embedded Microprocessor Benchmark Consortium (EEMBC)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Original Author: Shay Gal-on
*/
