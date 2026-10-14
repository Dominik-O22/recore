// The source of variadic.bin, which tests/thumb.rs reads: Cortex-M3 flash at 0 with two functions
// that take a variable number of arguments, one a format and one a list of words ended by a null.
//   clang --target=thumbv7m-none-eabi -mcpu=cortex-m3 -O2 -ffreestanding -fno-unwind-tables -c variadic.c
//   rust-lld -flavor gnu -e reset -o variadic.elf variadic.o -T <(echo 'SECTIONS { .text 0 : { KEEP(*(.vectors)) *(.text*) *(.rodata*) }
//     .bss 0x20000000 : { *(.bss*) } /DISCARD/ : { *(.ARM.exidx*) } }')
//   llvm-objcopy -O binary variadic.elf variadic.bin
#include <stdarg.h>

volatile int sink;

__attribute__((noinline)) int say(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int count = 0;
    for (const char *at = format; *at; at++)
        if (*at == '%') count += va_arg(arguments, int);
        else sink = *at;
    va_end(arguments);
    return count;
}

__attribute__((noinline)) int total(const char *first, ...) {
    va_list arguments;
    va_start(arguments, first);
    int length = 0;
    for (const char *word = first; word; word = va_arg(arguments, const char *))
        while (*word++) length++;
    va_end(arguments);
    return length;
}

__attribute__((noinline)) int words(void) { return total("alpha", "beta", "gamma", (const char *)0); }

__attribute__((noinline)) int greet(void) { return say("plain\n") + say("%d and %d\n", 3, 4); }

void reset(void) {
    sink = words() + greet();
    for (;;) {}
}

__attribute__((section(".vectors"), used)) const void *const vectors[16] = {(void *)0x20001000, (void *)reset};
