// The source of oracle-thumb.bin, which tests/session.rs of the server runs functions of: Cortex-M3
// flash at 0 with a few functions, one of which reads a peripheral register.
//   clang --target=thumbv7m-none-eabi -mcpu=cortex-m3 -O1 -ffreestanding -fno-unwind-tables -c oracle-thumb.c
//   rust-lld -flavor gnu -e reset -o oracle-thumb.elf oracle-thumb.o -T <(echo 'SECTIONS { .text 0 : { KEEP(*(.vectors)) *(.text*) *(.rodata*) }
//     .bss 0x20000000 : { *(.bss*) } /DISCARD/ : { *(.ARM.exidx*) } }')
//   llvm-objcopy -O binary oracle-thumb.elf oracle-thumb.bin

unsigned checksum(const unsigned char *p, unsigned n) {
    unsigned sum = 0;
    for (unsigned i = 0; i < n; i++) sum = sum * 31 + p[i];
    return sum;
}

int divide(int a, int b) { return a / b; }

// Six arguments: the last two go on the stack.
int weigh(int a, int b, int c, int d, int e, int f) { return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f; }

int counter;

int bump(int by) {
    counter += by;
    return counter;
}

// The status register of a UART, whose bit 0 says a byte has arrived.
int ready(void) { return *(volatile unsigned *)0x40004000 & 1; }

__attribute__((used, section(".vectors"))) const unsigned vectors[] = {0x20001000, 1};

void reset(void) {
    for (;;) {
        bump(ready());
        bump(divide(weigh(1, 2, 3, 4, 5, 6), (int)checksum((const unsigned char *)vectors, 4)));
    }
}
