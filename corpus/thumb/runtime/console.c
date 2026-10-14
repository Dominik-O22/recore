/* The serial console: a USART at the address an STM32F1 has its first one, polled to send and
 * read through its interrupt. */
#include <stdint.h>
#include <stdio.h>

struct usart {
    volatile uint32_t status, data, baud, control1, control2, control3, guard;
};
#define USART1 ((struct usart *)0x40013800)
#define TXE (1u << 7)
#define RXNE (1u << 5)

static volatile char received[16];
static volatile unsigned head, tail;

void _putchar(char character)
{
    while (!(USART1->status & TXE))
        ;
    USART1->data = (uint8_t)character;
}

int putchar(int character)
{
    _putchar((char)character);
    return character;
}

int puts(const char *text)
{
    while (*text)
        _putchar(*text++);
    _putchar('\n');
    return 0;
}

void USART1_IRQHandler(void)
{
    while (USART1->status & RXNE) {
        received[head % sizeof received] = (char)USART1->data;
        head++;
    }
}

int getchar(void)
{
    while (tail == head)
        ;
    return received[tail++ % sizeof received];
}
