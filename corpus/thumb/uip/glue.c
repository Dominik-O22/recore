/* What uIP leaves to its port: the clock, counted by SysTick, and the network device, which here
   is the second serial port with each frame behind its length. */
#include <stdint.h>
#include "uip.h"
#include "clock.h"
#include "tapdev.h"

struct usart {
    volatile uint32_t status, data, baud, control1, control2, control3, guard;
};
#define USART2 ((struct usart *)0x40004400)
#define TXE (1u << 7)
#define RXNE (1u << 5)

static volatile clock_time_t ticks;

void SysTick_Handler(void)
{
    ticks++;
}

clock_time_t clock_time(void)
{
    return ticks;
}

static unsigned char receive(void)
{
    while (!(USART2->status & RXNE))
        ;
    return (unsigned char)USART2->data;
}

static void send(unsigned char byte)
{
    while (!(USART2->status & TXE))
        ;
    USART2->data = byte;
}

void tapdev_init(void)
{
    USART2->baud = 0x45;
    USART2->control1 = 0x200C;
    *(volatile uint32_t *)0xE000E014 = 8000000 / CLOCK_CONF_SECOND - 1;
    *(volatile uint32_t *)0xE000E010 = 7;
}

unsigned int tapdev_read(void)
{
    unsigned int length, at;
    if (!(USART2->status & RXNE))
        return 0;
    length = receive();
    length = length << 8 | receive();
    for (at = 0; at < length; at++) {
        unsigned char byte = receive();
        if (at < UIP_BUFSIZE)
            uip_buf[at] = byte;
    }
    return length <= UIP_BUFSIZE ? length : 0;
}

void tapdev_send(void)
{
    unsigned int at;
    send(uip_len >> 8);
    send(uip_len);
    for (at = 0; at < uip_len; at++)
        send(uip_buf[at]);
}
