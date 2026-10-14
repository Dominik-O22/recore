/* What uIP leaves to its port: the clock, counted by timer 0, and the network device, which
   here is the serial port with each frame behind its length. */
#include <8051.h>
#include "uip.h"
#include "clock.h"
#include "tapdev.h"

static volatile clock_time_t ticks;

void timer0_tick(void) __interrupt(1)
{
    ticks++;
}

clock_time_t clock_time(void)
{
    clock_time_t now;
    ET0 = 0;
    now = ticks;
    ET0 = 1;
    return now;
}

static unsigned char receive(void)
{
    while (!RI)
        ;
    RI = 0;
    return SBUF;
}

static void send(unsigned char byte)
{
    while (!TI)
        ;
    TI = 0;
    SBUF = byte;
}

void tapdev_init(void)
{
    TMOD = 0x22;
    TH1 = 0xFD;
    SCON = 0x52;
    TR0 = TR1 = 1;
    ET0 = EA = 1;
}

unsigned int tapdev_read(void)
{
    unsigned int length, at;
    if (!RI)
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
