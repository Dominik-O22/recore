/* What the project's example reads and calls that the C library would give it: lines from
   standard input, here a few sentences a receiver sends, and the time of a date. */
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *const sentences[] = {
    "$GPRMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130998,011.3,E*62\n",
    "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\n",
    "$GPGST,024603.00,3.2,6.6,4.7,47.3,5.8,5.6,22.0*58\n",
    "$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74\n",
    "$GPVTG,096.5,T,083.5,M,0.0,N,0.0,K,D*22\n",
    "$GPZDA,160012.71,11,03,2004,-1,00*7D\n",
    "$GPGLL,3723.2475,N,12158.3416,W,161229.487,A,A*41\n",
};

FILE *stdin;
static unsigned next;

char *fgets(char *line, int size, FILE *stream)
{
    (void)stream;
    if (next == sizeof sentences / sizeof *sentences)
        return 0;
    strncpy(line, sentences[next++], size - 1);
    line[size - 1] = 0;
    return line;
}

/* Days before each month of a year that is not a leap year. */
static const short before_month[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

time_t timegm(struct tm *tm)
{
    long year = tm->tm_year + 1900L;
    long days = (year - 1970) * 365 + (year - 1969) / 4 + before_month[tm->tm_mon] + tm->tm_mday - 1;
    if (tm->tm_mon > 1 && year % 4 == 0)
        days++;
    return ((days * 24 + tm->tm_hour) * 60 + tm->tm_min) * 60LL + tm->tm_sec;
}
