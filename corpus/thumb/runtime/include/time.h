#pragma once
typedef long long time_t;
struct tm {
    int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
};
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
time_t timegm(struct tm *);
