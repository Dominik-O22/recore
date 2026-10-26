// The C runtime game.exe links in place of Microsoft's: the entry point, the C library functions
// the game calls, over kernel32, and the helpers the compiler calls on 32-bit x86. Built with
// -ffreestanding, so the compiler does not turn these loops back into calls to themselves.
#include "libc.h"

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef struct { DWORD low, high; } FILETIME;
typedef struct {
    DWORD attributes;
    FILETIME created, accessed, written;
    DWORD sizeHigh, sizeLow, reserved0, reserved1;
    char name[260], alternateName[14];
} WIN32_FIND_DATAA;
typedef struct {
    DWORD attributes;
    FILETIME created, accessed, written;
    DWORD sizeHigh, sizeLow;
} WIN32_FILE_ATTRIBUTE_DATA;
#define INVALID_HANDLE_VALUE ((HANDLE) -1)
#define K32 __declspec(dllimport)
#define WINAPI __stdcall

K32 __declspec(noreturn) void WINAPI ExitProcess(unsigned code);
K32 HANDLE WINAPI GetProcessHeap(void);
K32 void *WINAPI HeapAlloc(HANDLE heap, DWORD flags, size_t size);
K32 void *WINAPI HeapReAlloc(HANDLE heap, DWORD flags, void *block, size_t size);
K32 BOOL WINAPI HeapFree(HANDLE heap, DWORD flags, void *block);
K32 HANDLE WINAPI GetStdHandle(DWORD which);
K32 HANDLE WINAPI CreateFileA(const char *path, DWORD access, DWORD share, void *security, DWORD disposition, DWORD flags, HANDLE template);
K32 BOOL WINAPI ReadFile(HANDLE file, void *buffer, DWORD size, DWORD *done, void *overlapped);
K32 BOOL WINAPI WriteFile(HANDLE file, const void *buffer, DWORD size, DWORD *done, void *overlapped);
K32 BOOL WINAPI CloseHandle(HANDLE handle);
K32 DWORD WINAPI SetFilePointer(HANDLE file, long distance, long *high, DWORD method);
K32 BOOL WINAPI DeleteFileA(const char *path);
K32 BOOL WINAPI MoveFileA(const char *from, const char *to);
K32 void WINAPI GetSystemTimeAsFileTime(FILETIME *now);
K32 HANDLE WINAPI FindFirstFileA(const char *pattern, WIN32_FIND_DATAA *found);
K32 BOOL WINAPI FindNextFileA(HANDLE find, WIN32_FIND_DATAA *found);
K32 BOOL WINAPI FindClose(HANDLE find);
K32 BOOL WINAPI GetFileAttributesExA(const char *path, int level, WIN32_FILE_ATTRIBUTE_DATA *data);

int main(int argc, char *argv[]);

// The entry point: Brogue's main, with no arguments.
void mainCRTStartup(void) {
    char *argv[] = { "brogue", 0 };
    exit(main(1, argv));
}

void exit(int status) {
    ExitProcess(status);
}

// The compiler refers to this symbol from any object that uses floating point.
int _fltused = 0;

// The quotient of n by d, by shift and subtract, and the remainder in *rem. This file's own 64-bit
// divisions go through it, since the compiler would compile them to calls to __aulldiv.
static unsigned long long udivmod(unsigned long long n, unsigned long long d, unsigned long long *rem) {
    unsigned long long q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = r << 1 | (n >> i & 1);
        if (r >= d) {
            r -= d;
            q |= 1ULL << i;
        }
    }
    if (rem) {
        *rem = r;
    }
    return q;
}

// MSVC's signed 64-bit division, which the compiler calls on 32-bit x86. It is __stdcall, so it
// pops its operands, under its undecorated name.
long long __stdcall alldiv(long long n, long long d) __asm__("__alldiv");
long long __stdcall alldiv(long long n, long long d) {
    unsigned long long q = udivmod(n < 0 ? -(unsigned long long) n : n, d < 0 ? -(unsigned long long) d : d, 0);
    return (n < 0) != (d < 0) ? -(long long) q : (long long) q;
}

// MSVC's stack probe, which the compiler calls at the entry of a function whose frame is larger
// than a page, with the frame's size in eax. It touches each page of the new frame from the top
// down and returns with esp moved below the frame.
__asm__(
    ".text\n"
    ".globl __chkstk\n"
    "__chkstk:\n"
    ".intel_syntax noprefix\n"
    "    push ecx\n"
    "    lea ecx, [esp + 4]\n"
    "    sub ecx, eax\n"
    "    sbb eax, eax\n"
    "    not eax\n"
    "    and ecx, eax\n"
    "    mov eax, esp\n"
    "    and eax, 0xfffff000\n"
    ".Ltest:\n"
    "    cmp ecx, eax\n"
    "    jb .Lprobe\n"
    "    mov eax, ecx\n"
    "    pop ecx\n"
    "    xchg esp, eax\n"
    "    mov eax, dword ptr [eax]\n"
    "    mov dword ptr [esp], eax\n"
    "    ret\n"
    ".Lprobe:\n"
    "    sub eax, 0x1000\n"
    "    test dword ptr [eax], eax\n"
    "    jmp .Ltest\n"
    ".att_syntax prefix\n");

void *malloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void *calloc(size_t count, size_t size) {
    return HeapAlloc(GetProcessHeap(), 8 /* HEAP_ZERO_MEMORY */, count * size);
}

void *realloc(void *block, size_t size) {
    return block ? HeapReAlloc(GetProcessHeap(), 0, block, size) : malloc(size);
}

void free(void *block) {
    if (block) {
        HeapFree(GetProcessHeap(), 0, block);
    }
}

void qsort(void *base, size_t count, size_t size, int (*compare)(const void *, const void *)) {
    char *items = base;
    for (size_t i = 1; i < count; i++) {
        for (size_t j = i; j > 0 && compare(items + (j - 1) * size, items + j * size) > 0; j--) {
            char *a = items + (j - 1) * size, *b = items + j * size;
            for (size_t k = 0; k < size; k++) {
                char t = a[k];
                a[k] = b[k];
                b[k] = t;
            }
        }
    }
}

void *memset(void *dest, int c, size_t n) {
    unsigned char *d = dest;
    while (n--) {
        *d++ = (unsigned char) c;
    }
    return dest;
}

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++)) {
    }
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i]; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = 0;
    }
    return dest;
}

char *strcat(char *dest, const char *src) {
    strcpy(dest + strlen(dest), src);
    return dest;
}

char *strncat(char *dest, const char *src, size_t n) {
    char *d = dest + strlen(dest);
    while (n-- && *src) {
        *d++ = *src++;
    }
    *d = 0;
    return dest;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++, b++;
    }
    return (unsigned char) *a - (unsigned char) *b;
}

int isspace(int c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

int toupper(int c) {
    return c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c;
}

int atoi(const char *text) {
    while (isspace(*text)) {
        text++;
    }
    int sign = *text == '-' ? -1 : 1, n = 0;
    if (*text == '-' || *text == '+') {
        text++;
    }
    while (*text >= '0' && *text <= '9') {
        n = n * 10 + *text++ - '0';
    }
    return sign * n;
}

double sqrt(double x) {
    __asm__("fsqrt" : "+t"(x));
    return x;
}

double sin(double x) {
    __asm__("fsin" : "+t"(x));
    return x;
}

double cos(double x) {
    __asm__("fcos" : "+t"(x));
    return x;
}

long lround(double x) {
    return (long) (x < 0 ? x - 0.5 : x + 0.5);
}

// Times are seconds since 1970 in UTC; the game only shows dates and compares them.
time_t time(time_t *out) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    unsigned long long ticks = (unsigned long long) now.high << 32 | now.low;
    time_t t = udivmod(ticks - 116444736000000000ULL, 10000000, 0);
    if (out) {
        *out = t;
    }
    return t;
}

double difftime(time_t end, time_t start) {
    return (double) (end - start);
}

// Days since 1970-01-01 of a civil date, by Howard Hinnant's algorithm.
static long daysFromCivil(long y, unsigned m, unsigned d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned) (y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    return era * 146097 + (long) (yoe * 365 + yoe / 4 - yoe / 100 + doy) - 719468;
}

struct tm *localtime(const time_t *t) {
    static struct tm tm;
    unsigned long seconds = (unsigned long) *t, z = seconds / 86400 + 719468;
    unsigned long era = z / 146097, doe = z - era * 146097;
    unsigned long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    unsigned long doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    unsigned long m = mp < 10 ? mp + 3 : mp - 9;
    tm.tm_year = (int) (yoe + era * 400 + (m <= 2)) - 1900;
    tm.tm_mon = (int) m - 1;
    tm.tm_mday = (int) (doy - (153 * mp + 2) / 5 + 1);
    tm.tm_hour = (int) (seconds % 86400 / 3600);
    tm.tm_min = (int) (seconds % 3600 / 60);
    tm.tm_sec = (int) (seconds % 60);
    tm.tm_wday = (int) ((seconds / 86400 + 4) % 7);
    tm.tm_yday = (int) (daysFromCivil(tm.tm_year + 1900, m, 1) - daysFromCivil(tm.tm_year + 1900, 1, 1) + tm.tm_mday - 1);
    tm.tm_isdst = 0;
    return &tm;
}

time_t mktime(struct tm *tm) {
    long days = daysFromCivil(tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    return (time_t) days * 86400 + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
}

// The output of a formatting call: characters go to the buffer while room lasts, and count counts
// them all, as snprintf returns.
typedef struct {
    char *at;
    size_t room;
    int count;
} Out;

static void put(Out *out, char c) {
    if (out->room > 1) {
        *out->at++ = c;
        out->room--;
    }
    out->count++;
}

static void putPadded(Out *out, const char *sign, const char *body, int length, int width, int left, int zero) {
    int pad = width - length - (int) strlen(sign);
    if (!left && !zero) {
        for (; pad > 0; pad--) put(out, ' ');
    }
    while (*sign) put(out, *sign++);
    if (zero && !left) {
        for (; pad > 0; pad--) put(out, '0');
    }
    for (int i = 0; i < length; i++) put(out, body[i]);
    for (; pad > 0; pad--) put(out, ' ');
}

// Writes n in base into the end of digits, at least minimum digits, and returns the first.
static char *digitsOf(unsigned long long n, unsigned base, int upper, int minimum, char *end) {
    const char *glyphs = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char *at = end;
    do {
        unsigned long long r;
        n = udivmod(n, base, &r);
        *--at = glyphs[r];
        minimum--;
    } while (n || minimum > 0);
    return at;
}

int vsnprintf(char *buffer, size_t size, const char *format, va_list args) {
    Out out = { buffer, size, 0 };
    for (; *format; format++) {
        if (*format != '%') {
            put(&out, *format);
            continue;
        }
        int left = 0, zero = 0, plus = 0, space = 0, width = 0, precision = -1, longs = 0;
        for (;; format++) {
            if (format[1] == '-') left = 1;
            else if (format[1] == '0') zero = 1;
            else if (format[1] == '+') plus = 1;
            else if (format[1] == ' ') space = 1;
            else if (format[1] != '#') break;
        }
        format++;
        if (*format == '*') {
            width = va_arg(args, int);
            format++;
        } else {
            while (*format >= '0' && *format <= '9') width = width * 10 + *format++ - '0';
        }
        if (*format == '.') {
            format++;
            precision = 0;
            if (*format == '*') {
                precision = va_arg(args, int);
                format++;
            } else {
                while (*format >= '0' && *format <= '9') precision = precision * 10 + *format++ - '0';
            }
        }
        while (*format == 'h' || *format == 'l' || *format == 'z') {
            longs += *format++ == 'l';
        }
        char text[64], *end = text + sizeof text, *body;
        const char *sign = "";
        switch (*format) {
        case 'd':
        case 'i': {
            long long n = longs == 2 ? va_arg(args, long long) : va_arg(args, long);
            sign = n < 0 ? "-" : plus ? "+" : space ? " " : "";
            body = digitsOf(n < 0 ? -(unsigned long long) n : (unsigned long long) n, 10, 0, precision, end);
            putPadded(&out, sign, body, (int) (end - body), width, left, zero);
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        case 'p': {
            unsigned long long n = longs == 2 ? va_arg(args, unsigned long long) : va_arg(args, unsigned long);
            unsigned base = *format == 'u' ? 10 : 16;
            body = digitsOf(n, base, *format == 'X', *format == 'p' ? 8 : precision, end);
            putPadded(&out, sign, body, (int) (end - body), width, left, zero);
            break;
        }
        case 'f': {
            double x = va_arg(args, double);
            if (precision < 0) precision = 6;
            sign = x < 0 ? "-" : plus ? "+" : space ? " " : "";
            unsigned long long scale = 1, fraction;
            for (int i = 0; i < precision; i++) scale *= 10;
            unsigned long long whole = udivmod((unsigned long long) ((x < 0 ? -x : x) * scale + 0.5), scale, &fraction);
            body = precision ? digitsOf(fraction, 10, 0, precision, end) : end;
            if (precision) *--body = '.';
            body = digitsOf(whole, 10, 0, 1, body);
            putPadded(&out, sign, body, (int) (end - body), width, left, zero);
            break;
        }
        case 'c':
            text[0] = (char) va_arg(args, int);
            putPadded(&out, sign, text, 1, width, left, 0);
            break;
        case 's': {
            const char *s = va_arg(args, const char *);
            int length = (int) strlen(s);
            if (precision >= 0 && precision < length) length = precision;
            putPadded(&out, sign, s, length, width, left, 0);
            break;
        }
        case '%':
            put(&out, '%');
            break;
        default:
            format--;
        }
    }
    if (size) {
        *out.at = 0;
    }
    return out.count;
}

int snprintf(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buffer, size, format, args);
    va_end(args);
    return n;
}

int sprintf(char *buffer, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buffer, (size_t) -1, format, args);
    va_end(args);
    return n;
}

// An open file: its handle, fetched on first use for the standard streams, whether a read hit the
// end, and one character fscanf read too far.
struct FILE {
    HANDLE handle;
    DWORD standard;
    int eof, pushed;
};
static FILE outFile = { 0, (DWORD) -11, 0, EOF }, errFile = { 0, (DWORD) -12, 0, EOF };
FILE *stdout = &outFile, *stderr = &errFile;

static HANDLE handleOf(FILE *file) {
    if (!file->handle) {
        file->handle = GetStdHandle(file->standard);
    }
    return file->handle;
}

FILE *fopen(const char *path, const char *mode) {
    DWORD access = 0, disposition = 0;
    switch (mode[0]) {
    case 'r': access = 0x80000000 /* GENERIC_READ */, disposition = 3 /* OPEN_EXISTING */; break;
    case 'w': access = 0x40000000 /* GENERIC_WRITE */, disposition = 2 /* CREATE_ALWAYS */; break;
    case 'a': access = 0x40000000, disposition = 4 /* OPEN_ALWAYS */; break;
    default: return 0;
    }
    if (mode[1] == '+' || (mode[1] && mode[2] == '+')) {
        access = 0xc0000000;
    }
    HANDLE handle = CreateFileA(path, access, 3, 0, disposition, 0x80 /* FILE_ATTRIBUTE_NORMAL */, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    FILE *file = malloc(sizeof *file);
    *file = (FILE) { handle, 0, 0, EOF };
    if (mode[0] == 'a') {
        SetFilePointer(handle, 0, 0, SEEK_END);
    }
    return file;
}

int fclose(FILE *file) {
    CloseHandle(file->handle);
    free(file);
    return 0;
}

size_t fread(void *buffer, size_t size, size_t count, FILE *file) {
    DWORD done = 0;
    if (!size || !count) {
        return 0;
    }
    ReadFile(handleOf(file), buffer, size * count, &done, 0);
    if (done < size * count) {
        file->eof = 1;
    }
    return done / size;
}

size_t fwrite(const void *buffer, size_t size, size_t count, FILE *file) {
    DWORD done = 0;
    if (!size || !count) {
        return 0;
    }
    WriteFile(handleOf(file), buffer, size * count, &done, 0);
    return done / size;
}

int fgetc(FILE *file) {
    unsigned char c;
    if (file->pushed != EOF) {
        int pushed = file->pushed;
        file->pushed = EOF;
        return pushed;
    }
    return fread(&c, 1, 1, file) ? c : EOF;
}

int fputc(int c, FILE *file) {
    unsigned char byte = (unsigned char) c;
    return fwrite(&byte, 1, 1, file) ? byte : EOF;
}

int fputs(const char *text, FILE *file) {
    size_t length = strlen(text);
    return fwrite(text, 1, length, file) == length ? 0 : EOF;
}

int puts(const char *text) {
    return fputs(text, stdout) == EOF ? EOF : fputc('\n', stdout);
}

int putchar(int c) {
    return fputc(c, stdout);
}

char *fgets(char *buffer, int size, FILE *file) {
    int n = 0, c = 0;
    while (n < size - 1 && c != '\n' && (c = fgetc(file)) != EOF) {
        buffer[n++] = (char) c;
    }
    buffer[n] = 0;
    return n ? buffer : 0;
}

int fseek(FILE *file, long offset, int origin) {
    file->eof = 0;
    file->pushed = EOF;
    return SetFilePointer(file->handle, offset, 0, origin) == 0xffffffff ? -1 : 0;
}

long ftell(FILE *file) {
    return (long) SetFilePointer(file->handle, 0, 0, SEEK_CUR) - (file->pushed != EOF);
}

void rewind(FILE *file) {
    fseek(file, 0, SEEK_SET);
}

int feof(FILE *file) {
    return file->eof;
}

static int writeFormatted(FILE *file, const char *format, va_list args) {
    char buffer[1024];
    int n = vsnprintf(buffer, sizeof buffer, format, args);
    fputs(buffer, file);
    return n;
}

int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = writeFormatted(stdout, format, args);
    va_end(args);
    return n;
}

int fprintf(FILE *file, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = writeFormatted(file, format, args);
    va_end(args);
    return n;
}

// The input of a scanning call, a string or a file.
typedef struct {
    const char *text;
    FILE *file;
} In;

static int next(In *in) {
    if (in->file) {
        return fgetc(in->file);
    }
    return *in->text ? (unsigned char) *in->text++ : EOF;
}

static void back(In *in, int c) {
    if (c == EOF) {
        return;
    }
    if (in->file) {
        in->file->pushed = c;
    } else {
        in->text--;
    }
}

// The conversions the game's formats use: whitespace, literals, %d %i %u with h, l and ll, %s and
// %[^...].
static int vscan(In *in, const char *format, va_list args) {
    int assigned = 0, c;
    for (; *format; format++) {
        if (isspace(*format)) {
            while (isspace(c = next(in))) {
            }
            back(in, c);
            continue;
        }
        if (*format != '%') {
            if ((c = next(in)) != (unsigned char) *format) {
                back(in, c);
                return assigned;
            }
            continue;
        }
        format++;
        int shorts = 0, longs = 0;
        while (*format == 'h' || *format == 'l') {
            shorts += *format == 'h';
            longs += *format++ == 'l';
        }
        if (*format == 'd' || *format == 'i' || *format == 'u') {
            while (isspace(c = next(in))) {
            }
            int negative = c == '-', digits = 0;
            if (c == '-' || c == '+') {
                c = next(in);
            }
            unsigned long long n = 0;
            for (; c >= '0' && c <= '9'; c = next(in), digits++) {
                n = n * 10 + (unsigned) (c - '0');
            }
            back(in, c);
            if (!digits) {
                return assigned;
            }
            if (negative) {
                n = -n;
            }
            if (longs == 2) *va_arg(args, unsigned long long *) = n;
            else if (longs == 1) *va_arg(args, unsigned long *) = (unsigned long) n;
            else if (shorts) *va_arg(args, unsigned short *) = (unsigned short) n;
            else *va_arg(args, unsigned *) = (unsigned) n;
            assigned++;
        } else if (*format == 's' || *format == '[') {
            const char *stop = " \t\n\v\f\r";
            int stopLength = 6;
            if (*format == '[') {
                stop = format + 2;
                while (*format != ']') format++;
                stopLength = (int) (format - stop);
            } else {
                while (isspace(c = next(in))) {
                }
                back(in, c);
            }
            char *out = va_arg(args, char *), *start = out;
            while ((c = next(in)) != EOF) {
                int stops = 0;
                for (int i = 0; i < stopLength; i++) stops |= c == (unsigned char) stop[i];
                if (stops) break;
                *out++ = (char) c;
            }
            back(in, c);
            *out = 0;
            if (out == start) {
                return assigned;
            }
            assigned++;
        }
    }
    return assigned;
}

int sscanf(const char *text, const char *format, ...) {
    In in = { text, 0 };
    va_list args;
    va_start(args, format);
    int n = vscan(&in, format, args);
    va_end(args);
    return n;
}

int fscanf(FILE *file, const char *format, ...) {
    In in = { 0, file };
    va_list args;
    va_start(args, format);
    int n = vscan(&in, format, args);
    va_end(args);
    return n;
}

int remove(const char *path) {
    return DeleteFileA(path) ? 0 : -1;
}

int rename(const char *from, const char *to) {
    return MoveFileA(from, to) ? 0 : -1;
}

static time_t unixTime(FILETIME t) {
    unsigned long long ticks = (unsigned long long) t.high << 32 | t.low;
    return udivmod(ticks - 116444736000000000ULL, 10000000, 0);
}

int stat(const char *path, struct stat *out) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExA(path, 0 /* GetFileExInfoStandard */, &data)) {
        return -1;
    }
    out->st_size = (long long) data.sizeHigh << 32 | data.sizeLow;
    out->st_mtime = unixTime(data.written);
    return 0;
}

// An open directory listing: FindFirstFileA's first result is held until the first readdir.
struct DIR {
    HANDLE find;
    int unread;
    WIN32_FIND_DATAA found;
    struct dirent entry;
};

DIR *opendir(const char *path) {
    char pattern[FILENAME_MAX];
    snprintf(pattern, sizeof pattern, "%s*", path);
    DIR *dir = malloc(sizeof *dir);
    dir->find = FindFirstFileA(pattern, &dir->found);
    if (dir->find == INVALID_HANDLE_VALUE) {
        free(dir);
        return 0;
    }
    dir->unread = 1;
    return dir;
}

struct dirent *readdir(DIR *dir) {
    if (!dir->unread && !FindNextFileA(dir->find, &dir->found)) {
        return 0;
    }
    dir->unread = 0;
    strncpy(dir->entry.d_name, dir->found.name, sizeof dir->entry.d_name);
    return &dir->entry;
}

int closedir(DIR *dir) {
    FindClose(dir->find);
    free(dir);
    return 0;
}

size_t strftime(char *buffer, size_t size, const char *format, const struct tm *tm) {
    Out out = { buffer, size, 0 };
    for (; *format; format++) {
        int value = -1, width = 2;
        if (*format != '%') {
            put(&out, *format);
            continue;
        }
        switch (*++format) {
        case 'Y': value = tm->tm_year + 1900, width = 4; break;
        case 'm': value = tm->tm_mon + 1; break;
        case 'd': value = tm->tm_mday; break;
        case 'H': value = tm->tm_hour; break;
        case 'M': value = tm->tm_min; break;
        case 'S': value = tm->tm_sec; break;
        default: put(&out, *format);
        }
        if (value >= 0) {
            char text[16], *end = text + sizeof text;
            for (char *at = digitsOf((unsigned) value, 10, 0, width, end); at < end; at++) put(&out, *at);
        }
    }
    if (size) {
        *out.at = 0;
    }
    return (size_t) out.count < size ? (size_t) out.count : 0;
}
