// The part of the C library the game's source calls. libc.c implements, over kernel32, the
// functions the link needs; the rest the compiler folds away. Every standard header the game
// includes is a file that includes this one; clang supplies stddef.h, stdarg.h, stdint.h and
// limits.h.
#ifndef SHIM_LIBC_H
#define SHIM_LIBC_H

#include <stdarg.h>
#include <stddef.h>

// stdio.h
typedef struct FILE FILE;
extern FILE *stdout, *stderr;
#define EOF (-1)
#define FILENAME_MAX 260
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
int printf(const char *format, ...);
int fprintf(FILE *file, const char *format, ...);
int sprintf(char *buffer, const char *format, ...);
int snprintf(char *buffer, size_t size, const char *format, ...);
int vsnprintf(char *buffer, size_t size, const char *format, va_list args);
int sscanf(const char *text, const char *format, ...);
int fscanf(FILE *file, const char *format, ...);
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *file);
size_t fread(void *buffer, size_t size, size_t count, FILE *file);
size_t fwrite(const void *buffer, size_t size, size_t count, FILE *file);
char *fgets(char *buffer, int size, FILE *file);
int fputs(const char *text, FILE *file);
int fputc(int c, FILE *file);
int fgetc(FILE *file);
#define putc fputc
#define getc fgetc
int fseek(FILE *file, long offset, int origin);
long ftell(FILE *file);
void rewind(FILE *file);
int feof(FILE *file);
int fflush(FILE *file);
int remove(const char *path);
int rename(const char *from, const char *to);

// stdlib.h
void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *block, size_t size);
void free(void *block);
void qsort(void *base, size_t count, size_t size, int (*compare)(const void *, const void *));
int abs(int n);
long labs(long n);
long long llabs(long long n);
int atoi(const char *text);
__declspec(noreturn) void exit(int status);

// string.h
void *memset(void *dest, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strcat(char *dest, const char *src);
char *strncat(char *dest, const char *src, size_t n);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);

// ctype.h
int isdigit(int c);
int isalpha(int c);
int isalnum(int c);
int isspace(int c);
int isupper(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int toupper(int c);
int tolower(int c);

// math.h
double sqrt(double x);
double pow(double x, double y);
double floor(double x);
double ceil(double x);
double fabs(double x);
double sin(double x);
double cos(double x);
long lround(double x);

// time.h, with MSVC's 64-bit time_t
typedef long long time_t;
typedef long clock_t;
#define CLOCKS_PER_SEC 1000
struct tm {
    int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
};
time_t time(time_t *out);
clock_t clock(void);
struct tm *localtime(const time_t *t);
time_t mktime(struct tm *tm);
double difftime(time_t end, time_t start);
size_t strftime(char *buffer, size_t size, const char *format, const struct tm *tm);

// assert.h, as a release build compiles it
#define assert(x) ((void) 0)

// sys/types.h, sys/stat.h and dirent.h, enough to list the current directory
struct stat {
    long long st_size;
    time_t st_mtime;
};
int stat(const char *path, struct stat *out);
typedef struct DIR DIR;
struct dirent {
    char d_name[260];
};
DIR *opendir(const char *path);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);

#endif
