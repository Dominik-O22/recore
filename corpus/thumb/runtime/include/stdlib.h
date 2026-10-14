#pragma once
#include <stddef.h>
#define RAND_MAX 0x7fff
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
int abs(int);
long labs(long);
int atoi(const char *);
long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
int rand(void);
void srand(unsigned);
_Noreturn void abort(void);
_Noreturn void exit(int);
