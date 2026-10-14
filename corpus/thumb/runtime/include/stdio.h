#pragma once
/* `printf` and its kin are the printf project's, which renames them to end in `_`. */
#include <stddef.h>
#include <stdarg.h>
#include "printf.h"
#define EOF (-1)
int putchar(int);
int puts(const char *);
int getchar(void);
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
