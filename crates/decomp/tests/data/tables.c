// The source of tables.elf, which tests/session.rs of the server reads: a table of records that
// open with a name and have a number among their pointers, as a Python module lists its
// functions, and a table of pairs that close with the name, as Python lists its exceptions.
//   gcc -O2 -fPIE -pie -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -o tables.elf tables.c && strip tables.elf
#include <stdio.h>

struct method {
    const char *name;
    int (*call)(int);
    long flags;
    const char *doc;
};

struct pair {
    const int *type;
    const char *name;
};

__attribute__((noinline)) int twice(int value) { return value * 2 + printf(""); }
__attribute__((noinline)) int negate(int value) { return -value + printf(""); }
__attribute__((noinline)) int square(int value) { return value * value + printf(""); }

const struct method methods[] = {
    { "twice", twice, 8, "Return the value doubled." },
    { "negate", negate, 8, "Return the value with its sign turned." },
    { "square", square, 8, "Return the value times itself." },
    { 0, 0, 0, 0 },
};

const int value_error = 1, type_error = 2, key_error = 3;

const struct pair errors[] = {
    { &value_error, "ValueError" },
    { &type_error, "TypeError" },
    { &key_error, "KeyError" },
    { 0, 0 },
};

int main(int count, char **arguments) {
    (void)arguments;
    const struct method *method = &methods[count % 3];
    printf("%s %d %s %d\n", method->doc, method->call(count), errors[count % 3].name, *errors[count % 3].type);
    return 0;
}
