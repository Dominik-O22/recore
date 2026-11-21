// The source of opaque.elf, which tests/session.rs of the server reads: functions whose debug
// information says they take a pointer to a struct the program declares and never defines, as
// a kernel prototype names one, and read fields through it.
//   gcc -O1 -g -fno-inline -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,-e,start -o opaque.elf opaque.c
struct device;

int poll(struct device *dev, int limit) {
    int *words = (int *)dev;
    if (words[4] < limit)
        words[2] = limit;
    return words[1];
}

long reset(struct device *dev) {
    long *words = (long *)dev;
    words[3] = 0;
    return words[0];
}

static int buffer[8];

void start(void) {
    poll((struct device *)buffer, 3);
    reset((struct device *)buffer);
}
