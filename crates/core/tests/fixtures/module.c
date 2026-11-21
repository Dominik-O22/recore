// A stand-in for a Linux kernel module, compiled as the kernel compiles one for x86-64 and for
// AArch64: see build-module.sh.
struct ops {
    int (*probe)(int);
    void (*remove)(void);
};

extern void *kmalloc(unsigned long size);
extern void kfree(void *p);
extern int printk(const char *fmt, ...);
extern unsigned long jiffies;

static int probe(int id) {
    void *p = kmalloc(id);
    if (!p)
        return -12;
    printk("probe %d at %lu\n", id, jiffies);
    kfree(p);
    return 0;
}

static void remove(void) {
    printk("remove\n");
}

// `used`, or clang sees that nothing reads `remove` and drops it.
static struct ops driver __attribute__((used)) = {probe, remove};

__attribute__((noipa)) int call_probe(struct ops *ops, int id) {
    return ops->probe(id);
}

__attribute__((noipa)) int call_twice(int (*f)(int)) {
    return f(1) + f(2);
}

int init_module(void) {
    return call_probe(&driver, 1) + call_twice(driver.probe);
}

#ifdef __aarch64__
// kCFI puts a hash of each function's type before it, as a word of data. These structures are
// named so that the hash before the function that takes one reads as an `adr` into another
// function: to an instruction, and off a word.
struct w3671628;
struct u0341202;

int kcfi_word(struct w3671628 *p) {
    return p != 0;
}

int kcfi_off_word(struct u0341202 *p) {
    return p == 0;
}
#endif
