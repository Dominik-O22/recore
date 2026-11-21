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
extern void panic(const char *fmt, ...) __attribute__((noreturn));

// What MODULE_LICENSE leaves, in the section every module has.
static const char license[] __attribute__((section(".modinfo"), used)) = "license=GPL";

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

// The kernel passes `_THIS_IP_`, the address of a label inside the function, to what traces
// it. The label starts no function: the function's symbol says where the function ends.
__attribute__((noipa)) void traced(unsigned long value) {
    printk("value %lu\n", value);
    printk("at %lx\n", ({ __label__ here; here: (unsigned long)&&here; }));
}

__attribute__((noipa)) int checked(int value) {
    if (value > 4)
        panic("bad value %d\n", value);
    return value * 3;
}

// Hand-written code may name an entry inside a routine, whose symbol's size covers it.
asm(".text\n"
    ".globl outer\n.type outer, %function\nouter:\n\tnop\n"
    ".globl inner\n.type inner, %function\ninner:\n\tret\n"
    ".size inner, . - inner\n.size outer, . - outer\n");
