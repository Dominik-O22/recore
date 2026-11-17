// A stand-in for a Linux kernel module, compiled as the kernel compiles one: see build-module.sh.
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

static struct ops driver = {probe, remove};

__attribute__((noipa)) int call_probe(struct ops *ops, int id) {
    return ops->probe(id);
}

__attribute__((noipa)) int call_twice(int (*f)(int)) {
    return f(1) + f(2);
}

int init_module(void) {
    return call_probe(&driver, 1) + call_twice(driver.probe);
}
