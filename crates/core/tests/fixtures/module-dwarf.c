// A kernel module with DWARF whose declaration of `panic` does not say that it never returns,
// for the corpus truth's test: where a module has DWARF, the truth takes its word.
// `build-module.sh` makes module-dwarf-arm64.o from it.

extern void panic(const char *fmt, ...);

__attribute__((section(".modinfo"), used)) static const char license[] = "license=GPL";

int checked(int value)
{
    if (value < 0)
        panic("bad value %d\n", value);
    return value + 1;
}
