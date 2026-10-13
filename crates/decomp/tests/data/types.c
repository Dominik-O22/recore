// The source of types.elf and types.exe with types.pdb, which tests/debug_types.rs reads.
//   gcc -g -O1 -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,-e,start -o types.elf types.c
//   x86_64-w64-mingw32-clang -g -gcodeview -O1 -nostdlib -Wl,--pdb=types.pdb -Wl,-e,start -o types.exe types.c
// With -DPATCHED and without -g it is types-patched.elf, a later build of the same program for
// the `diff` tool: `total` has a check it lacked, and `clamp` is new.
struct node {
    int value;
    struct node *next;
};

typedef enum { RED, GREEN = 5 } color;

union number {
    int whole;
    float real;
};

struct shape {
    color tint;
    union number size;
    unsigned visible : 1;
    unsigned layer : 4;
    struct node *points;
    int (*area)(struct shape *shape, int scale);
};

struct node *head;

#ifdef PATCHED
__attribute__((noinline)) int clamp(int value) {
    return value > 1000 ? 1000 : value;
}
#endif

__attribute__((noinline)) int total(struct node *list, int scale) {
    int sum = 0;
#ifdef PATCHED
    if (scale > 100) return clamp(scale);
#endif
    for (; list; list = list->next) sum += list->value * scale;
    return sum;
}

__attribute__((noinline)) int draw(struct shape *shape) {
    if (shape->visible) return shape->area(shape, 3) + shape->layer;
    return shape->tint;
}

void start(void) {
    struct shape shape = {0};
    head = 0;
    draw(&shape);
    total(head, 2);
}
