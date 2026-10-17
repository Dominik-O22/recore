// The source of structs.elf and structs.exe, which tests/structs.rs reads: functions that use
// the structs they are passed only through pointers, for recore to recover the layouts from.
//   gcc -O1 -fno-inline -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,-e,start -o structs.elf structs.c && strip structs.elf
//   zig cc -target x86-windows-gnu -O1 -fno-inline -nostdlib -fno-stack-protector -Wl,-e,start -o structs.exe structs.c && strip structs.exe
// zig 0.14 from mise. The PE is 32-bit, so its functions take their parameters on the stack.
struct session {
    int state;
    int retries;
    long long sent;
};

struct conn {
    int id;
    int flags;
    struct session *session;
    int limit;
    int pad;
    long long stamp;
};

struct node {
    int value;
    struct node *next;
};

struct point {
    int x;
    int y;
    int z;
};

// A parameter whose struct holds a pointer to another struct.
__attribute__((noinline)) int touch(struct conn *conn, int value) {
    if (conn->limit < value) {
        conn->session->retries = value;
        conn->stamp = 0;
    }
    return conn->flags;
}

// A list: the pointer read from a field is the pointer the loop goes on with.
__attribute__((noinline)) int sum(struct node *list) {
    int total = 0;
    for (; list; list = list->next) total += list->value;
    return total;
}

// An array of structs, stepped through element by element.
__attribute__((noinline)) int spread(struct point *points, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total += points[i].x * points[i].z;
    return total;
}

// A caller that only passes its parameter on: what `touch` recovers must not show here.
__attribute__((noinline)) int relay(struct conn *conn) {
    return touch(conn, 7) + 1;
}

// The high half of the stamp alone: 4 bytes inside the 8 that `touch` writes, so the struct
// recovered here and `touch`'s cannot be one.
__attribute__((noinline)) int late(struct conn *conn) {
    return ((volatile int *)&conn->stamp)[1] + conn->flags;
}

volatile int sink;

void start(void) {
    struct session session = {0};
    struct conn conn = {1, 2, &session, 3, 0, 4};
    struct node second = {2, 0}, first = {1, &second};
    struct point points[2] = {{1, 2, 3}, {4, 5, 6}};
    sink = touch(&conn, 5) + sum(&first) + spread(points, 2) + relay(&conn) + late(&conn);
}
