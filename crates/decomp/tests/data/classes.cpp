// The source of classes.elf, which tests/debug_types.rs reads.
//   g++ -g -O1 -nostdlib -static -fno-stack-protector -fno-asynchronous-unwind-tables -fno-exceptions -Wl,--build-id=none -Wl,-e,start -o classes.elf classes.cpp
struct Tag {};

struct Buffer {
    char *data;
    long length;
    ~Buffer();
};

__attribute__((noinline, noipa)) Buffer::~Buffer() { data = 0; }

__attribute__((noinline, noipa)) long measure(Buffer buffer, Tag tag, long extra) { return buffer.length + extra; }

__attribute__((noinline, noipa)) Buffer make(long length) { return Buffer{0, length}; }

volatile long result;

extern "C" void start() {
    Buffer buffer = make(result);
    result = measure(buffer, Tag{}, 4);
}
