// A small Objective-C program without the SDK: two classes, a category on an imported class,
// a switch, and message sends in both the stub and the classic form.
__attribute__((objc_root_class))
@interface Shape
+ (instancetype)alloc;
- (int)area;
- (int)scaledBy:(int)factor;
@end

@interface Square : Shape
@property int side;
- (int)area;
+ (Square *)withSide:(int)side;
@end

@interface NSObject
@end
@interface NSObject (Shapes)
- (int)corners;
@end

// The linker writes a stub that loads the selector for a call to `_objc_msgSend$<selector>`,
// which is what Apple's clang emits for every message send; this clang does not.
extern int area_through_stub(id, SEL) __asm__("_objc_msgSend$area");
extern int puts(const char *);
extern void abort(void) __attribute__((noreturn));

@implementation Shape
+ (instancetype)alloc { return (id)0; }
- (int)area { return 0; }
- (int)scaledBy:(int)factor { return [self area] * factor; }
@end

@implementation Square
- (int)area { return self.side * self.side; }
+ (Square *)withSide:(int)side {
    Square *square = [Square alloc];
    square.side = side;
    return square;
}
@end

@implementation NSObject (Shapes)
- (int)corners { return 0; }
@end

static const char *name(int corners) {
    switch (corners) {
    case 0: return "circle";
    case 1: return "drop";
    case 2: return "lens";
    case 3: return "triangle";
    case 4: return "square";
    case 5: return "pentagon";
    default: abort();
    }
}

int main(int argc, char **argv) {
    Square *square = [Square withSide:argc];
    puts(name([square scaledBy:2]));
    return area_through_stub(square, 0);
}
