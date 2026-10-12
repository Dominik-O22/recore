// A small C++ program for the class recovery tests: single, multiple and virtual inheritance,
// and a class that cannot be instantiated. `build.sh` compiles it.
namespace zoo {

struct Animal {
    virtual ~Animal() {}
    virtual int legs() const = 0;
    virtual int speak() const { return 1; }
};

struct Dog : Animal {
    int legs() const override { return 4; }
    int speak() const override { return 2; }
};

struct Swimmer {
    virtual int depth() const { return 3; }
    int laps = 0;
};

// Two base classes with virtual functions: two vtables.
struct Duck : Animal, Swimmer {
    int legs() const override { return 2; }
    int depth() const override { return 1; }
};

// A virtual base class: `Bat` carries a vtable naming `Winged` for use while it constructs
// that part, which is not the vtable of `Winged`.
struct Winged : virtual Animal {
    int wings = 2;
    Winged();
    int legs() const override { return 0; }
    virtual int span() const { return wings; }
};

struct Bat : Winged {
    int ears = 2;
    Bat();
    int legs() const override { return ears; }
    int span() const override { return 5; }
};

}

int use(const zoo::Animal *animal) __attribute__((noinline));
int use(const zoo::Animal *animal) { return animal->legs() + animal->speak(); }

// Out of line and opaque, so that the constructors really run through the construction vtable.
zoo::Winged::Winged() { wings = use(this); }
zoo::Bat::Bat() { ears = use(this); }

int main() {
    zoo::Dog dog;
    zoo::Duck duck;
    zoo::Bat bat;
    zoo::Winged winged;
    const zoo::Swimmer *swimmer = &duck;
    return use(&dog) + use(&duck) + use(&bat) + use(&winged) + swimmer->depth();
}
