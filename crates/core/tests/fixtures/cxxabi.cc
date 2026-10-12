// The parts of the C++ runtime library that `classes.cc` needs, for a fixture that links the
// library in instead of importing it: the three type information classes with their vtables.
namespace std {
class type_info {
public:
    virtual ~type_info();
    const char *name;
};
type_info::~type_info() {}
}

namespace __cxxabiv1 {
class __class_type_info : public std::type_info {
public:
    virtual ~__class_type_info();
};
class __si_class_type_info : public __class_type_info {
public:
    virtual ~__si_class_type_info();
    const __class_type_info *base;
};
class __vmi_class_type_info : public __class_type_info {
public:
    virtual ~__vmi_class_type_info();
    unsigned flags, count;
};
__class_type_info::~__class_type_info() {}
__si_class_type_info::~__si_class_type_info() {}
__vmi_class_type_info::~__vmi_class_type_info() {}
}

extern "C" void __cxa_pure_virtual() { for (;;) {} }
void operator delete(void *) noexcept {}
void operator delete(void *, __SIZE_TYPE__) noexcept {}

int main();
extern "C" void _start() {
    main();
    for (;;) {}
}
