// The source of short.elf, which tests/session.rs of the server reads: tables that point to
// names too short to be taken for strings, and to one-character strings the compiler packs back
// to back, which read as UTF-16 text too.
//   gcc -O2 -fPIE -pie -Wl,--build-id=none -o short.elf short.c && strip short.elf
const char *const words[] = { "ab", "if", "do" };
// One-character strings back to back, ended by a zero more, as a compiler lays out short literals.
static const char packed[] = "<\0!\0(\0)\0{\0}\0\0";
const char *const ops[] = { packed, packed + 2, packed + 4, packed + 6, packed + 8, packed + 10 };

int main(int n, char **arguments) {
    (void)arguments;
    return words[n % 3][0] + ops[n % 6][0];
}
