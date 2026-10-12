//! Prototypes of well-known imported functions.
//!
//! The decompiler cannot see how many arguments an imported function takes, and a wrong guess
//! spreads to every caller. This small table covers the C runtime and the Win32 calls that turn
//! up in almost every binary, written by hand with the types that read best. Behind it are the
//! prototypes of Ghidra's type archives with types reduced to numbers, strings and pointers:
//! `data/win32.protos` from the 32-bit Windows archive, `data/clib.protos` from the 64-bit C
//! library archive (glibc and what Linux programs commonly link) and `data/macos.protos` from
//! the macOS archive. `ghidra/ExportPrototypes.java` writes those files.

use std::collections::HashSet;

use anyhow::Result;

use recore::image::Format;

use crate::{Session, Target};

/// Types the tables are written in. `{ptr}` is the pointer-sized unsigned integer, and `{long}`
/// the size in bytes of C's `long`: 4 on Windows and on 32-bit targets, 8 elsewhere.
const TYPES: &[&str] = &[
    "typedef int4 int;",
    "typedef uint4 uint;",
    "typedef uint4 DWORD;",
    "typedef int4 BOOL;",
    "typedef {ptr} size_t;",
    "typedef int{long} long;",
    "typedef uint{long} ulong;",
    "typedef void *HANDLE;",
    "typedef wchar2 *wstr;",
];

/// The exported archives: one `<convention> <prototype>` per line, sorted by function name.
const WINDOWS: &str = include_str!("../data/win32.protos");
const CLIB: &str = include_str!("../data/clib.protos");
const MACOS: &str = include_str!("../data/macos.protos");

/// The archives that describe the imports of an image of `format`, the most trusted first.
fn archives(format: Format) -> &'static [&'static str] {
    match format {
        Format::Pe => &[WINDOWS],
        Format::Elf => &[CLIB],
        // The C library archive covers libraries the macOS one lacks, such as OpenSSL's newer
        // functions, and both describe the same C interface.
        Format::MachO => &[MACOS, CLIB],
    }
}

/// The entry for a function in the archives of `format`, as (convention, prototype); the
/// convention is `-` if unknown.
fn archived(format: Format, name: &str) -> Option<(&'static str, &'static str)> {
    let mut found = archives(format).iter().filter_map(|archive| entry(archive, name));
    let first = found.next()?;
    // The macOS headers declare some functions in the old style, without parameters, which the
    // archive records as taking none. Another archive that lists parameters knows better.
    if first.1.ends_with("(void)") {
        return Some(found.find(|later| !later.1.ends_with("(void)")).unwrap_or(first));
    }
    Some(first)
}

/// The line of `archive` for a function. Found by bisecting the text, so that a session pays
/// for the imports it has and not for an index of all twenty thousand.
fn entry(archive: &'static str, name: &str) -> Option<(&'static str, &'static str)> {
    let bytes = archive.as_bytes();
    let (mut low, mut high) = (0, bytes.len());
    while low < high {
        let middle = (low + high) / 2;
        let start = bytes[..middle].iter().rposition(|&byte| byte == b'\n').map_or(0, |at| at + 1);
        let end = bytes[start..].iter().position(|&byte| byte == b'\n').map_or(bytes.len(), |at| start + at);
        let (convention, prototype) = archive.get(start..end)?.split_once(' ')?;
        match name_of(prototype).cmp(name) {
            std::cmp::Ordering::Less => low = end + 1,
            std::cmp::Ordering::Greater => high = start,
            std::cmp::Ordering::Equal => return Some((convention, prototype)),
        }
    }
    None
}

/// C runtime functions, `__cdecl` on 32-bit Windows. These go before the archives on every
/// target, so they are written with the types that hold everywhere.
const C_RUNTIME: &[&str] = &[
    "void *memcpy(void *dst, void *src, size_t n)",
    "void *memmove(void *dst, void *src, size_t n)",
    "void *memset(void *dst, int value, size_t n)",
    "int memcmp(void *a, void *b, size_t n)",
    "void *memchr(void *s, int c, size_t n)",
    "void *malloc(size_t size)",
    "void *calloc(size_t count, size_t size)",
    "void *realloc(void *block, size_t size)",
    "void free(void *block)",
    "size_t strlen(char *s)",
    "char *strcpy(char *dst, char *src)",
    "char *strncpy(char *dst, char *src, size_t n)",
    "char *strcat(char *dst, char *src)",
    "char *strncat(char *dst, char *src, size_t n)",
    "int strcmp(char *a, char *b)",
    "int strncmp(char *a, char *b, size_t n)",
    "char *strchr(char *s, int c)",
    "char *strrchr(char *s, int c)",
    "char *strstr(char *s, char *needle)",
    "char *strdup(char *s)",
    "char *_strdup(char *s)",
    "int _stricmp(char *a, char *b)",
    "int strcasecmp(char *a, char *b)",
    "size_t wcslen(wstr s)",
    "wstr wcscpy(wstr dst, wstr src)",
    "int wcscmp(wstr a, wstr b)",
    "int atoi(char *s)",
    "long strtol(char *s, char **end, int base)",
    "ulong strtoul(char *s, char **end, int base)",
    "int printf(char *format, ...)",
    "int sprintf(char *dst, char *format, ...)",
    "int snprintf(char *dst, size_t n, char *format, ...)",
    "int fprintf(void *stream, char *format, ...)",
    "int puts(char *s)",
    "int fputs(char *s, void *stream)",
    "int putchar(int c)",
    "void *fopen(char *path, char *mode)",
    "int fclose(void *stream)",
    "size_t fread(void *dst, size_t size, size_t count, void *stream)",
    "size_t fwrite(void *src, size_t size, size_t count, void *stream)",
    "char *fgets(char *dst, int n, void *stream)",
    "int fflush(void *stream)",
    "char *getenv(char *name)",
    "void exit(int status)",
    "void abort(void)",
    "void qsort(void *base, size_t count, size_t size, void *compare)",
    // The macOS archive lost the handler of this one.
    "void *signal(int sig, void *handler)",
];

/// What glibc's headers turn calls into when a program is built with `_FORTIFY_SOURCE` or for
/// C99: the checked and the C99 variants, which no archive lists.
const GLIBC: &[&str] = &[
    "void __stack_chk_fail(void)",
    "int *__errno_location(void)",
    "int __cxa_atexit(void *function, void *argument, void *dso)",
    "void __cxa_finalize(void *dso)",
    "void __assert_fail(char *assertion, char *file, uint line, char *function)",
    "void *__memcpy_chk(void *dst, void *src, size_t n, size_t dstlen)",
    "void *__memmove_chk(void *dst, void *src, size_t n, size_t dstlen)",
    "void *__memset_chk(void *dst, int value, size_t n, size_t dstlen)",
    "char *__strcpy_chk(char *dst, char *src, size_t dstlen)",
    "char *__strncpy_chk(char *dst, char *src, size_t n, size_t dstlen)",
    "char *__strcat_chk(char *dst, char *src, size_t dstlen)",
    "char *__strncat_chk(char *dst, char *src, size_t n, size_t dstlen)",
    "char *__stpcpy_chk(char *dst, char *src, size_t dstlen)",
    "int __printf_chk(int flag, char *format, ...)",
    "int __fprintf_chk(void *stream, int flag, char *format, ...)",
    "int __dprintf_chk(int fd, int flag, char *format, ...)",
    "int __sprintf_chk(char *dst, int flag, size_t dstlen, char *format, ...)",
    "int __snprintf_chk(char *dst, size_t n, int flag, size_t dstlen, char *format, ...)",
    "int __vprintf_chk(int flag, char *format, void *arguments)",
    "int __vfprintf_chk(void *stream, int flag, char *format, void *arguments)",
    "int __vsprintf_chk(char *dst, int flag, size_t dstlen, char *format, void *arguments)",
    "int __vsnprintf_chk(char *dst, size_t n, int flag, size_t dstlen, char *format, void *arguments)",
    "int __asprintf_chk(char **result, int flag, char *format, ...)",
    "int __vasprintf_chk(char **result, int flag, char *format, void *arguments)",
    "void __syslog_chk(int priority, int flag, char *format, ...)",
    "char *__fgets_chk(char *dst, size_t dstlen, int n, void *stream)",
    "size_t __fread_chk(void *dst, size_t dstlen, size_t size, size_t count, void *stream)",
    "long __read_chk(int fd, void *dst, size_t n, size_t dstlen)",
    "long __readlink_chk(char *path, char *dst, size_t n, size_t dstlen)",
    "char *__realpath_chk(char *path, char *resolved, size_t resolvedlen)",
    "char *__getcwd_chk(char *dst, size_t n, size_t dstlen)",
    "void __longjmp_chk(void *environment, int value)",
    "int __isoc99_scanf(char *format, ...)",
    "int __isoc99_sscanf(char *s, char *format, ...)",
    "int __isoc99_fscanf(void *stream, char *format, ...)",
    "int __isoc23_scanf(char *format, ...)",
    "int __isoc23_sscanf(char *s, char *format, ...)",
    "int __isoc23_fscanf(void *stream, char *format, ...)",
    "long __isoc23_strtol(char *s, char **end, int base)",
    "ulong __isoc23_strtoul(char *s, char **end, int base)",
    "int8 __isoc23_strtoll(char *s, char **end, int base)",
    "uint8 __isoc23_strtoull(char *s, char **end, int base)",
];

/// What compilers call on a program's behalf, and what no archive lists: the C++, Objective-C
/// and Swift runtimes under their link names, and the message catalogue.
const RUNTIME: &[&str] = &[
    "void *_Znwm(size_t size)",
    "void *_Znam(size_t size)",
    "void *_Znwj(size_t size)",
    "void *_Znaj(size_t size)",
    "void _ZdlPv(void *block)",
    "void _ZdaPv(void *block)",
    "void _ZdlPvm(void *block, size_t size)",
    "void _ZdaPvm(void *block, size_t size)",
    "void _ZdlPvj(void *block, size_t size)",
    "void _ZdaPvj(void *block, size_t size)",
    "void _Unwind_Resume(void *exception)",
    "void *__cxa_allocate_exception(size_t size)",
    "void __cxa_free_exception(void *exception)",
    "void __cxa_throw(void *exception, void *type, void *destructor)",
    "void *__cxa_begin_catch(void *exception)",
    "void __cxa_end_catch(void)",
    "void __cxa_rethrow(void)",
    "int __cxa_guard_acquire(void *guard)",
    "void __cxa_guard_release(void *guard)",
    "void __cxa_guard_abort(void *guard)",
    "void __cxa_pure_virtual(void)",
    "void _ZSt17__throw_bad_allocv(void)",
    "void _ZSt28__throw_bad_array_new_lengthv(void)",
    "void _ZSt20__throw_length_errorPKc(char *what)",
    "void _ZSt19__throw_logic_errorPKc(char *what)",
    "void _ZSt20__throw_out_of_rangePKc(char *what)",
    "void _ZSt24__throw_out_of_range_fmtPKcz(char *format, ...)",
    "void _ZSt21__glibcxx_assert_failPKciS0_S0_(char *file, int line, char *function, char *condition)",
    "char *gettext(char *id)",
    "char *dgettext(char *domain, char *id)",
    "char *dcgettext(char *domain, char *id, int category)",
    "char *ngettext(char *id, char *plural, ulong n)",
    "char *dcngettext(char *domain, char *id, char *plural, ulong n, int category)",
    "char *libintl_gettext(char *id)",
    "char *libintl_dgettext(char *domain, char *id)",
    "char *libintl_dcgettext(char *domain, char *id, int category)",
    "char *libintl_ngettext(char *id, char *plural, ulong n)",
    "void *objc_retain(void *object)",
    "void objc_release(void *object)",
    "void *objc_autorelease(void *object)",
    "void *objc_retainAutoreleasedReturnValue(void *object)",
    "void *objc_autoreleaseReturnValue(void *object)",
    "void *swift_retain(void *object)",
    "void swift_release(void *object)",
    "void *swift_bridgeObjectRetain(void *object)",
    "void swift_bridgeObjectRelease(void *object)",
    "void *swift_allocObject(void *metadata, size_t size, size_t alignment)",
    "void swift_beginAccess(void *address, void *buffer, size_t flags, void *pc)",
    "void swift_endAccess(void *buffer)",
    "void swift_once(void *predicate, void *function, void *context)",
    "bool swift_isUniquelyReferenced_nonNull_native(void *object)",
];

/// Win32 functions, `__stdcall` on 32-bit Windows.
const WIN32: &[&str] = &[
    "HANDLE CreateFileA(char *name, DWORD access, DWORD share, void *security, DWORD disposition, DWORD flags, HANDLE template)",
    "HANDLE CreateFileW(wstr name, DWORD access, DWORD share, void *security, DWORD disposition, DWORD flags, HANDLE template)",
    "BOOL ReadFile(HANDLE file, void *buffer, DWORD size, DWORD *read, void *overlapped)",
    "BOOL WriteFile(HANDLE file, void *buffer, DWORD size, DWORD *written, void *overlapped)",
    "BOOL CloseHandle(HANDLE handle)",
    "DWORD GetLastError(void)",
    "void SetLastError(DWORD error)",
    "DWORD GetFileSize(HANDLE file, DWORD *high)",
    "DWORD SetFilePointer(HANDLE file, int4 distance, int4 *high, DWORD method)",
    "BOOL DeleteFileA(char *name)",
    "BOOL DeleteFileW(wstr name)",
    "HANDLE GetProcessHeap(void)",
    "void *HeapAlloc(HANDLE heap, DWORD flags, size_t size)",
    "void *HeapReAlloc(HANDLE heap, DWORD flags, void *block, size_t size)",
    "BOOL HeapFree(HANDLE heap, DWORD flags, void *block)",
    "void *VirtualAlloc(void *address, size_t size, DWORD type, DWORD protect)",
    "BOOL VirtualFree(void *address, size_t size, DWORD type)",
    "BOOL VirtualProtect(void *address, size_t size, DWORD protect, DWORD *old)",
    "void *LocalAlloc(uint flags, size_t size)",
    "void *LocalFree(void *block)",
    "HANDLE LoadLibraryA(char *name)",
    "HANDLE LoadLibraryW(wstr name)",
    "HANDLE LoadLibraryExW(wstr name, HANDLE file, DWORD flags)",
    "BOOL FreeLibrary(HANDLE module)",
    "void *GetProcAddress(HANDLE module, char *name)",
    "HANDLE GetModuleHandleA(char *name)",
    "HANDLE GetModuleHandleW(wstr name)",
    "DWORD GetModuleFileNameA(HANDLE module, char *name, DWORD size)",
    "DWORD GetModuleFileNameW(HANDLE module, wstr name, DWORD size)",
    "HANDLE GetCurrentProcess(void)",
    "DWORD GetCurrentProcessId(void)",
    "DWORD GetCurrentThreadId(void)",
    "void ExitProcess(uint status)",
    "BOOL TerminateProcess(HANDLE process, uint status)",
    "void Sleep(DWORD milliseconds)",
    "DWORD GetTickCount(void)",
    "DWORD WaitForSingleObject(HANDLE handle, DWORD milliseconds)",
    "void EnterCriticalSection(void *section)",
    "void LeaveCriticalSection(void *section)",
    "void InitializeCriticalSection(void *section)",
    "void DeleteCriticalSection(void *section)",
    "DWORD TlsAlloc(void)",
    "void *TlsGetValue(DWORD index)",
    "BOOL TlsSetValue(DWORD index, void *value)",
    "BOOL TlsFree(DWORD index)",
    "void OutputDebugStringA(char *text)",
    "void OutputDebugStringW(wstr text)",
    "int MultiByteToWideChar(uint codepage, DWORD flags, char *src, int srclen, wstr dst, int dstlen)",
    "int WideCharToMultiByte(uint codepage, DWORD flags, wstr src, int srclen, char *dst, int dstlen, char *fallback, BOOL *used)",
    "int lstrlenA(char *s)",
    "int lstrlenW(wstr s)",
    "int MessageBoxA(HANDLE window, char *text, char *caption, uint type)",
    "int4 RegOpenKeyExA(HANDLE key, char *subkey, DWORD options, DWORD access, HANDLE *result)",
    "int4 RegQueryValueExA(HANDLE key, char *name, DWORD *reserved, DWORD *type, void *data, DWORD *size)",
    "int4 RegCloseKey(HANDLE key)",
    "BOOL CryptAcquireContextA(HANDLE *provider, char *container, char *name, DWORD type, DWORD flags)",
    "BOOL CryptAcquireContextW(HANDLE *provider, wstr container, wstr name, DWORD type, DWORD flags)",
    "BOOL CryptReleaseContext(HANDLE provider, DWORD flags)",
    "BOOL CryptGenRandom(HANDLE provider, DWORD size, void *buffer)",
    "BOOL CryptCreateHash(HANDLE provider, uint algorithm, HANDLE key, DWORD flags, HANDLE *hash)",
    "BOOL CryptHashData(HANDLE hash, void *data, DWORD size, DWORD flags)",
    "BOOL CryptGetHashParam(HANDLE hash, DWORD param, void *data, DWORD *size, DWORD flags)",
    "BOOL CryptDestroyHash(HANDLE hash)",
    "BOOL CryptDeriveKey(HANDLE provider, uint algorithm, HANDLE hash, DWORD flags, HANDLE *key)",
    "BOOL CryptImportKey(HANDLE provider, void *blob, DWORD size, HANDLE pubkey, DWORD flags, HANDLE *key)",
    "BOOL CryptExportKey(HANDLE key, HANDLE expkey, DWORD type, DWORD flags, void *blob, DWORD *size)",
    "BOOL CryptSetKeyParam(HANDLE key, DWORD param, void *data, DWORD flags)",
    "BOOL CryptEncrypt(HANDLE key, HANDLE hash, BOOL final, DWORD flags, void *data, DWORD *size, DWORD capacity)",
    "BOOL CryptDecrypt(HANDLE key, HANDLE hash, BOOL final, DWORD flags, void *data, DWORD *size)",
    "BOOL CryptDestroyKey(HANDLE key)",
];

/// The declaration [`declare`] makes on `target` for an archive entry.
fn declaration(target: Target, convention: &str, prototype: &str) -> String {
    // Only 32-bit Windows has more than one convention to choose from.
    let convention = if target == Target::X86Windows && convention != "-" { format!("__{convention} ") } else { String::new() };
    format!("extern {convention}{prototype};")
}

/// Every prototype of the first archive for `format` by function name, as the declaration
/// [`declare`] would make for it on `target`.
pub fn archive_declarations(target: Target, format: Format) -> impl Iterator<Item = (&'static str, String)> {
    let entries = archives(format)[0].lines().filter_map(|line| line.split_once(' '));
    entries.map(move |(convention, prototype)| (name_of(prototype), declaration(target, convention, prototype)))
}

/// Every function the tables written by hand have a prototype for.
pub fn known() -> impl Iterator<Item = &'static str> {
    C_RUNTIME.iter().chain(WIN32).chain(GLIBC).chain(RUNTIME).map(|prototype| name_of(prototype))
}

/// Where [`declare`] takes the prototype of the import `name` of an image of `format` from:
/// `table` for the C runtime and Win32 ones written by hand, `added table` for the glibc and
/// language runtime ones, `archive`, or `None` if it has none.
pub fn source(format: Format, name: &str) -> Option<&'static str> {
    let listed = |table: &[&str]| table.iter().any(|prototype| name_of(prototype) == name);
    if listed(C_RUNTIME) || listed(WIN32) {
        Some("table")
    } else if listed(GLIBC) || listed(RUNTIME) {
        Some("added table")
    } else {
        archived(format, name).map(|_| "archive")
    }
}

/// The function name in a prototype: the identifier before the parameter list.
fn name_of(prototype: &str) -> &str {
    let head = prototype.split('(').next().unwrap_or(prototype);
    head.rsplit([' ', '*']).next().unwrap_or(head)
}

/// Gives every import in `imports` that the tables or the archives of `format` know its
/// prototype. The imports must already be declared in the session.
pub fn declare<'a>(session: &mut Session, target: Target, format: Format, imports: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut wanted: HashSet<&str> = imports.collect();
    let pointer = if target.pointer_bytes() == 4 { "uint4" } else { "uint8" };
    let long = if format == Format::Pe || target.pointer_bytes() == 4 { "4" } else { "8" };
    for declaration in TYPES {
        session.declare(&declaration.replace("{ptr}", pointer).replace("{long}", long))?;
    }
    // Only 32-bit Windows has more than one convention to choose from.
    let windows32 = target == Target::X86Windows;
    let conventions = if windows32 { ["__cdecl ", "__stdcall "] } else { ["", ""] };
    for (table, convention) in [C_RUNTIME, WIN32, GLIBC, RUNTIME].into_iter().zip([conventions[0], conventions[1], "", ""]) {
        for prototype in table.iter().filter(|p| wanted.remove(name_of(p))) {
            session.declare(&format!("extern {convention}{prototype};"))?;
        }
    }
    let mut wanted: Vec<&str> = wanted.into_iter().collect();
    wanted.sort_unstable();
    for (convention, prototype) in wanted.into_iter().filter_map(|name| archived(format, name)) {
        // One prototype the parser rejects must not cost the session the rest.
        let _ = session.declare(&declaration(target, convention, prototype));
    }
    Ok(())
}
