//! Prototypes of well-known imported functions.
//!
//! The decompiler cannot see how many arguments an imported function takes, and a wrong guess
//! spreads to every caller. This small table covers the C runtime and the Win32 calls that turn
//! up in almost every binary, written by hand with the types that read best. Behind it is
//! `data/win32.protos`, the prototypes of Ghidra's 32-bit Windows type archive with types reduced
//! to numbers, strings and pointers; `ghidra/ExportPrototypes.java` writes that file.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use anyhow::Result;

use crate::{Session, Target};

/// Types the table is written in. `{ptr}` is the pointer-sized unsigned integer.
const TYPES: &[&str] = &[
    "typedef int4 int;",
    "typedef uint4 uint;",
    "typedef uint4 DWORD;",
    "typedef int4 BOOL;",
    "typedef {ptr} size_t;",
    "typedef void *HANDLE;",
    "typedef wchar2 *wstr;",
];

/// The exported archive: one `<convention> <prototype>` per line, sorted by function name.
const ARCHIVE: &str = include_str!("../data/win32.protos");

/// The archive by function name, as (convention, prototype). The convention is `-` if unknown.
fn archive() -> &'static HashMap<&'static str, (&'static str, &'static str)> {
    static BY_NAME: OnceLock<HashMap<&str, (&str, &str)>> = OnceLock::new();
    BY_NAME.get_or_init(|| ARCHIVE.lines().filter_map(|line| line.split_once(' ')).map(|(convention, prototype)| (name_of(prototype), (convention, prototype))).collect())
}

/// C runtime functions, `__cdecl` on 32-bit Windows.
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
    "int4 strtol(char *s, char **end, int base)",
    "uint4 strtoul(char *s, char **end, int base)",
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

/// Every archive prototype as the declaration [`declare`] would make for it on `target`.
pub fn archive_declarations(target: Target) -> impl Iterator<Item = (&'static str, String)> {
    let windows32 = target == Target::X86Windows;
    archive().iter().map(move |(&name, &(convention, prototype))| {
        let convention = if windows32 && convention != "-" { format!("__{convention} ") } else { String::new() };
        (name, format!("extern {convention}{prototype};"))
    })
}

/// Every function the table has a prototype for.
pub fn known() -> impl Iterator<Item = &'static str> {
    C_RUNTIME.iter().chain(WIN32).map(|prototype| name_of(prototype))
}

/// The function name in a prototype: the identifier before the parameter list.
fn name_of(prototype: &str) -> &str {
    let head = prototype.split('(').next().unwrap_or(prototype);
    head.rsplit([' ', '*']).next().unwrap_or(head)
}

/// Gives every import in `imports` that the table or the archive knows its prototype. The
/// imports must already be declared in the session.
pub fn declare<'a>(session: &mut Session, target: Target, imports: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut wanted: HashSet<&str> = imports.collect();
    let pointer = if target.pointer_bytes() == 4 { "uint4" } else { "uint8" };
    for declaration in TYPES {
        session.declare(&declaration.replace("{ptr}", pointer))?;
    }
    // Only 32-bit Windows has more than one convention to choose from.
    let windows32 = target == Target::X86Windows;
    let conventions = if windows32 { ["__cdecl ", "__stdcall "] } else { ["", ""] };
    for (table, convention) in [C_RUNTIME, WIN32].into_iter().zip(conventions) {
        for prototype in table.iter().filter(|p| wanted.remove(name_of(p))) {
            session.declare(&format!("extern {convention}{prototype};"))?;
        }
    }
    // The archive describes Windows; an ELF import of the same name may differ.
    if matches!(target, Target::X86Windows | Target::X86_64Windows) {
        for (_, declaration) in archive_declarations(target).filter(|(name, _)| wanted.contains(name)) {
            // One prototype the parser rejects must not cost the session the rest.
            let _ = session.declare(&declaration);
        }
    }
    Ok(())
}
