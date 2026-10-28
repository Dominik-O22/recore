//! kernel32.dll: what the C runtime and the game ask of Windows, apart from files (files.rs).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use recore_machine::{Cpu, Frame};

use crate::{Win32, session::Tape};

/// The handle `HeapCreate` and `GetProcessHeap` give; every heap is the one bump heap.
const HEAP_HANDLE: u32 = 0x00ff_0000;
const LAST_ERROR: u32 = 0x34;
const TLS_SLOTS: u32 = 0xe10;
/// Module handles `LoadLibraryA` gives: `MODULES + i` for the `i`th DLL it loaded.
const MODULES: u32 = 0x7000_0000;

/// The time the game sees. `Real` is the host's. `Virtual` starts at 1999-01-01 and moves only
/// by 100 microseconds per reading and by what the game sleeps, so two runs of the same input see
/// the same times and end in the same state, as fast as the machine runs. A run without a window
/// (TT_SHOTS, TT_HEADLESS) is virtual unless it replays a session; TT_CLOCK=real or virtual
/// overrides. With TT_RECORD or TT_REPLAY, the real clock's readings go through `tape`
/// (session.rs).
pub enum Clock {
    Real { started: Instant, tape: Tape },
    Virtual { micros: u64 },
}

/// 1999-01-01 00:00:00 UTC in microseconds since 1970.
const VIRTUAL_START: u64 = 915_148_800_000_000;

impl Clock {
    pub fn from_env() -> Clock {
        let set = |name| std::env::var_os(name).is_some();
        let windowless = (set("TT_SHOTS") || set("TT_HEADLESS")) && !set("TT_REPLAY");
        match std::env::var("TT_CLOCK").as_deref() {
            Ok("virtual") => Clock::Virtual { micros: 0 },
            Ok("real") => Clock::Real { started: Instant::now(), tape: Tape::open("clock") },
            _ if windowless => Clock::Virtual { micros: 0 },
            _ => Clock::Real { started: Instant::now(), tape: Tape::open("clock") },
        }
    }

    /// Microseconds since the game started.
    pub fn micros(&mut self) -> u64 {
        match self {
            Clock::Real { started, tape } => tape.number(0, || started.elapsed().as_micros() as u64),
            Clock::Virtual { micros } => {
                *micros += 100;
                *micros
            }
        }
    }

    /// Microseconds since 1970.
    fn unix_micros(&mut self) -> u64 {
        match self {
            Clock::Real { tape, .. } => tape.number(1, || SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64),
            Clock::Virtual { .. } => VIRTUAL_START + self.micros(),
        }
    }

    /// Writes what the tape holds so far, at each frame and before the game quits.
    pub fn flush(&mut self) {
        if let Clock::Real { tape, .. } = self {
            tape.flush();
        }
    }

    pub fn sleep(&mut self, ms: u32) {
        match self {
            Clock::Real { tape, .. } if tape.replaying() => {}
            Clock::Real { .. } => std::thread::sleep(Duration::from_millis(u64::from(ms.min(1000)))),
            Clock::Virtual { micros } => *micros += u64::from(ms) * 1000,
        }
    }
}

pub fn run(w: &mut Win32, c: &mut Cpu, name: &str, f: Frame) -> bool {
    let teb = c.reg(recore_machine::regs::FS_OFFSET);
    let a = |c: &mut Cpu, n| c.arg(f, n);
    match name {
        // Windows 98, 4.10.1998. DirectX version checks of the time can probe DirectMusic only
        // on Windows 9x and fail without it. GetVersion keeps the major and minor
        // version in the low word and sets the high bit for Windows 9x.
        "GetVersion" => c.ret(f, Some(0xc000_0a04), 0),
        // OSVERSIONINFOA: 4.10.1998, VER_PLATFORM_WIN32_WINDOWS.
        "GetVersionExA" => {
            let info = a(c, 0);
            for (i, v) in [4u32, 10, 1998, 1].into_iter().enumerate() {
                c.set_u32(info + 4 + 4 * i as u32, v);
            }
            c.ret(f, Some(1), 1);
        }
        "GetModuleHandleA" => {
            let named = a(c, 0);
            let handle = if named == 0 { 0x40_0000 } else { 0 };
            if named != 0 {
                eprintln!("host: GetModuleHandleA({:?}) answers 0", c.mem.c_str(named));
            }
            c.ret(f, Some(handle), 1);
        }
        "GetModuleFileNameA" => {
            let (buf, size) = (a(c, 1), a(c, 2));
            let len = w.put_str(c, buf, size, &format!("{}\\{}", w.game.root, w.game.exe));
            c.ret(f, Some(len), 3);
        }
        "GetCommandLineA" => {
            let line = std::env::var("TT_ARGS").unwrap_or_else(|_| w.game.command_line.into());
            let line = w.static_str(c, &line);
            c.ret(f, Some(line), 0);
        }
        "GetStartupInfoA" => {
            let info = a(c, 0);
            c.mem.poke(info, &[0; 68]);
            c.set_u32(info, 68);
            c.ret(f, None, 1);
        }
        "GetCurrentThreadId" | "GetCurrentProcessId" => c.ret(f, Some(1), 0),
        "GetCurrentProcess" => c.ret(f, Some(u32::MAX), 0),
        "GetCurrentThread" => c.ret(f, Some(0xffff_fffe), 0),
        "SetPriorityClass" => c.ret(f, Some(1), 2),
        "SetConsoleCtrlHandler" => c.ret(f, Some(1), 2),
        // TIME_ZONE_INFORMATION, all zero: UTC.
        "GetTimeZoneInformation" => {
            let info = a(c, 0);
            c.mem.poke(info, &[0; 172]);
            c.ret(f, Some(0), 1);
        }
        // The one instance: the mutex is new.
        "CreateMutexA" => {
            c.set_u32(teb + LAST_ERROR, 0);
            c.ret(f, Some(0x5556), 3);
        }
        "ReleaseMutex" => c.ret(f, Some(1), 1),
        "CreateProcessA" => {
            let (app, line) = (a(c, 0), a(c, 1));
            let name = if app != 0 { c.mem.c_str(app) } else { c.mem.c_str(line) };
            eprintln!("host: CreateProcessA {name:?} fails");
            c.ret(f, Some(0), 10);
        }
        "FreeLibrary" => c.ret(f, Some(1), 1),
        "GlobalHandle" => {
            let p = a(c, 0);
            c.ret(f, Some(p), 1);
        }
        "GlobalFree" | "LocalFree" => c.ret(f, Some(0), 1),
        "FormatMessageA" => c.ret(f, Some(0), 7),
        "FatalAppExitA" => {
            let text = a(c, 1);
            eprintln!("host: FatalAppExit {:?}", c.mem.c_str(text));
            std::process::exit(3);
        }
        // Unlinks the exception handlers above the target frame; their unwind handlers do not run.
        "RtlUnwind" => {
            let (target, value) = (a(c, 0), a(c, 3));
            if target != 0 {
                c.set_u32(teb, target);
            }
            c.ret(f, Some(value), 4);
        }
        "lstrcatA" => {
            let (dst, src) = (a(c, 0), a(c, 1));
            let mut text = crate::fmt::c_bytes(c, dst);
            text.extend(crate::fmt::c_bytes(c, src));
            w.put_bytes(c, dst, u32::MAX, &text);
            c.ret(f, Some(dst), 2);
        }
        "GetPriorityClass" => c.ret(f, Some(0x20), 1),
        "SetThreadPriority" => c.ret(f, Some(1), 2),
        "ExitProcess" | "TerminateProcess" => {
            let code = a(c, if name == "ExitProcess" { 0 } else { 1 });
            eprintln!("host: the game exited with {code}");
            std::process::exit(code as i32);
        }
        // Heaps: one bump heap that never frees.
        "HeapCreate" => c.ret(f, Some(HEAP_HANDLE), 3),
        "GetProcessHeap" => c.ret(f, Some(HEAP_HANDLE), 0),
        "HeapDestroy" => c.ret(f, Some(1), 1),
        "HeapAlloc" => {
            let size = a(c, 2);
            let p = w.heap_alloc(c, size);
            c.ret(f, Some(p), 3);
        }
        "HeapFree" => {
            let p = a(c, 2);
            let freed = p == 0 || w.heap_free(p);
            c.ret(f, Some(u32::from(freed)), 3);
        }
        "HeapSize" => {
            let p = a(c, 2);
            let size = w.sizes.get(&p).copied().unwrap_or(u32::MAX);
            c.ret(f, Some(size), 3);
        }
        // HEAP_REALLOC_IN_PLACE_ONLY is 0x10.
        "HeapReAlloc" => {
            let (flags, p, size) = (a(c, 1), a(c, 2), a(c, 3));
            let new = w.heap_realloc(c, p, size, flags & 0x10 != 0);
            c.ret(f, Some(new), 4);
        }
        "GlobalAlloc" => {
            let size = a(c, 1);
            let p = w.alloc(size);
            c.ret(f, Some(p), 2);
        }
        "GlobalLock" => {
            let p = a(c, 0);
            c.ret(f, Some(p), 1);
        }
        "GlobalUnlock" => c.ret(f, Some(0), 1),
        // MEM_RESERVE alone or with MEM_COMMIT at no address gets fresh pages; a commit inside
        // a reservation is the reservation's own address.
        "VirtualAlloc" => {
            let (at, size) = (a(c, 0), a(c, 1));
            let p = if at != 0 { at } else { w.alloc_pages(size) };
            c.ret(f, Some(p), 4);
        }
        "VirtualFree" => c.ret(f, Some(1), 3),
        "VirtualProtect" => {
            let old = a(c, 3);
            if old != 0 {
                c.set_u32(old, 4);
            }
            c.ret(f, Some(1), 4);
        }
        // MEMORY_BASIC_INFORMATION of a committed read-write region around the address.
        "VirtualQuery" => {
            let (at, info) = (a(c, 0), a(c, 1));
            let page = at & !0xfff;
            for (i, v) in [page, page, 4, page, 0x1000, 0x1000, 4, 0x20000].into_iter().enumerate() {
                c.set_u32(info + 4 * i as u32, v);
            }
            c.ret(f, Some(28), 3);
        }
        "IsBadReadPtr" | "IsBadWritePtr" => c.ret(f, Some(0), 2),
        "IsBadCodePtr" => c.ret(f, Some(0), 1),
        "GetSystemInfo" => {
            let info = a(c, 0);
            let fields = [0u32, 0x1000, 0x1_0000, 0x7ffe_ffff, 1, 1, 586, 0x1_0000, 0x0006_0001];
            for (i, v) in fields.into_iter().enumerate() {
                c.set_u32(info + 4 * i as u32, v);
            }
            c.ret(f, None, 1);
        }
        "GlobalMemoryStatus" => {
            let info = a(c, 0);
            let fields = [32u32, 10, 0x2000_0000, 0x1800_0000, 0x4000_0000, 0x3000_0000, 0x7ffe_0000, 0x7000_0000];
            for (i, v) in fields.into_iter().enumerate() {
                c.set_u32(info + 4 * i as u32, v);
            }
            c.ret(f, None, 1);
        }
        "IsProcessorFeaturePresent" => c.ret(f, Some(0), 1),
        // Thread-local storage in the thread block's 64 slots.
        "TlsAlloc" => {
            let index = w.tls_next;
            w.tls_next += 1;
            c.ret(f, Some(index), 0);
        }
        "TlsFree" => c.ret(f, Some(1), 1),
        "TlsGetValue" => {
            let index = a(c, 0);
            let v = c.u32_at(teb + TLS_SLOTS + 4 * index);
            c.set_u32(teb + LAST_ERROR, 0);
            c.ret(f, Some(v), 1);
        }
        "TlsSetValue" => {
            let (index, v) = (a(c, 0), a(c, 1));
            c.set_u32(teb + TLS_SLOTS + 4 * index, v);
            c.ret(f, Some(1), 2);
        }
        "GetLastError" => {
            let v = c.u32_at(teb + LAST_ERROR);
            c.ret(f, Some(v), 0);
        }
        "SetLastError" => {
            let v = a(c, 0);
            c.set_u32(teb + LAST_ERROR, v);
            c.ret(f, None, 1);
        }
        "InitializeCriticalSection" | "EnterCriticalSection" | "LeaveCriticalSection" | "DeleteCriticalSection" => c.ret(f, None, 1),
        "InterlockedIncrement" | "InterlockedDecrement" => {
            let p = a(c, 0);
            let v = c.u32_at(p);
            let v = if name == "InterlockedIncrement" { v.wrapping_add(1) } else { v.wrapping_sub(1) };
            c.set_u32(p, v);
            c.ret(f, Some(v), 1);
        }
        "SetUnhandledExceptionFilter" => c.ret(f, Some(0), 1),
        "UnhandledExceptionFilter" => c.ret(f, Some(0), 1),
        "OutputDebugStringA" => {
            let text = a(c, 0);
            eprintln!("game: {}", c.mem.c_str(text).trim_end());
            c.ret(f, None, 1);
        }
        // Environment: empty.
        "GetEnvironmentStrings" | "GetEnvironmentStringsW" => {
            let block = w.alloc(4);
            c.ret(f, Some(block), 0);
        }
        "FreeEnvironmentStringsA" | "FreeEnvironmentStringsW" => c.ret(f, Some(1), 1),
        "SetEnvironmentVariableA" => c.ret(f, Some(1), 2),
        "GetComputerNameA" => {
            let (buf, size) = (a(c, 0), a(c, 1));
            let cap = c.u32_at(size);
            let len = w.put_str(c, buf, cap, "RECORE");
            c.set_u32(size, len);
            c.ret(f, Some(1), 2);
        }
        // Code pages and locale: Windows-1252, US English.
        "GetACP" => c.ret(f, Some(1252), 0),
        "GetOEMCP" => c.ret(f, Some(437), 0),
        "IsValidCodePage" | "IsValidLocale" => c.ret(f, Some(1), if name == "IsValidCodePage" { 1 } else { 2 }),
        "GetCPInfo" => {
            let info = a(c, 1);
            c.mem.poke(info, &[0; 20]);
            c.set_u32(info, 1);
            c.st(info + 4, 1, u128::from(b'?'));
            c.ret(f, Some(1), 2);
        }
        "GetUserDefaultLCID" | "GetUserDefaultLangID" => c.ret(f, Some(0x409), 0),
        "EnumSystemLocalesA" => c.ret(f, Some(1), 2),
        "GetLocaleInfoA" => {
            let (kind, buf, size) = (a(c, 1), a(c, 2), a(c, 3));
            let value = locale(kind);
            let len = if size == 0 { value.len() as u32 + 1 } else { w.put_str(c, buf, size, value) + 1 };
            c.ret(f, Some(len), 4);
        }
        "GetLocaleInfoW" => {
            let (kind, buf, size) = (a(c, 1), a(c, 2), a(c, 3));
            let value = locale(kind);
            if size != 0 {
                for (i, ch) in value.encode_utf16().chain([0]).take(size as usize).enumerate() {
                    c.st(buf + 2 * i as u32, 2, u128::from(ch));
                }
            }
            c.ret(f, Some(value.len() as u32 + 1), 4);
        }
        "MultiByteToWideChar" => {
            let (src, len, dst, cap) = (a(c, 2), a(c, 3) as i32, a(c, 4), a(c, 5));
            let bytes = c_bytes(c, src, len);
            if cap != 0 {
                for (i, b) in bytes.iter().take(cap as usize).enumerate() {
                    c.st(dst + 2 * i as u32, 2, u128::from(*b));
                }
            }
            c.ret(f, Some(bytes.len() as u32), 6);
        }
        "WideCharToMultiByte" => {
            let (src, len, dst, cap) = (a(c, 2), a(c, 3) as i32, a(c, 4), a(c, 5));
            let units = wide(c, src, len);
            if cap != 0 {
                for (i, u) in units.iter().take(cap as usize).enumerate() {
                    c.st(dst + i as u32, 1, u128::from(if *u < 256 { *u as u8 } else { b'?' }));
                }
            }
            c.ret(f, Some(units.len() as u32), 8);
        }
        // GetStringType(locale or type, ...): the A form takes a locale first.
        "GetStringTypeA" | "GetStringTypeW" => {
            let shift = u32::from(name == "GetStringTypeA");
            let (src, len, out) = (a(c, 1 + shift), a(c, 2 + shift) as i32, a(c, 3 + shift));
            let units: Vec<u16> = if shift == 1 { c_bytes(c, src, len).into_iter().map(u16::from).collect() } else { wide(c, src, len) };
            for (i, u) in units.iter().enumerate() {
                c.st(out + 2 * i as u32, 2, u128::from(ctype(*u)));
            }
            c.ret(f, Some(1), 4 + shift);
        }
        "LCMapStringA" | "LCMapStringW" => {
            let (flags, src, len, dst, cap) = (a(c, 1), a(c, 2), a(c, 3) as i32, a(c, 4), a(c, 5));
            let units: Vec<u16> = if name == "LCMapStringA" { c_bytes(c, src, len).into_iter().map(u16::from).collect() } else { wide(c, src, len) };
            let mapped: Vec<u16> = units.iter().map(|&u| map_case(u, flags)).collect();
            if cap != 0 {
                for (i, u) in mapped.iter().take(cap as usize).enumerate() {
                    if name == "LCMapStringA" {
                        c.st(dst + i as u32, 1, u128::from(*u as u8));
                    } else {
                        c.st(dst + 2 * i as u32, 2, u128::from(*u));
                    }
                }
            }
            c.ret(f, Some(mapped.len() as u32), 6);
        }
        "CompareStringA" | "CompareStringW" => {
            let (flags, s1, n1, s2, n2) = (a(c, 1), a(c, 2), a(c, 3) as i32, a(c, 4), a(c, 5) as i32);
            let (x, y): (Vec<u16>, Vec<u16>) = if name == "CompareStringA" {
                (c_bytes(c, s1, n1).into_iter().map(u16::from).collect(), c_bytes(c, s2, n2).into_iter().map(u16::from).collect())
            } else {
                (wide(c, s1, n1), wide(c, s2, n2))
            };
            let fold = |v: Vec<u16>| -> Vec<u16> { if flags & 1 != 0 { v.into_iter().map(|u| map_case(u, 0x100)).collect() } else { v } };
            let order = fold(x).cmp(&fold(y)) as i32 + 2;
            c.ret(f, Some(order as u32), 6);
        }
        "GetTickCount" => {
            let ms = (w.clock.micros() / 1000) as u32;
            w.answer_after_timers(c, f, 0, Some(ms));
        }
        "QueryPerformanceFrequency" => {
            let p = a(c, 0);
            c.st(p, 8, 1_000_000);
            c.ret(f, Some(1), 1);
        }
        "QueryPerformanceCounter" => {
            let p = a(c, 0);
            let us = w.clock.micros();
            c.st(p, 8, u128::from(us));
            c.ret(f, Some(1), 1);
        }
        "GetSystemTimeAsFileTime" => {
            let p = a(c, 0);
            let since = w.clock.unix_micros();
            c.st(p, 8, u128::from(since * 10 + 116_444_736_000_000_000));
            c.ret(f, None, 1);
        }
        "GetLocalTime" => {
            let p = a(c, 0);
            let secs = w.clock.unix_micros() / 1_000_000;
            let (days, rest) = (secs / 86400, secs % 86400);
            let (y, m, d) = civil(days as i64);
            for (i, v) in [y as u16, m as u16, ((days + 4) % 7) as u16, d as u16, (rest / 3600) as u16, (rest / 60 % 60) as u16, (rest % 60) as u16, 0].into_iter().enumerate() {
                c.st(p + 2 * i as u32, 2, u128::from(v));
            }
            c.ret(f, None, 1);
        }
        "Sleep" => {
            let ms = a(c, 0);
            w.clock.sleep(ms);
            w.answer_after_timers(c, f, 1, None);
        }
        "SleepEx" => {
            let ms = a(c, 0);
            w.clock.sleep(ms);
            c.ret(f, Some(0), 2);
        }
        // Threads do not run: the game gets a handle and its thread never starts.
        "CreateThread" => {
            let start = a(c, 2);
            eprintln!("host: CreateThread at {start:#x} does not run");
            c.ret(f, Some(0x5555), 6);
        }
        "WaitForSingleObject" => c.ret(f, Some(0), 2),
        // Every DLL loads, as a handle that names it; GetProcAddress finds a function the
        // executable imports from it by name, at its import's host address, and nothing else.
        "LoadLibraryA" => {
            let named = a(c, 0);
            let dll = c.mem.c_str(named).to_ascii_lowercase();
            let i = w.modules.iter().position(|m| *m == dll).unwrap_or_else(|| {
                w.modules.push(dll);
                w.modules.len() - 1
            });
            c.ret(f, Some(MODULES + i as u32), 1);
        }
        "GetProcAddress" => {
            let (module, named) = (a(c, 0), a(c, 1));
            let name = if named < 0x1_0000 { String::new() } else { c.mem.c_str(named) };
            let dll = module.checked_sub(MODULES).and_then(|i| w.modules.get(i as usize)).cloned().unwrap_or_default();
            let found = w.imports.iter().position(|(d, n)| d.eq_ignore_ascii_case(&dll) && *n == name).map_or(0, |i| crate::IMPORTS + 4 * i as u32);
            if found == 0 {
                eprintln!("host: GetProcAddress({dll:?}, {name:?}) answers 0");
            }
            c.ret(f, Some(found), 2);
        }
        "WinExec" => c.ret(f, Some(0), 2),
        "RaiseException" => {
            let code = a(c, 0);
            panic!("the game raised exception {code:#x}");
        }
        "lstrcpyA" => {
            let (dst, src) = (a(c, 0), a(c, 1));
            let text = c.mem.c_str(src);
            w.put_str(c, dst, u32::MAX, &text);
            c.ret(f, Some(dst), 2);
        }
        "lstrcpynA" => {
            let (dst, src, n) = (a(c, 0), a(c, 1), a(c, 2));
            let text = c.mem.c_str(src);
            w.put_str(c, dst, n, &text);
            c.ret(f, Some(dst), 3);
        }
        _ => return false,
    }
    true
}

/// The bytes of a narrow string of `len` bytes, or up to and with its zero for -1.
fn c_bytes(c: &mut Cpu, at: u32, len: i32) -> Vec<u8> {
    if len >= 0 {
        return c.mem.bytes(at, len as usize);
    }
    let mut v = c.mem.c_str(at).into_bytes();
    v.push(0);
    v
}

fn wide(c: &mut Cpu, at: u32, len: i32) -> Vec<u16> {
    let mut out = Vec::new();
    loop {
        if len >= 0 && out.len() == len as usize {
            break;
        }
        let u = c.ld(at + 2 * out.len() as u32, 2) as u16;
        out.push(u);
        if len < 0 && u == 0 {
            break;
        }
    }
    out
}

/// CT_CTYPE1 bits for a character: upper 1, lower 2, digit 4, space 8, punctuation 0x10,
/// control 0x20, blank 0x40, hex digit 0x80, alpha 0x100.
fn ctype(u: u16) -> u16 {
    let Ok(b) = u8::try_from(u) else { return 0x100 };
    let ch = b as char;
    let mut t = 0;
    if ch.is_ascii_uppercase() {
        t |= 0x101;
    }
    if ch.is_ascii_lowercase() {
        t |= 0x102;
    }
    if ch.is_ascii_digit() {
        t |= 0x4;
    }
    if ch.is_ascii_whitespace() {
        t |= 0x8;
    }
    if ch.is_ascii_punctuation() {
        t |= 0x10;
    }
    if ch.is_ascii_control() {
        t |= 0x20;
    }
    if ch == ' ' || ch == '\t' {
        t |= 0x40;
    }
    if ch.is_ascii_hexdigit() {
        t |= 0x80;
    }
    if b >= 0xc0 {
        t |= 0x100;
    }
    t
}

/// LCMAP_LOWERCASE 0x100, LCMAP_UPPERCASE 0x200, for ASCII.
fn map_case(u: u16, flags: u32) -> u16 {
    match u8::try_from(u) {
        Ok(b) if flags & 0x100 != 0 => u16::from(b.to_ascii_lowercase()),
        Ok(b) if flags & 0x200 != 0 => u16::from(b.to_ascii_uppercase()),
        _ => u,
    }
}

fn locale(kind: u32) -> &'static str {
    match kind & 0xffff {
        0x1004 => "1252",
        0xb => "437",
        0x1 => "0409",
        0x3 | 0x7 => "ENU",
        0x5 => "USA",
        0x0e => ".",
        0x0f => ",",
        0x14 => "$",
        _ => "",
    }
}

/// Year, month and day of a count of days since 1970-01-01.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}
