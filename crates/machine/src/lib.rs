//! The machine that code `recore-mcp lift` writes runs on: the x86 registers as bytes, a flat
//! 32-bit memory, and the p-code semantics recore's emulator runs ([`ops`], [`x87`]) for the
//! operations the lifter does not write out as Rust. Every call to an address at or above
//! [`HOST`] goes to the [`Host`], which the program running the lifted code provides: it stands
//! in for Windows and the other DLLs the executable imports.

mod coverage;
pub mod image;
pub mod ops;
pub mod x87;

use std::{collections::HashMap, fs::File, io::Read, path::Path, sync::OnceLock};

pub use ops::Code;
pub use x87::{f64_to_f80, f80_to_f64};
use ops::{compute, signed};

#[cold]
#[inline(never)]
fn outside_flat(addr: u32, len: usize) -> ! {
    panic!("memory {addr:#x}+{len:#x} is outside flat memory, which ends at {FLAT_SIZE:#x}");
}

/// Register offsets in the x86 p-code register space, as `(offset, size)`.
pub mod regs {
    pub const EAX: (u32, usize) = (0x0, 4);
    pub const ECX: (u32, usize) = (0x4, 4);
    pub const EDX: (u32, usize) = (0x8, 4);
    pub const EBX: (u32, usize) = (0xc, 4);
    pub const ESP: (u32, usize) = (0x10, 4);
    pub const EBP: (u32, usize) = (0x14, 4);
    pub const ESI: (u32, usize) = (0x18, 4);
    pub const EDI: (u32, usize) = (0x1c, 4);
    pub const FS_OFFSET: (u32, usize) = (0x110, 4);
    pub const FPU_CONTROL: (u32, usize) = (0x10a0, 2);
    pub const FPU_STATUS: (u32, usize) = (0x10a2, 2);
    pub const ST: [(u32, usize); 8] = [(0x1100, 10), (0x1110, 10), (0x1120, 10), (0x1130, 10), (0x1140, 10), (0x1150, 10), (0x1160, 10), (0x1170, 10)];
    pub const C: [(u32, usize); 4] = [(0x1090, 1), (0x1091, 1), (0x1092, 1), (0x1093, 1)];
}
use regs::*;

/// Addresses from here up belong to the host: import slots and methods of host objects.
pub const HOST: u32 = 0xf000_0000;

const PAGE: usize = 4096;

/// Whether flat memory reserves the whole 32-bit address space, as a 64-bit Unix host can. A
/// 32-bit host (wasm) holds only the low [`FLAT_SIZE`] bytes, where the host puts everything the
/// program uses, and an access above them panics.
const RESERVES_ALL: bool = cfg!(all(unix, target_pointer_width = "64"));
const FLAT_SIZE: u64 = if RESERVES_ALL { 1 << 32 } else { 1 << 29 };

struct Page {
    bytes: [u8; PAGE],
    dirty: [bool; PAGE],
}

/// Where memory nothing has written yet comes from.
enum Backing {
    /// A snapshot directory, as recore's `run` reads one: each region's bytes in `<start>.bin`.
    Snapshot { regions: Vec<(u32, u32, File)> },
    Image(Vec<image::Section>),
}

/// The program's memory, in one of two layouts. Flat: the address space ([`FLAT_SIZE`] bytes of
/// it) is one block and an access is one unaligned load or store. Paged: pages filled on first
/// touch, which also remember which bytes the program wrote, for comparisons with recore's
/// emulator (`writes`).
pub struct Mem {
    flat: *mut u8,
    pages: Vec<Option<Box<Page>>>,
    backing: Backing,
}

// The mapping belongs to the one thread that runs the lifted code.
unsafe impl Send for Mem {}

impl Mem {
    fn new(backing: Backing, flat: bool) -> std::io::Result<Mem> {
        if !flat {
            return Ok(Mem { flat: std::ptr::null_mut(), pages: (0..(1usize << 20)).map(|_| None).collect(), backing });
        }
        let base = Self::flat_block(&backing)?;
        Ok(Mem { flat: base, pages: Vec::new(), backing })
    }

    /// The whole address space: a private anonymous mapping reserved without backing store,
    /// snapshot regions mapped over it at their addresses.
    #[cfg(all(unix, target_pointer_width = "64"))]
    fn flat_block(backing: &Backing) -> std::io::Result<*mut u8> {
        // SAFETY: a fresh private anonymous mapping, reserved without backing store; regions are
        // mapped over it at fixed addresses inside it.
        let base = unsafe { libc::mmap(std::ptr::null_mut(), (1usize << 32) + PAGE, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE, -1, 0) };
        if base == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let base = base.cast::<u8>();
        match backing {
            Backing::Snapshot { regions } => {
                use std::os::fd::AsRawFd;
                for (start, end, file) in regions {
                    let len = (file.metadata()?.len().min(u64::from(end - start)) as usize).div_ceil(PAGE) * PAGE;
                    if len == 0 {
                        continue;
                    }
                    // SAFETY: inside the reservation; a private mapping of a file we opened.
                    let at = unsafe { libc::mmap(base.add(*start as usize).cast(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_FIXED, file.as_raw_fd(), 0) };
                    if at == libc::MAP_FAILED {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            Backing::Image(sections) => Self::copy_sections(base, sections),
        }
        Ok(base)
    }

    /// The low [`FLAT_SIZE`] bytes, zeroed, and a page more for the widest access at their end.
    #[cfg(not(all(unix, target_pointer_width = "64")))]
    fn flat_block(backing: &Backing) -> std::io::Result<*mut u8> {
        let layout = std::alloc::Layout::from_size_align(FLAT_SIZE as usize + PAGE, PAGE).expect("flat memory's layout");
        // SAFETY: the layout's size is not zero.
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        if base.is_null() {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        match backing {
            Backing::Snapshot { regions } => {
                for (start, end, file) in regions {
                    let mut bytes = Vec::new();
                    file.take(u64::from(end - start)).read_to_end(&mut bytes)?;
                    assert!(u64::from(*start) + bytes.len() as u64 <= FLAT_SIZE, "snapshot region {start:#x} is outside flat memory");
                    // SAFETY: inside the block, as just checked.
                    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(*start as usize), bytes.len()) };
                }
            }
            Backing::Image(sections) => Self::copy_sections(base, sections),
        }
        Ok(base)
    }

    fn copy_sections(base: *mut u8, sections: &[image::Section]) {
        for s in sections {
            assert!(u64::from(s.addr) + s.data.len() as u64 <= FLAT_SIZE, "section {:#x} is outside flat memory", s.addr);
            // SAFETY: inside the block, as just checked.
            unsafe { std::ptr::copy_nonoverlapping(s.data.as_ptr(), base.add(s.addr as usize), s.data.len()) };
        }
    }

    /// Where `len` bytes from `addr` live in flat memory; panics when they are outside it.
    #[inline(always)]
    fn flat_at(&self, addr: u32, len: usize) -> *mut u8 {
        if !RESERVES_ALL && u64::from(addr) + len as u64 > FLAT_SIZE {
            outside_flat(addr, len);
        }
        // SAFETY: inside the block: the whole address space, or checked above.
        unsafe { self.flat.add(addr as usize) }
    }

    fn page(&mut self, index: usize) -> &mut Page {
        if self.pages[index].is_none() {
            let mut page = Box::new(Page { bytes: [0; PAGE], dirty: [false; PAGE] });
            let start = (index * PAGE) as u32;
            match &self.backing {
                Backing::Snapshot { regions } => {
                    if let Some((s, _, file)) = regions.iter().find(|(s, e, _)| *s <= start && start < *e) {
                        use std::io::{Seek, SeekFrom};
                        let mut file = file;
                        let _ = file.seek(SeekFrom::Start(u64::from(start - s))).and_then(|_| file.read(&mut page.bytes));
                    }
                }
                Backing::Image(sections) => {
                    for s in sections {
                        let (from, to) = (start.max(s.addr), (start + PAGE as u32).min(s.addr + s.size));
                        if from < to {
                            page.bytes[(from - start) as usize..(to - start) as usize].copy_from_slice(&s.data[(from - s.addr) as usize..(to - s.addr) as usize]);
                        }
                    }
                }
            }
            self.pages[index] = Some(page);
        }
        self.pages[index].as_mut().expect("just filled")
    }

    #[inline]
    pub fn read(&mut self, addr: u32, size: usize) -> u128 {
        if !self.flat.is_null() {
            let p = self.flat_at(addr, size);
            // SAFETY: `flat_at` answers a place with `size` bytes and a page after it.
            return unsafe {
                match size {
                    1 => u128::from(*p),
                    2 => u128::from(p.cast::<u16>().read_unaligned()),
                    4 => u128::from(p.cast::<u32>().read_unaligned()),
                    8 => u128::from(p.cast::<u64>().read_unaligned()),
                    _ => p.cast::<u128>().read_unaligned() & ops::mask(size),
                }
            };
        }
        let mut v = 0u128;
        for i in 0..size {
            let a = addr.wrapping_add(i as u32) as usize;
            v |= u128::from(self.page(a / PAGE).bytes[a % PAGE]) << (8 * i);
        }
        v
    }

    #[inline]
    pub fn write(&mut self, addr: u32, size: usize, v: u128) {
        if !self.flat.is_null() {
            let p = self.flat_at(addr, size);
            // SAFETY: as in `read`.
            unsafe {
                match size {
                    1 => *p = v as u8,
                    2 => p.cast::<u16>().write_unaligned(v as u16),
                    4 => p.cast::<u32>().write_unaligned(v as u32),
                    8 => p.cast::<u64>().write_unaligned(v as u64),
                    _ => (0..size).for_each(|i| *p.add(i) = (v >> (8 * i)) as u8),
                }
            }
            return;
        }
        for i in 0..size {
            let a = addr.wrapping_add(i as u32) as usize;
            let p = self.page(a / PAGE);
            p.bytes[a % PAGE] = (v >> (8 * i)) as u8;
            p.dirty[a % PAGE] = true;
        }
    }

    /// Writes without marking the bytes as written by the program, for setup.
    pub fn poke(&mut self, addr: u32, bytes: &[u8]) {
        if !self.flat.is_null() {
            let p = self.flat_at(addr, bytes.len());
            // SAFETY: `flat_at` answers a place with `bytes.len()` bytes.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
            return;
        }
        for (i, &b) in bytes.iter().enumerate() {
            let a = addr.wrapping_add(i as u32) as usize;
            self.page(a / PAGE).bytes[a % PAGE] = b;
        }
    }

    pub fn bytes(&mut self, addr: u32, len: usize) -> Vec<u8> {
        if !self.flat.is_null() {
            let p = self.flat_at(addr, len);
            // SAFETY: `flat_at` answers a place with `len` bytes.
            return unsafe { std::slice::from_raw_parts(p, len) }.to_vec();
        }
        (0..len).map(|i| self.read(addr.wrapping_add(i as u32), 1) as u8).collect()
    }

    /// Where address `addr` lives in flat memory, for Rust that reads the program's structures
    /// in place. Paged memory has no such place.
    #[inline]
    pub fn ptr(&self, addr: u32) -> Option<*mut u8> {
        (!self.flat.is_null()).then(|| self.flat_at(addr, 1))
    }

    /// The text at `addr` up to its terminating zero.
    pub fn c_str(&mut self, addr: u32) -> String {
        let mut out = Vec::new();
        while out.len() < 0x10000 {
            let b = self.read(addr.wrapping_add(out.len() as u32), 1) as u8;
            if b == 0 {
                break;
            }
            out.push(b);
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The bytes the program wrote, outside `excluded` ranges, as `(address, bytes)` runs. Only
    /// paged memory knows them; flat memory answers none.
    pub fn writes(&self, excluded: &[(u32, u32)]) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        for (index, page) in self.pages.iter().enumerate() {
            let Some(page) = page else { continue };
            let mut at = 0;
            while at < PAGE {
                if !page.dirty[at] {
                    at += 1;
                    continue;
                }
                let start = at;
                while at < PAGE && page.dirty[at] {
                    at += 1;
                }
                let addr = (index * PAGE + start) as u32;
                if !excluded.iter().any(|&(s, e)| addr >= s && addr < e) {
                    out.push((addr, page.bytes[start..at].to_vec()));
                }
            }
        }
        out
    }
}

/// The return address [`Cpu::call`] pushes for lifted code called from Rust.
pub const NATIVE_RETURN: u32 = HOST - 8;

/// A number the program keeps in memory, little-endian and unaligned, which [`Cpu::get`] and
/// [`Cpu::set`] read and write.
pub trait Plain: Copy {
    fn from_bits(bits: u128) -> Self;
    fn to_bits(self) -> u128;
}

macro_rules! plain_integers {
    ($($t:ty),*) => {$(
        impl Plain for $t {
            fn from_bits(bits: u128) -> Self { bits as $t }
            fn to_bits(self) -> u128 { self as u128 & ops::mask(size_of::<$t>()) }
        }
    )*};
}

plain_integers!(u8, i8, u16, i16, u32, i32, u64, i64);

impl Plain for f32 {
    fn from_bits(bits: u128) -> Self {
        f32::from_bits(bits as u32)
    }
    fn to_bits(self) -> u128 {
        u128::from(f32::to_bits(self))
    }
}

impl Plain for f64 {
    fn from_bits(bits: u128) -> Self {
        f64::from_bits(bits as u64)
    }
    fn to_bits(self) -> u128 {
        u128::from(f64::to_bits(self))
    }
}

/// How a host function was entered: through a `CALL` that pushed a return address, or at a call
/// site the lifter intercepted before the `CALL` ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Called,
    AtCallSite,
}

/// What stands in for everything outside the executable. A host function that hands control to
/// lifted code, as `DispatchMessageA` calls a window procedure, sets the stack up with
/// [`Cpu::redirect`] and answers the code's address, which the machine then calls in its place.
pub trait Host {
    /// A call to an address at or above [`HOST`].
    fn call(&mut self, c: &mut Cpu, addr: u32, frame: Frame) -> Option<u32>;
    /// A call the lifter intercepted at an import's call site.
    fn import(&mut self, c: &mut Cpu, name: &str, frame: Frame) -> Option<u32>;
}

pub struct Cpu {
    regs: Box<[u8; 0x2000]>,
    /// The x87 registers ST0 to ST7, as `f64`: a program that keeps the control word at 53 bits
    /// computes so, and lifted code keeps them so, rounding as the word says in the functions that
    /// load another. `sts` and `save_st` give them in the extended format.
    st: [f64; 8],
    /// The general registers EAX to EDI and the flag bytes 0x200 to 0x20f, which lifted code
    /// saves and loads around every call; the other registers stay bytes in `regs`.
    g: [u32; 8],
    f: [u8; 16],
    uniques: HashMap<u64, u8>,
    pub mem: Mem,
    host: Option<Box<dyn Host>>,
    tsc: u64,
    /// Lifted code the host asked for with [`Cpu::defer`], with its arguments.
    deferred: Vec<(u32, Vec<u32>)>,
}

/// A lifted function.
pub type Lifted = fn(&mut Cpu);

/// The lifted functions, which [`dispatch`] looks up: a slot per address of the code section,
/// and the few entries outside it, sorted. The lifter also lifts words of data that only look
/// like code addresses (0xe8bef9bb among them); a slot per address up to those would span 30 GB.
pub struct Table {
    code: std::ops::Range<u32>,
    slots: Vec<Option<Lifted>>,
    others: Vec<(u32, Lifted)>,
    /// The functions later entries replaced, sorted: what [`original`] answers.
    replaced: Vec<(u32, Lifted)>,
}

pub static TABLE: OnceLock<Table> = OnceLock::new();

/// Installs the functions [`dispatch`] calls, given by their entry addresses, with `code` the
/// image's code section. A later entry for an address replaces an earlier one, as a port
/// written in Rust replaces the lifted function.
pub fn install(functions: Vec<(u32, Lifted)>, code: std::ops::Range<u32>) {
    let mut slots = vec![None; code.len()];
    let mut others: Vec<(u32, Lifted)> = Vec::new();
    let mut replaced: Vec<(u32, Lifted)> = Vec::new();
    for (addr, f) in functions {
        let old = if code.contains(&addr) {
            slots[(addr - code.start) as usize].replace(f)
        } else {
            let old = others.iter().position(|e| e.0 == addr).map(|i| others.remove(i).1);
            others.push((addr, f));
            old
        };
        if let Some(old) = old.filter(|_| !replaced.iter().any(|e| e.0 == addr)) {
            replaced.push((addr, old));
        }
    }
    others.sort_by_key(|e| e.0);
    replaced.sort_by_key(|e| e.0);
    coverage::start(slots.len());
    TABLE.set(Table { code, slots, others, replaced }).ok();
}

/// The function installed first at `addr` when a later entry replaced it, as a port replaces the
/// lifted original: a port that only adds to the original's work calls it through this.
pub fn original(addr: u32) -> Option<Lifted> {
    let replaced = &TABLE.get()?.replaced;
    replaced.binary_search_by_key(&addr, |e| e.0).ok().map(|i| replaced[i].1)
}

/// Calls the code at `addr`: a lifted function or the host.
pub fn dispatch(c: &mut Cpu, addr: u32) {
    if addr >= HOST {
        let mut host = c.host.take().expect("a host");
        let next = host.call(c, addr, Frame::Called);
        c.host = Some(host);
        c.run_deferred();
        if let Some(target) = next {
            dispatch(c, target);
        }
        return;
    }
    let table = TABLE.get().expect("the lifted functions");
    let found = if table.code.contains(&addr) {
        let index = (addr - table.code.start) as usize;
        coverage::entered(index);
        table.slots[index]
    } else {
        table.others.binary_search_by_key(&addr, |e| e.0).ok().map(|i| table.others[i].1)
    };
    match found {
        Some(f) => f(c),
        None => c.missing(addr),
    }
}

pub fn sx(v: u128, size: usize) -> i128 {
    signed(v, size)
}

impl Cpu {
    /// A machine over an image or a snapshot, with flat or paged memory (see [`Mem`]).
    pub fn new(backing_image: Option<image::Image>, snapshot: Option<&Path>, host: Box<dyn Host>, flat: bool) -> std::io::Result<Cpu> {
        let backing = match (snapshot, backing_image) {
            (Some(dir), _) => {
                let mut regions = Vec::new();
                for line in std::fs::read_to_string(dir.join("snapshot.tsv"))?.lines() {
                    let f: Vec<&str> = line.split('\t').collect();
                    if f[0] == "region" {
                        let (s, e) = (u32::from_str_radix(f[1], 16).unwrap_or(0), u32::from_str_radix(f[2], 16).unwrap_or(0));
                        regions.push((s, e, File::open(dir.join(format!("{}.bin", f[1])))?));
                    }
                }
                Backing::Snapshot { regions }
            }
            (None, Some(image)) => Backing::Image(image.sections),
            (None, None) => Backing::Image(Vec::new()),
        };
        let mut c = Cpu { regs: Box::new([0; 0x2000]), st: [0.0; 8], g: [0; 8], f: [0; 16], uniques: HashMap::new(), mem: Mem::new(backing, flat)?, host: Some(host), tsc: 0, deferred: Vec::new() };
        c.wg(FPU_CONTROL.0, 2, 0x27f);
        Ok(c)
    }

    #[inline]
    pub fn rg(&self, off: u32, size: usize) -> u128 {
        let at = off as usize;
        if at < 0x20 {
            return read_le(&gpr_bytes(self.g), at, size);
        }
        if (0x200..0x210).contains(&at) {
            return read_le(&self.f, at - 0x200, size);
        }
        read_le(&self.regs[..], at, size)
    }

    #[inline]
    pub fn wg(&mut self, off: u32, size: usize, v: u128) {
        let at = off as usize;
        if at < 0x20 {
            let mut bytes = gpr_bytes(self.g);
            write_le(&mut bytes, at, size, v);
            self.g = std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()));
            return;
        }
        if (0x200..0x210).contains(&at) {
            return write_le(&mut self.f, at - 0x200, size, v);
        }
        write_le(&mut self.regs[..], at, size, v)
    }

    pub fn reg(&self, r: (u32, usize)) -> u32 {
        match r {
            (off, 4) if off < 0x20 && off % 4 == 0 => self.g[off as usize / 4],
            _ => self.rg(r.0, r.1) as u32,
        }
    }

    pub fn set_reg(&mut self, r: (u32, usize), v: u32) {
        match r {
            (off, 4) if off < 0x20 && off % 4 == 0 => self.g[off as usize / 4] = v,
            _ => self.wg(r.0, r.1, u128::from(v)),
        }
    }

    pub fn uq(&self, off: u64, size: usize) -> u128 {
        (0..size).map(|i| u128::from(*self.uniques.get(&(off + i as u64)).unwrap_or(&0)) << (8 * i)).fold(0, |a, b| a | b)
    }

    pub fn wuq(&mut self, off: u64, size: usize, v: u128) {
        for i in 0..size {
            self.uniques.insert(off + i as u64, (v >> (8 * i)) as u8);
        }
    }

    #[inline]
    pub fn ld(&mut self, addr: u32, size: usize) -> u128 {
        self.mem.read(addr, size)
    }

    #[inline]
    pub fn st(&mut self, addr: u32, size: usize, v: u128) {
        self.mem.write(addr, size, v)
    }

    /// Loads and stores of one width, which lifted code calls for the values it keeps in the
    /// Rust type of their size.
    #[inline]
    pub fn ld_u8(&mut self, addr: u32) -> u8 {
        self.mem.read(addr, 1) as u8
    }

    #[inline]
    pub fn ld_u16(&mut self, addr: u32) -> u16 {
        self.mem.read(addr, 2) as u16
    }

    #[inline]
    pub fn ld_u32(&mut self, addr: u32) -> u32 {
        self.mem.read(addr, 4) as u32
    }

    #[inline]
    pub fn ld_u64(&mut self, addr: u32) -> u64 {
        self.mem.read(addr, 8) as u64
    }

    #[inline]
    pub fn st_u8(&mut self, addr: u32, v: u8) {
        self.mem.write(addr, 1, u128::from(v))
    }

    #[inline]
    pub fn st_u16(&mut self, addr: u32, v: u16) {
        self.mem.write(addr, 2, u128::from(v))
    }

    #[inline]
    pub fn st_u32(&mut self, addr: u32, v: u32) {
        self.mem.write(addr, 4, u128::from(v))
    }

    #[inline]
    pub fn st_u64(&mut self, addr: u32, v: u64) {
        self.mem.write(addr, 8, u128::from(v))
    }

    pub fn u32_at(&mut self, addr: u32) -> u32 {
        self.mem.read(addr, 4) as u32
    }

    pub fn set_u32(&mut self, addr: u32, v: u32) {
        self.mem.write(addr, 4, u128::from(v));
    }

    /// The control word, as lifted code that keeps the x87 registers as f64 reads it.
    #[inline]
    fn control_word(&self) -> u16 {
        let at = FPU_CONTROL.0 as usize;
        u16::from_le_bytes([self.regs[at], self.regs[at + 1]])
    }

    /// A float operation of a lifted body that loads the control word, on its `f64` registers,
    /// rounded as the word says. `native` is the operation done in `f64`: what the processor gives
    /// to nearest at 53 bits, and narrowed to a normal `f32` at 24. Any other rounding, or a
    /// result past single precision's range at 24 bits, is the x87's own on the operands widened,
    /// which hold them exactly, rounded once into an `f64`.
    #[inline]
    fn controlled(&self, code: Code, inputs: &[f64], native: f64) -> f64 {
        let word = self.control_word();
        if word & 0xc00 == 0 {
            if word & 0x300 != 0 {
                return native;
            }
            let narrow = native as f32;
            if narrow.is_normal() {
                return f64::from(narrow);
            }
        }
        let mut widened = [(0, 10); 2];
        for (place, &x) in widened.iter_mut().zip(inputs) {
            place.0 = f64_to_f80(x);
        }
        f64::from_bits(x87::compute(code, 8, &widened[..inputs.len()], self.control()).unwrap_or_else(|e| panic!("{code:?}: {e}")) as u64)
    }

    #[inline]
    pub fn f64_add(&self, a: f64, b: f64) -> f64 {
        self.controlled(Code::FAdd, &[a, b], a + b)
    }

    #[inline]
    pub fn f64_sub(&self, a: f64, b: f64) -> f64 {
        self.controlled(Code::FSub, &[a, b], a - b)
    }

    #[inline]
    pub fn f64_mult(&self, a: f64, b: f64) -> f64 {
        self.controlled(Code::FMult, &[a, b], a * b)
    }

    #[inline]
    pub fn f64_div(&self, a: f64, b: f64) -> f64 {
        self.controlled(Code::FDiv, &[a, b], a / b)
    }

    #[inline]
    pub fn f64_sqrt(&self, a: f64) -> f64 {
        self.controlled(Code::FSqrt, &[a], a.sqrt())
    }

    /// `x` stored as a 4-byte float, rounded the way the control word says.
    #[inline]
    pub fn f64_to_4(&self, x: f64) -> u32 {
        if self.control_word() & 0xc00 == 0 {
            return (x as f32).to_bits();
        }
        x87::compute(Code::Float2Float, 4, &[(f64_to_f80(x), 10)], self.control()).unwrap_or_else(|e| panic!("Float2Float: {e}")) as u32
    }

    /// `x` rounded to an integer in the direction the control word says.
    #[inline]
    pub fn to_integral(&self, x: f64) -> f64 {
        match self.control_word() >> 10 & 3 {
            0 => x.round_ties_even(),
            1 => x.floor(),
            2 => x.ceil(),
            _ => x.trunc(),
        }
    }

    fn control(&self) -> x87::Control {
        x87::Control::from_word(self.rg(FPU_CONTROL.0, 2))
    }

    /// The x87's common float operations, one function for each operation and operand size, which
    /// the lifter calls instead of [`Cpu::op`]: each is `op` with the case fixed, so the compiler
    /// keeps only that case, once, here rather than in every lifted call site. `f_add` adds two
    /// extended floats into one, `f_less` compares two, `f_4_10` widens a float to extended,
    /// `f_10_4` rounds extended to a float, `i_4_10` converts a 32-bit integer.
    #[inline(always)]
    fn float(&mut self, code: Code, size: usize, inputs: &[(u128, usize)]) -> u128 {
        x87::compute(code, size, inputs, self.control()).unwrap_or_else(|e| panic!("{code:?}: {e}"))
    }

    #[inline(never)]
    pub fn f_add(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FAdd, 10, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_sub(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FSub, 10, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_mult(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FMult, 10, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_div(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FDiv, 10, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_sqrt(&mut self, a: u128) -> u128 {
        self.float(Code::FSqrt, 10, &[(a, 10)])
    }

    #[inline(never)]
    pub fn f_equal(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FEqual, 1, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_not_equal(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FNotEqual, 1, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_less(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FLess, 1, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_less_equal(&mut self, a: u128, b: u128) -> u128 {
        self.float(Code::FLessEqual, 1, &[(a, 10), (b, 10)])
    }

    #[inline(never)]
    pub fn f_nan(&mut self, a: u128) -> u128 {
        self.float(Code::FNan, 1, &[(a, 10)])
    }

    #[inline(never)]
    pub fn f_4_10(&mut self, a: u128) -> u128 {
        self.float(Code::Float2Float, 10, &[(a, 4)])
    }

    #[inline(never)]
    pub fn f_8_10(&mut self, a: u128) -> u128 {
        self.float(Code::Float2Float, 10, &[(a, 8)])
    }

    #[inline(never)]
    pub fn f_10_4(&mut self, a: u128) -> u128 {
        self.float(Code::Float2Float, 4, &[(a, 10)])
    }

    #[inline(never)]
    pub fn f_10_8(&mut self, a: u128) -> u128 {
        self.float(Code::Float2Float, 8, &[(a, 10)])
    }

    #[inline(never)]
    pub fn i_2_10(&mut self, a: u128) -> u128 {
        self.float(Code::Int2Float, 10, &[(a, 2)])
    }

    #[inline(never)]
    pub fn i_4_10(&mut self, a: u128) -> u128 {
        self.float(Code::Int2Float, 10, &[(a, 4)])
    }

    #[inline(never)]
    pub fn i_8_10(&mut self, a: u128) -> u128 {
        self.float(Code::Int2Float, 10, &[(a, 8)])
    }

    pub fn op(&mut self, code: Code, size: usize, inputs: &[(u128, usize)]) -> u128 {
        let r = if x87::applies(code, size, inputs) { x87::compute(code, size, inputs, self.control()) } else { compute(code, size, inputs, false) };
        r.unwrap_or_else(|e| panic!("{code:?}: {e}"))
    }

    pub fn x87(&mut self, instruction: x87::Instruction) {
        let mut stack = self.sts();
        let outcome = x87::execute(instruction, stack[0], stack[1], self.control());
        match outcome.stack {
            x87::Stack::Replace(top) => stack[0] = top,
            x87::Stack::Pop(top) => {
                stack.copy_within(1.., 0);
                stack[0] = top;
            }
            x87::Stack::ReplacePush(top, pushed) => {
                stack.copy_within(..7, 1);
                stack[1] = top;
                stack[0] = pushed;
            }
            x87::Stack::Push(pushed) => {
                stack.copy_within(..7, 1);
                stack[0] = pushed;
            }
        }
        self.save_st(stack);
        let mut status = self.rg(FPU_STATUS.0, 2);
        for (index, (condition, bit)) in outcome.conditions.into_iter().zip([8, 9, 10, 14]).enumerate() {
            if let Some(set) = condition {
                self.wg(C[index].0, 1, u128::from(set));
                status = status & !(1 << bit) | u128::from(set) << bit;
            }
        }
        self.wg(FPU_STATUS.0, 2, status);
    }

    /// The registers a lifted function keeps in locals, written back before a call or a return.
    pub fn save(&mut self, g: [u32; 8], f: [u8; 16], s: [u128; 8]) {
        self.g = g;
        self.f = f;
        self.save_st(s);
    }

    /// The general registers, before a call or at a return. The lifter adds the flags
    /// ([`Cpu::save_f`]) and the x87 registers ([`Cpu::save_st`]) only where the callee or the
    /// caller reads them.
    #[inline]
    pub fn save_g(&mut self, g: [u32; 8]) {
        self.g = g;
    }

    #[inline]
    pub fn save_f(&mut self, f: [u8; 16]) {
        self.f = f;
    }

    pub fn save_st(&mut self, s: [u128; 8]) {
        self.st = s.map(f80_to_f64);
    }

    #[inline]
    pub fn gpr(&self) -> [u32; 8] {
        self.g
    }

    #[inline]
    pub fn flags(&self) -> [u8; 16] {
        self.f
    }

    pub fn sts(&self) -> [u128; 8] {
        self.st.map(f64_to_f80)
    }

    /// `save_st` and `sts` as the machine keeps the registers, for lifted code that keeps
    /// them as `f64` too.
    #[inline]
    pub fn save_st64(&mut self, s: [f64; 8]) {
        self.st = s;
    }

    #[inline]
    pub fn sts64(&self) -> [f64; 8] {
        self.st
    }

    /// A processor operation the p-code leaves to the machine. CPUID reports an Intel
    /// Pentium Pro class processor with the x87 unit, a time stamp counter and CMPXCHG8B, and no
    /// MMX, SSE or 3DNow!, so a program takes its plain x87 paths; Ghidra's CPUID answers with the
    /// address of EAX, EBX, EDX, ECX.
    pub fn callother(&mut self, name: &str, input: u128) -> u128 {
        const CPUID: u32 = 0xefff_0000;
        if name == "rdtsc" {
            self.tsc += 1000;
            return u128::from(self.tsc);
        }
        let (eax, ebx, edx, ecx): (u32, u32, u32, u32) = match name {
            "cpuid_basic_info" => (1, u32::from_le_bytes(*b"Genu"), u32::from_le_bytes(*b"ineI"), u32::from_le_bytes(*b"ntel")),
            "cpuid_Version_info" => (0x0612, 0, 0x0000_8111, 0),
            _ => {
                let _ = input;
                (0, 0, 0, 0)
            }
        };
        for (i, v) in [eax, ebx, edx, ecx].into_iter().enumerate() {
            self.mem.poke(CPUID + 4 * i as u32, &v.to_le_bytes());
        }
        u128::from(CPUID)
    }

    pub fn missing(&mut self, addr: u32) {
        panic!("no lifted function at {addr:#x}");
    }

    pub fn import(&mut self, name: &str, tail: bool) {
        let mut host = self.host.take().expect("a host");
        let next = host.import(self, name, if tail { Frame::Called } else { Frame::AtCallSite });
        self.host = Some(host);
        self.run_deferred();
        if let Some(target) = next {
            dispatch(self, target);
        }
    }

    /// Asks for a call of lifted code at `addr` with `args` once the host function running now
    /// returns, as Windows runs a library's callbacks on a thread of its own. The host cannot run
    /// lifted code itself, since that code calls the host in turn.
    pub fn defer(&mut self, addr: u32, args: Vec<u32>) {
        self.deferred.push((addr, args));
    }

    /// Runs the calls [`Cpu::defer`] asked for, keeping the host function's answer in EAX and EDX.
    fn run_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        let (eax, edx) = (self.reg(EAX), self.reg(EDX));
        for (addr, args) in std::mem::take(&mut self.deferred) {
            self.call(addr, None, &args);
        }
        self.set_reg(EAX, eax);
        self.set_reg(EDX, edx);
    }

    /// Replaces a host function entered with `frame`, which took `taken` stack arguments, with a
    /// call of lifted code that takes `args`: the code returns where the host function would
    /// have, with the stack as the host function would have left it.
    pub fn redirect(&mut self, frame: Frame, taken: u32, args: &[u32]) {
        let sp = self.reg(ESP);
        let (ret, after) = match frame {
            Frame::Called => (self.u32_at(sp), sp + 4 + 4 * taken),
            Frame::AtCallSite => (HOST - 4, sp + 4 * taken),
        };
        let mut at = after;
        for &v in args.iter().rev() {
            at -= 4;
            self.set_u32(at, v);
        }
        at -= 4;
        self.set_u32(at, ret);
        self.set_reg(ESP, at);
    }

    /// Calls lifted code at `addr` from Rust as a `CALL` does, with `this` in ECX and `args` pushed
    /// right to left, and answers EAX. The stack is as it was before, whichever side takes the
    /// arguments off. The return address pushed is [`NATIVE_RETURN`], which nothing jumps to:
    /// lifted code returns by returning.
    pub fn call(&mut self, addr: u32, this: Option<u32>, args: &[u32]) -> u32 {
        let sp = self.reg(ESP);
        let mut at = sp;
        for &v in args.iter().rev() {
            at -= 4;
            self.set_u32(at, v);
        }
        at -= 4;
        self.set_u32(at, NATIVE_RETURN);
        self.set_reg(ESP, at);
        if let Some(this) = this {
            self.set_reg(ECX, this);
        }
        dispatch(self, addr);
        self.set_reg(ESP, sp);
        self.reg(EAX)
    }

    /// A value of the program's memory at `addr`, as its bytes are laid out there.
    #[inline]
    pub fn get<T: Plain>(&mut self, addr: u32) -> T {
        T::from_bits(self.mem.read(addr, size_of::<T>()))
    }

    #[inline]
    pub fn set<T: Plain>(&mut self, addr: u32, value: T) {
        self.mem.write(addr, size_of::<T>(), value.to_bits());
    }

    /// The `n`th stack argument of a host function entered with `frame`.
    pub fn arg(&mut self, frame: Frame, n: u32) -> u32 {
        let sp = self.reg(ESP) + if frame == Frame::Called { 4 } else { 0 };
        self.u32_at(sp + 4 * n)
    }

    /// Returns from a host function: `value` in EAX, `args` stack arguments taken off as a
    /// stdcall function does, and the return address if the `CALL` pushed one.
    pub fn ret(&mut self, frame: Frame, value: Option<u32>, args: u32) {
        if let Some(v) = value {
            self.set_reg(EAX, v);
        }
        let sp = self.reg(ESP) + if frame == Frame::Called { 4 } else { 0 } + 4 * args;
        self.set_reg(ESP, sp);
    }
}

/// Reads all of a file into memory at `addr`, for hosts that load data.
pub fn read_file_into(c: &mut Cpu, file: &mut File, addr: u32, len: usize) -> std::io::Result<usize> {
    let mut buf = vec![0; len];
    let got = file.read(&mut buf)?;
    for (i, b) in buf[..got].iter().enumerate() {
        c.mem.write(addr + i as u32, 1, u128::from(*b));
    }
    Ok(got)
}

/// The general registers as the bytes `rg` and `wg` address, EAX first.
fn gpr_bytes(g: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (i, v) in g.into_iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    bytes
}

/// The little-endian value of `size` bytes at `at`.
#[inline]
fn read_le(r: &[u8], at: usize, size: usize) -> u128 {
    match size {
        1 => u128::from(r[at]),
        2 => u128::from(u16::from_le_bytes(r[at..at + 2].try_into().unwrap())),
        4 => u128::from(u32::from_le_bytes(r[at..at + 4].try_into().unwrap())),
        8 => u128::from(u64::from_le_bytes(r[at..at + 8].try_into().unwrap())),
        _ => (0..size).fold(0, |v, i| v | u128::from(r[at + i]) << (8 * i)),
    }
}

#[inline]
fn write_le(r: &mut [u8], at: usize, size: usize, v: u128) {
    match size {
        1 => r[at] = v as u8,
        2 => r[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes()),
        4 => r[at..at + 4].copy_from_slice(&(v as u32).to_le_bytes()),
        8 => r[at..at + 8].copy_from_slice(&(v as u64).to_le_bytes()),
        _ => (0..size).for_each(|i| r[at + i] = (v >> (8 * i)) as u8),
    }
}
