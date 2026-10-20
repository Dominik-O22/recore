//! What a 32-bit Windows program finds of its system: the thread environment block that `FS`
//! points to, and stand-ins for the system functions the MSVC C runtime calls for it. They
//! keep their state where Windows does, in the block, so a run on a snapshot's thread reads
//! that thread's last error and TLS slots.

use super::{Emulator, Return};

/// The register that holds where `FS` begins, as the processor specification names it.
pub(super) const SEGMENT: &str = "FS_OFFSET";
/// Bytes of a thread environment block that a run treats as its own.
pub(super) const TEB_SIZE: u64 = 0x1000;

// Offsets in a 32-bit thread environment block.
const EXCEPTION_LIST: u64 = 0x0;
const STACK_BASE: u64 = 0x4;
const STACK_LIMIT: u64 = 0x8;
const SELF: u64 = 0x18;
const PROCESS_ID: u64 = 0x20;
const THREAD_ID: u64 = 0x24;
const LAST_ERROR: u64 = 0x34;
const TLS_SLOTS: u64 = 0xe10;
const TLS_EXPANSION: u64 = 0xf94;

/// TLS slots in the block, and more that a block it points to holds.
const SLOTS: u64 = 64;
const EXPANSION_SLOTS: u64 = 1024;
/// The process and thread a fresh block says it is.
const FRESH_PROCESS: u64 = 0x100;
const FRESH_THREAD: u64 = 0x104;

const ERROR_INVALID_PARAMETER: u64 = 87;
const TLS_OUT_OF_INDEXES: u64 = 0xffff_ffff;
/// `HEAP_ZERO_MEMORY`, which asks `HeapAlloc` for a block of zeros.
const HEAP_ZERO_MEMORY: u64 = 8;

/// What the run keeps of the thread it is on, besides what its environment block holds.
#[derive(Default)]
pub(super) struct Thread {
    /// Where the block is, once the run has started.
    pub teb: Option<u64>,
    /// The TLS slots `TlsAlloc` gave out, a bit each.
    taken: u64,
}

impl Emulator<'_> {
    /// Points `FS` at the block the caller chose with `FS_OFFSET`, or at the first thread the
    /// snapshot lists, or else at a fresh block whose stack is the run's and whose last error
    /// and TLS slots are zero.
    pub(super) fn start_thread(&mut self, chosen: Option<u64>) -> Result<(), String> {
        let snapshot = self.memory.snapshot;
        let listed = snapshot.map_or(&[][..], |snapshot| &snapshot.tebs[..]);
        let teb = match (chosen, listed.first()) {
            (Some(teb), _) => teb,
            (None, Some(&teb)) => {
                let others = if listed.len() > 1 { format!(", the first of the {} it lists", listed.len()) } else { String::new() };
                self.note_once(format!("the run is on the snapshot's thread whose TEB is at {teb:#x}{others}: set FS_OFFSET to choose another"));
                teb
            }
            (None, None) => {
                let teb = self.fresh_teb;
                self.write_memory(teb, &[0; TEB_SIZE as usize], false);
                for (offset, value) in [(EXCEPTION_LIST, 0xffff_ffff), (STACK_BASE, self.stack.1), (STACK_LIMIT, self.stack.0), (SELF, teb), (PROCESS_ID, FRESH_PROCESS), (THREAD_ID, FRESH_THREAD)] {
                    self.write_word(teb + offset, value, false);
                }
                if snapshot.is_some() {
                    self.note_once("the snapshot lists no thread, so the run is on a fresh one, whose TLS slots are empty".into());
                }
                teb
            }
        };
        self.thread.teb = Some(teb);
        self.write_register(SEGMENT, u128::from(teb))
    }

    fn write_word(&mut self, addr: u64, value: u64, mark: bool) {
        self.memory.write(&self.binary.program.image, self.memory.code, addr, 4, u128::from(value), mark);
    }

    /// Where the TLS slot `index` of the thread at `teb` is, if it has one.
    fn tls_slot(&mut self, teb: u64, index: u64) -> Option<u64> {
        if index < SLOTS {
            return Some(teb + TLS_SLOTS + 4 * index);
        }
        let expansion = self.read_pointer(teb + TLS_EXPANSION);
        (index < SLOTS + EXPANSION_SLOTS && expansion != 0).then(|| expansion + 4 * (index - SLOTS))
    }

    /// Runs the stand-in for the Windows function `name`, or gives `None` if it has none.
    pub(super) fn windows_stand_in(&mut self, name: &str, tail: bool) -> Result<Option<Return>, String> {
        if !self.abi.windows {
            return Ok(None);
        }
        let teb = self.read_register(SEGMENT)? as u64;
        let (args, value) = match name {
            "GetLastError" => (0, Some(self.read_pointer(teb + LAST_ERROR))),
            "SetLastError" => {
                let code = self.argument(0, tail)?;
                self.write_word(teb + LAST_ERROR, code, true);
                (1, None)
            }
            "GetCurrentThreadId" => (0, Some(self.read_pointer(teb + THREAD_ID))),
            // A clock a run reads gives a different answer each time, unless the caller fixes it.
            "GetTickCount" => match self.ticks {
                Some(ticks) => (0, Some(ticks)),
                None => return Ok(None),
            },
            // A slot is free if this thread's value is zero and the run gave it out to no one. On
            // a snapshot's thread that may be a slot another module of the process owns, which
            // the PEB's TLS bitmap would tell.
            "TlsAlloc" => {
                let mut free = None;
                for index in 0..SLOTS {
                    if self.thread.taken >> index & 1 == 0 && self.read_pointer(teb + TLS_SLOTS + 4 * index) == 0 {
                        free = Some(index);
                        break;
                    }
                }
                if let Some(index) = free {
                    self.thread.taken |= 1 << index;
                }
                (0, Some(free.unwrap_or(TLS_OUT_OF_INDEXES)))
            }
            // Both say in the last error whether the thread has the slot.
            "TlsGetValue" => {
                let index = self.argument(0, tail)?;
                let slot = self.tls_slot(teb, index);
                self.write_word(teb + LAST_ERROR, if slot.is_some() { 0 } else { ERROR_INVALID_PARAMETER }, true);
                (1, Some(slot.map_or(0, |slot| self.read_pointer(slot))))
            }
            "TlsSetValue" => {
                let (index, value) = (self.argument(0, tail)?, self.argument(1, tail)?);
                let slot = self.tls_slot(teb, index);
                match slot {
                    Some(slot) => self.write_word(slot, value, true),
                    None => {
                        self.write_word(teb + LAST_ERROR, ERROR_INVALID_PARAMETER, true);
                        self.note_once(format!("TlsSetValue failed for TLS index {index:#x}, which the thread has no slot for. A C runtime whose startup did not run passes 0xffffffff: run the startup first with `before`"));
                    }
                }
                (2, Some(u64::from(slot.is_some())))
            }
            "HeapAlloc" => {
                let (flags, size) = (self.argument(1, tail)?, self.argument(2, tail)?);
                let block = self.allocate(size);
                if let Some(block) = block.filter(|_| flags & HEAP_ZERO_MEMORY != 0) {
                    let size = self.length(size)?;
                    self.write_memory(block, &vec![0; size as usize], false);
                }
                (3, Some(block.unwrap_or(0)))
            }
            "HeapFree" => (3, Some(1)),
            // One thread runs, so no lock is ever held by another.
            "InitializeCriticalSection" | "EnterCriticalSection" | "LeaveCriticalSection" | "DeleteCriticalSection" => (1, None),
            // The run loads no module but the binary, which a null name asks for.
            "GetModuleHandleA" => {
                let named = self.argument(0, tail)?;
                if named != 0 {
                    let named = self.text_at(named, false);
                    self.note_once(format!("GetModuleHandleA asked for {named}, which the run does not load, and was answered NULL"));
                }
                (1, Some(if named == 0 { self.binary.program.image.base } else { 0 }))
            }
            "GetFileVersionInfoSizeA" => {
                let (file, handle) = (self.argument(0, tail)?, self.argument(1, tail)?);
                let (_, size) = self.version_resource(name, file)?;
                if handle != 0 {
                    self.write_word(handle, 0, true);
                }
                (2, Some(size))
            }
            "GetFileVersionInfoA" => {
                let (file, len, data) = (self.argument(0, tail)?, self.argument(2, tail)?, self.argument(3, tail)?);
                let (addr, size) = self.version_resource(name, file)?;
                let len = self.length(len.min(size))?;
                let bytes: Vec<u8> = (0..len).map(|index| self.byte_at(addr + index)).collect();
                self.write_memory(data, &bytes, true);
                (4, Some(1))
            }
            "VerQueryValueA" => {
                let (block, path, value, len) = (self.argument(0, tail)?, self.argument(1, tail)?, self.argument(2, tail)?, self.argument(3, tail)?);
                let path = self.text_at(path, false);
                let found = self.version_value(block, &path)?;
                if let Some((addr, size)) = found {
                    self.write_word(value, addr, true);
                    self.write_word(len, size, true);
                }
                (4, Some(u64::from(found.is_some())))
            }
            _ => return Ok(None),
        };
        Ok(Some(Return { value, pops: 4 * args }))
    }

    /// The text at `addr`, of bytes or of UTF-16 units, up to its end.
    fn text_at(&mut self, addr: u64, wide: bool) -> String {
        let unit = if wide { 2 } else { 1 };
        let mut units = Vec::new();
        loop {
            let code = self.memory.read(&self.binary.program.image, self.memory.code, addr + unit * units.len() as u64, unit as usize) as u16;
            if code == 0 || units.len() >= 0x1000 {
                break;
            }
            units.push(code);
        }
        String::from_utf16_lossy(&units)
    }

    /// The address and size of the binary's own version resource, which answers for whatever
    /// file the program names, and says so.
    fn version_resource(&mut self, function: &str, file: u64) -> Result<(u64, u64), String> {
        let named = self.text_at(file, false);
        let found = self.binary.program.image.version_resource.ok_or_else(|| format!("{function} asked for the version of {named}, and the binary has no version resource to answer from"))?;
        self.note_once(format!("{function} asked for the version of {named}, and the binary's own version resource answered"));
        Ok(found)
    }

    /// The value at `path` in the version information at `block`, as the address and length
    /// `VerQueryValue` gives: `\` for the fixed file information, and the names of nested
    /// blocks after it, as `\VarFileInfo\Translation`. Each block is its length, the length of
    /// its value, its type, its name in UTF-16, the value and the blocks in it, each part
    /// aligned to 4 bytes.
    fn version_value(&mut self, block: u64, path: &str) -> Result<Option<(u64, u64)>, String> {
        let mut at = block;
        for name in path.split('\\').filter(|name| !name.is_empty()) {
            let end = at + self.half(at);
            let (value, value_length) = self.version_value_place(at);
            let mut child = (value + value_length + 3) & !3;
            at = loop {
                let length = self.half(child);
                if child >= end || length == 0 {
                    return Ok(None);
                }
                if self.text_at(child + 6, true).eq_ignore_ascii_case(name) {
                    break child;
                }
                child = (child + length + 3) & !3;
            };
        }
        if self.half(at + 4) == 1 {
            return Err(format!("the run asked for the text `{path}` of a version resource, which the stand-in does not convert"));
        }
        Ok(Some(self.version_value_place(at)))
    }

    /// Where the value of the version block at `at` begins, after its name, and its bytes.
    fn version_value_place(&mut self, at: u64) -> (u64, u64) {
        let name = self.text_at(at + 6, true).encode_utf16().count() as u64;
        let value = (at + 6 + 2 * (name + 1) + 3) & !3;
        let units = if self.half(at + 4) == 1 { 2 } else { 1 };
        (value, self.half(at + 2) * units)
    }

    fn half(&mut self, addr: u64) -> u64 {
        self.memory.read(&self.binary.program.image, self.memory.code, addr, 2) as u64
    }
}
