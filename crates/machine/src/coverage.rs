//! Which functions of the code section a run entered: while `LIFT_COVERAGE` names a file,
//! [`dispatch`](crate::dispatch) sets a bit per entry it calls, and the file gets them when the
//! process exits. Off, it costs `dispatch` one load.
//!
//! The file starts with `functions <n> ports <m>`, the entries of the code section the table
//! holds and how many of them ports replaced, then has one line per entry entered,
//! `0x<addr> lifted` or `0x<addr> port`.

use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::TABLE;

/// A bit per address of the code section.
static ENTERED: OnceLock<Box<[AtomicU64]>> = OnceLock::new();

/// Starts counting when `LIFT_COVERAGE` is set, for a code section of `len` addresses.
pub(crate) fn start(len: usize) {
    if std::env::var_os("LIFT_COVERAGE").is_none() {
        return;
    }
    let bits = (0..len.div_ceil(64)).map(|_| AtomicU64::new(0)).collect();
    if ENTERED.set(bits).is_ok() {
        // SAFETY: `written` takes no arguments and only writes a file.
        #[cfg(unix)]
        unsafe { libc::atexit(written) };
    }
}

/// `dispatch` enters the entry at `index` of the code section.
#[inline]
pub(crate) fn entered(index: usize) {
    if let Some(bits) = ENTERED.get() {
        let (word, bit) = (&bits[index / 64], 1u64 << (index % 64));
        if word.load(Relaxed) & bit == 0 {
            word.fetch_or(bit, Relaxed);
        }
    }
}

// Without libc's `atexit` (wasm) the file is never written.
#[cfg_attr(not(unix), allow(dead_code))]
extern "C" fn written() {
    let (Some(path), Some(bits), Some(table)) = (std::env::var_os("LIFT_COVERAGE"), ENTERED.get(), TABLE.get()) else { return };
    let Ok(file) = std::fs::File::create(path) else { return };
    let mut out = std::io::BufWriter::new(file);
    let port = |addr: u32| table.replaced.binary_search_by_key(&addr, |e| e.0).is_ok();
    let functions = table.slots.iter().filter(|f| f.is_some()).count();
    let ports = table.replaced.iter().filter(|e| table.code.contains(&e.0)).count();
    writeln!(out, "functions {functions} ports {ports}").ok();
    for (index, slot) in table.slots.iter().enumerate() {
        if slot.is_some() && bits[index / 64].load(Relaxed) & 1 << (index % 64) != 0 {
            let addr = table.code.start + index as u32;
            writeln!(out, "{addr:#x} {}", if port(addr) { "port" } else { "lifted" }).ok();
        }
    }
}
