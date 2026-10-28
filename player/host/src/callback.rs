//! Host functions that call game code more than once, as `EnumDisplayModes` calls its callback
//! for each mode. While a host function runs the machine has no host, so game code it calls could
//! not reach an import (the callbacks allocate, which can reach `HeapAlloc`). Instead the host
//! function hands control with `Cpu::redirect` to [`call_each`], a Rust function in the lifted
//! functions' table, which runs as game code does, with the host in place.

use recore_machine::{Cpu, Frame, Lifted, regs::*};

use crate::Win32;

/// Where [`call_each`] sits in the table of lifted functions, below the host's addresses.
pub const CALL_EACH: u32 = 0xe000_0000;

pub const NATIVE: &[(u32, Lifted)] = &[(CALL_EACH, call_each)];

impl Win32 {
    /// Ends the running host function, entered with `frame` and taking `taken` stack arguments,
    /// by calling `callback` with each of `calls` until one answers 0, as DDENUMRET_CANCEL does,
    /// and then answering `result`.
    pub fn call_each(&mut self, c: &mut Cpu, frame: Frame, taken: u32, callback: u32, calls: &[Vec<u32>], result: u32) {
        let width = calls.first().map_or(0, Vec::len) as u32;
        let block = self.alloc(4 * width * calls.len() as u32);
        for (i, v) in calls.iter().flatten().enumerate() {
            c.set_u32(block + 4 * i as u32, *v);
        }
        c.redirect(frame, taken, &[callback, calls.len() as u32, width, block, result]);
        self.next = Some(CALL_EACH);
    }
}

/// `call_each(callback, count, width, block, result)`, stdcall: calls `callback` with each row of
/// `width` words of `block` until one answers 0, and answers `result`.
fn call_each(c: &mut Cpu) {
    let sp = c.reg(ESP);
    let [callback, count, width, block, result] = std::array::from_fn(|i| c.u32_at(sp + 4 + 4 * i as u32));
    for i in 0..count {
        let args: Vec<u32> = (0..width).map(|k| c.u32_at(block + 4 * (i * width + k))).collect();
        if c.call(callback, None, &args) == 0 {
            break;
        }
    }
    c.set_reg(EAX, result);
    c.set_reg(ESP, sp + 4 + 4 * 5);
}
