//! winmm.dll: the multimedia timers the game counts its frames with, and the joystick, which is
//! absent, and CD audio's command strings, which cd.rs answers. A periodic timer's callback runs
//! when the game next reads the clock after it is due, which suits timers that count frames.

use recore_machine::{Cpu, Frame};

use crate::Win32;

pub struct Timer {
    id: u32,
    period_us: u64,
    due_us: u64,
    callback: u32,
    user: u32,
    periodic: bool,
}

#[derive(Default)]
pub struct Timers {
    timers: Vec<Timer>,
    next: u32,
}

/// MMSYSERR_NODRIVER, JOYERR_UNPLUGGED.
const NO_DRIVER: u32 = 6;
const UNPLUGGED: u32 = 167;

impl Win32 {
    /// The call of the first timer callback due by now, `(id, 0, user, 0, 0)`, with its next due
    /// time set. A timer more than a period late fires once, as Windows coalesces late periods.
    fn due_timer(&mut self) -> Option<(u32, Vec<u32>)> {
        if self.timers.timers.is_empty() {
            return None;
        }
        let now = self.clock.micros();
        let i = self.timers.timers.iter().position(|t| t.due_us <= now)?;
        let t = &mut self.timers.timers[i];
        let call = (t.callback, vec![t.id, 0, t.user, 0, 0]);
        t.due_us = (t.due_us + t.period_us).max(now);
        if !t.periodic {
            self.timers.timers.remove(i);
        }
        Some(call)
    }

    /// Ends the running host function, entered with `f` and taking `taken` arguments, with
    /// `result`, running first a timer callback that is due.
    pub fn answer_after_timers(&mut self, c: &mut Cpu, f: Frame, taken: u32, result: Option<u32>) {
        match self.due_timer() {
            None => c.ret(f, result, taken),
            Some((callback, args)) => self.call_each(c, f, taken, callback, &[args], result.unwrap_or(0)),
        }
    }
}

pub fn run(w: &mut Win32, c: &mut Cpu, name: &str, f: Frame) -> bool {
    let a = |c: &mut Cpu, n| c.arg(f, n);
    match name {
        "timeBeginPeriod" | "timeEndPeriod" => c.ret(f, Some(0), 1),
        // timeSetEvent(delay, resolution, callback, user, flags); TIME_PERIODIC is 1.
        "timeSetEvent" => {
            let (delay, callback, user, flags) = (a(c, 0), a(c, 2), a(c, 3), a(c, 4));
            w.timers.next += 1;
            let id = w.timers.next;
            let now = w.clock.micros();
            let period_us = u64::from(delay.max(1)) * 1000;
            w.timers.timers.push(Timer { id, period_us, due_us: now + period_us, callback, user, periodic: flags & 1 != 0 });
            c.ret(f, Some(id), 5);
        }
        "timeKillEvent" => {
            let id = a(c, 0);
            w.timers.timers.retain(|t| t.id != id);
            c.ret(f, Some(0), 1);
        }
        "timeGetTime" => {
            let ms = (w.clock.micros() / 1000) as u32;
            w.answer_after_timers(c, f, 0, Some(ms));
        }
        "joyGetDevCapsA" => c.ret(f, Some(UNPLUGGED), 3),
        "joyGetPosEx" | "joyGetPos" => c.ret(f, Some(UNPLUGGED), 2),
        "waveOutGetNumDevs" | "joyGetNumDevs" => c.ret(f, Some(0), 0),
        "mciSendCommandA" => c.ret(f, Some(NO_DRIVER), 4),
        "mciSendStringA" => crate::cd::send(w, c, f),
        // timeGetDevCaps(caps, size): periods of 1 ms to 1000 s.
        "timeGetDevCaps" => {
            let caps = a(c, 0);
            c.set_u32(caps, 1);
            c.set_u32(caps + 4, 1_000_000);
            c.ret(f, Some(0), 2);
        }
        _ => return false,
    }
    true
}
