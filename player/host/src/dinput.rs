//! DirectInput 5: the game reads the mouse and the keyboard as devices. Their state is the
//! host's input state in `Win32::user`.

use recore_machine::Cpu;

use crate::{
    Win32,
    com::{Args, Iface},
};

const OK: u32 = 0;
/// GUID_SysMouse's first dword; GUID_SysKeyboard's is 0x6f1d2b61.
const SYS_MOUSE: u32 = 0x6f1d_2b60;
/// A device's object id: the game asks each device for IDirectInputDevice2A, a new object
/// with the same id, and reads it through that, so the id and not the address names the device.
const MOUSE: u32 = 1;
const KEYBOARD: u32 = 2;

pub struct Input {
    /// Mouse movement and buttons since the game last read them.
    pub moved: (i32, i32, i32),
    pub buttons: [bool; 3],
    /// DirectInput scan codes held, 0x80 for down.
    pub scans: [u8; 256],
    /// Key presses and releases the game has not read from the keyboard's buffer: scan code and
    /// whether it went down.
    pub events: std::collections::VecDeque<(u8, bool)>,
    /// The sequence number of the next event read.
    pub sequence: u32,
}

impl Default for Input {
    fn default() -> Input {
        Input { moved: (0, 0, 0), buttons: [false; 3], scans: [0; 256], events: Default::default(), sequence: 0 }
    }
}

pub fn method(w: &mut Win32, c: &mut Cpu, iface: Iface, name: &str, a: &Args) -> Option<u32> {
    let v = match (iface, name) {
        (Iface::DirectInput, "CreateDevice") => {
            let (guid, out) = (a.get(c, 0), a.get(c, 1));
            let id = if c.u32_at(guid) == SYS_MOUSE { MOUSE } else { KEYBOARD };
            let device = w.new_object(c, Iface::InputDevice, id);
            c.set_u32(out, device);
            OK
        }
        (Iface::DirectInput, "EnumDevices") => OK,
        // While the game holds the mouse, as it acquires it exclusively to read it, the window
        // locks the pointer and reports only its motion, as DirectInput does.
        (Iface::InputDevice, "Acquire" | "Unacquire") => {
            if a.id == MOUSE {
                let on = name == "Acquire";
                eprintln!("host: the game {} the mouse", if on { "holds" } else { "releases" });
                w.input.moved = (0, 0, 0);
                if let Some(link) = &w.link {
                    link.capture(on);
                }
            }
            OK
        }
        (Iface::InputDevice, "SetDataFormat" | "SetCooperativeLevel" | "SetProperty" | "Poll" | "SetEventNotification") => OK,
        // DIMOUSESTATE: dx, dy, dz, four buttons; the keyboard: 256 key bytes.
        (Iface::InputDevice, "GetDeviceState") => {
            w.sync_input();
            let (size, out) = (a.get(c, 0), a.get(c, 1));
            c.mem.poke(out, &vec![0; size as usize]);
            if a.id == MOUSE {
                let (dx, dy, dz) = std::mem::take(&mut w.input.moved);
                for (i, v) in [dx, dy, dz].into_iter().enumerate() {
                    c.set_u32(out + 4 * i as u32, v as u32);
                }
                for (i, &down) in w.input.buttons.iter().enumerate() {
                    c.st(out + 12 + i as u32, 1, if down { 0x80 } else { 0 });
                }
            } else {
                let scans = w.input.scans;
                c.mem.poke(out, &scans[..size.min(256) as usize]);
            }
            OK
        }
        // DIDEVCAPS after its size: attached, the device type, axes, buttons and no POVs.
        (Iface::InputDevice, "GetCapabilities") => {
            let caps = a.get(c, 0);
            let (kind, axes, buttons) = if a.id == MOUSE { (0x112, 3, 3) } else { (0x413, 0, 128) };
            for (i, v) in [1, kind, axes, buttons, 0].into_iter().enumerate() {
                c.set_u32(caps + 4 + 4 * i as u32, v);
            }
            OK
        }
        // The mouse and the keyboard have no force feedback: DIERR_UNSUPPORTED.
        (Iface::InputDevice, "GetForceFeedbackState" | "SendForceFeedbackCommand" | "CreateEffect") => 0x8000_4001,
        (Iface::InputDevice, "EnumEffects" | "EnumCreatedEffectObjects" | "Escape") => OK,
        // GetDeviceData(size, DIDEVICEOBJECTDATA[], &count, flags): the keyboard's buffered key
        // events, each the scan code, 0x80 or 0 for down or up, a time stamp and a sequence
        // number, as many as `count` says; DIGDD_PEEK (1) leaves them in the buffer. The mouse
        // has none.
        (Iface::InputDevice, "GetDeviceData") => {
            w.sync_input();
            let (size, out, count, flags) = (a.get(c, 0), a.get(c, 1), a.get(c, 2), a.get(c, 3));
            let wanted = c.u32_at(count) as usize;
            let events: Vec<(u8, bool)> = if a.id == KEYBOARD { w.input.events.iter().take(wanted).copied().collect() } else { Vec::new() };
            if out != 0 {
                for (i, &(scan, down)) in events.iter().enumerate() {
                    let at = out + i as u32 * size.max(16);
                    let ms = (w.clock.micros() / 1000) as u32;
                    for (k, v) in [u32::from(scan), if down { 0x80 } else { 0 }, ms, w.input.sequence + i as u32].into_iter().enumerate() {
                        c.set_u32(at + 4 * k as u32, v);
                    }
                }
            }
            if flags & 1 == 0 {
                w.input.events.drain(..events.len());
                w.input.sequence += events.len() as u32;
            }
            c.set_u32(count, events.len() as u32);
            OK
        }
        _ => return None,
    };
    Some(v)
}
