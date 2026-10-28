//! Host COM objects: DirectDraw, DirectInput and DirectSound objects the game holds as pointers.
//! Each lives in game memory as its vtable pointer and an id; the vtable's entries are host
//! addresses that name the interface and the method, so a call through it lands in
//! [`Win32::com`]. `QueryInterface` gives another object with the same id, so every version of
//! an interface reaches the same state.

use recore_machine::{Cpu, Frame, HOST};

use crate::{Win32, com_tables::*, ddraw, dinput, dsound};

/// Methods of interface `i` are at `METHODS + i * 0x1000 + 4 * method`.
pub const METHODS: u32 = HOST + 0x0100_0000;

const E_NOINTERFACE: u32 = 0x8000_4002;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Iface {
    DirectDraw,
    DirectDraw2,
    DirectDraw4,
    Surface,
    Surface3,
    Surface4,
    Palette,
    Clipper,
    DirectInput,
    InputDevice,
    DirectSound,
    SoundBuffer,
    /// An object with only IUnknown's methods.
    Unknown,
}

const ALL: [Iface; 13] = [
    Iface::DirectDraw,
    Iface::DirectDraw2,
    Iface::DirectDraw4,
    Iface::Surface,
    Iface::Surface3,
    Iface::Surface4,
    Iface::Palette,
    Iface::Clipper,
    Iface::DirectInput,
    Iface::InputDevice,
    Iface::DirectSound,
    Iface::SoundBuffer,
    Iface::Unknown,
];

impl Iface {
    pub fn table(self) -> &'static [(&'static str, u32)] {
        match self {
            Iface::DirectDraw => IDIRECT_DRAW,
            Iface::DirectDraw2 => IDIRECT_DRAW2,
            Iface::DirectDraw4 => IDIRECT_DRAW4,
            Iface::Surface => IDIRECT_DRAW_SURFACE,
            Iface::Surface3 => IDIRECT_DRAW_SURFACE3,
            Iface::Surface4 => IDIRECT_DRAW_SURFACE4,
            Iface::Palette => IDIRECT_DRAW_PALETTE,
            Iface::Clipper => IDIRECT_DRAW_CLIPPER,
            Iface::DirectInput => IDIRECT_INPUTA,
            Iface::InputDevice => IDIRECT_INPUT_DEVICE2A,
            Iface::DirectSound => IDIRECT_SOUND,
            Iface::SoundBuffer => IDIRECT_SOUND_BUFFER,
            Iface::Unknown => &[("QueryInterface", 2), ("AddRef", 0), ("Release", 0)],
        }
    }

    fn index(self) -> u32 {
        ALL.iter().position(|&i| i == self).expect("listed") as u32
    }

    /// The interface an IID names, by the IID's first dword, among those that reach the same
    /// object as `self`.
    fn query(self, iid: u32) -> Option<Iface> {
        let family = match self {
            Iface::DirectDraw | Iface::DirectDraw2 | Iface::DirectDraw4 => [(0x6c14_db80, Iface::DirectDraw), (0xb3a6_f3e0, Iface::DirectDraw2), (0x9c59_509a, Iface::DirectDraw4)],
            Iface::Surface | Iface::Surface3 | Iface::Surface4 => [(0x6c14_db81, Iface::Surface), (0xda04_4e00, Iface::Surface3), (0x0b2b_8630, Iface::Surface4)],
            // IID_IDirectInputDevice2A is a superset of IDirectInputDeviceA's vtable.
            Iface::InputDevice => [(0x5944_e680, Iface::InputDevice), (0x5944_e682, Iface::InputDevice), (0, Iface::InputDevice)],
            _ => return None,
        };
        family.iter().find(|(first, _)| *first == iid && iid != 0).map(|(_, i)| *i)
    }
}

/// A method call's arguments after `this`, the id of the object it was called on, and the
/// stack arguments the method takes with `this`.
pub struct Args {
    pub frame: Frame,
    pub id: u32,
    pub taken: u32,
}

impl Args {
    pub fn get(&self, c: &mut Cpu, n: u32) -> u32 {
        c.arg(self.frame, n + 1)
    }
}

impl Win32 {
    /// A new object of interface `iface` in game memory, for the state `id` names.
    pub fn new_object(&mut self, c: &mut Cpu, iface: Iface, id: u32) -> u32 {
        let vtable = match self.vtables.get(&iface) {
            Some(&v) => v,
            None => {
                let n = iface.table().len() as u32;
                let v = self.alloc(4 * n);
                for m in 0..n {
                    c.mem.poke(v + 4 * m, &(METHODS + iface.index() * 0x1000 + 4 * m).to_le_bytes());
                }
                self.vtables.insert(iface, v);
                v
            }
        };
        let object = self.alloc(8);
        c.mem.poke(object, &vtable.to_le_bytes());
        c.mem.poke(object + 4, &id.to_le_bytes());
        object
    }

    pub fn com(&mut self, c: &mut Cpu, addr: u32, frame: Frame) {
        let (iface, method) = (ALL[((addr - METHODS) >> 12) as usize], ((addr - METHODS) & 0xfff) / 4);
        let (name, nargs) = iface.table()[method as usize];
        let this = c.arg(frame, 0);
        let args = Args { frame, id: c.u32_at(this + 4), taken: nargs + 1 };
        if self.trace {
            eprintln!("host: {iface:?}::{name} from {:#x}", c.u32_at(c.reg(recore_machine::regs::ESP)));
        }
        if self.backtrace.iter().any(|b| b == name) {
            eprintln!("host: {iface:?}::{name} called from {}", crate::game_stack(self.game.names));
        }
        let value = match name {
            // No reference counts: Release says the object is gone, as the game loops on
            // Release until it answers 0.
            "AddRef" => Some(1),
            "Release" => Some(0),
            "QueryInterface" => {
                let (iid, out) = (args.get(c, 0), args.get(c, 1));
                let first = c.u32_at(iid);
                match iface.query(first) {
                    Some(other) => {
                        let object = self.new_object(c, other, args.id);
                        c.set_u32(out, object);
                        Some(0)
                    }
                    None => {
                        eprintln!("host: {iface:?}::QueryInterface for an IID starting {first:#010x} answers E_NOINTERFACE");
                        c.set_u32(out, 0);
                        Some(E_NOINTERFACE)
                    }
                }
            }
            _ => match iface {
                Iface::DirectInput | Iface::InputDevice => dinput::method(self, c, iface, name, &args),
                Iface::DirectSound | Iface::SoundBuffer => dsound::method(self, c, iface, name, &args),
                _ => ddraw::method(self, c, iface, name, &args),
            },
        };
        match value {
            // A method that hands control to game code (callback.rs) has set its own return.
            Some(_) if self.next.is_some() => {}
            Some(v) => c.ret(frame, Some(v), nargs + 1),
            None => panic!("{iface:?}::{name} is not implemented"),
        }
    }
}
