//! ole32, advapi32, and what a game can run without: window chrome, dialogs, the console, the
//! DirectSound functions dsound.rs does not have, a light gun's driver, and the Miles functions
//! miles.rs does not have, which answer 0.

use recore_machine::{Cpu, Frame};

use crate::{Win32, com::Iface};

const ERROR_FILE_NOT_FOUND: u32 = 2;

/// Imports the game runs without, as (name, value answered, stdcall arguments): window chrome,
/// dialogs, the console and the aux mixer, which has no devices.
const STUBS: &[(&str, u32, u32)] = &[
    ("auxGetNumDevs", 0, 0),
    ("auxGetDevCapsA", 6, 3),
    ("auxGetVolume", 6, 2),
    ("auxSetVolume", 6, 2),
    ("CheckDlgButton", 1, 3),
    ("ClipCursor", 1, 1),
    ("CreateSolidBrush", 0x7200_0001, 1),
    ("EndDialog", 1, 2),
    ("GetActiveWindow", 0x10001, 0),
    ("GetConsoleMode", 0, 2),
    ("GetDlgItem", 0x7300_0001, 2),
    ("GetMenu", 0, 1),
    ("GetParent", 0, 1),
    ("GetSysColor", 0, 1),
    ("GetSystemPaletteEntries", 0, 4),
    ("GlobalAddAtomA", 0xc001, 1),
    ("GlobalDeleteAtom", 0, 1),
    ("GlobalFindAtomA", 0, 1),
    ("InvalidateRect", 1, 3),
    ("IsDlgButtonChecked", 0, 2),
    ("IsMenu", 0, 1),
    ("KillTimer", 1, 2),
    ("LoadMenuA", 0x7400_0001, 2),
    ("MapWindowPoints", 0, 4),
    ("MoveWindow", 1, 6),
    ("ReadConsoleInputA", 0, 4),
    ("SendDlgItemMessageA", 0, 5),
    ("SendMessageA", 0, 4),
    ("SetConsoleMode", 0, 2),
    ("SetTimer", 1, 4),
    ("WriteConsoleA", 0, 5),
];

pub fn run(w: &mut Win32, c: &mut Cpu, dll: &str, name: &str, f: Frame) -> bool {
    let a = |c: &mut Cpu, n| c.arg(f, n);
    match (dll, name) {
        (_, "CoInitializeEx") => c.ret(f, Some(0), 2),
        (_, "CoInitialize") => c.ret(f, Some(0), 1),
        (_, "RegQueryInfoKeyA") => c.ret(f, Some(ERROR_FILE_NOT_FOUND), 12),
        // ERROR_NO_MORE_ITEMS.
        (_, "RegEnumKeyExA") => c.ret(f, Some(259), 8),
        (_, "RegEnumValueA") => c.ret(f, Some(259), 8),
        (_, "CoUninitialize") => c.ret(f, None, 0),
        // CLSID_DirectDraw makes the host's DirectDraw, as the interface asked for. CLSID_DirectMusic
        // makes an object with only IUnknown's methods, which the DirectX version check makes and
        // releases. Others, such as DirectShow's filter graph that plays the movies, are not
        // registered, and the game goes on without them.
        (_, "CoCreateInstance") => {
            let (clsid, iid, out) = (a(c, 0), a(c, 3), a(c, 4));
            let (class, wanted) = (c.u32_at(clsid), c.u32_at(iid));
            let object = match class {
                0xd7b7_0ee0 => [(0x6c14_db80, Iface::DirectDraw), (0xb3a6_f3e0, Iface::DirectDraw2), (0x9c59_509a, Iface::DirectDraw4)]
                    .iter()
                    .find(|(first, _)| *first == wanted)
                    .map(|&(_, iface)| w.new_object(c, iface, 0)),
                0x636b_9f10 => Some(w.new_object(c, Iface::Unknown, 0)),
                _ => None,
            };
            if object.is_none() {
                eprintln!("host: CoCreateInstance of a class starting {class:#010x} fails");
            }
            c.set_u32(out, object.unwrap_or(0));
            c.ret(f, Some(if object.is_some() { 0 } else { 0x8004_0154 }), 5);
        }
        // The registry is empty, so the game takes its defaults; keys it creates are accepted.
        (_, "RegOpenKeyA") => c.ret(f, Some(ERROR_FILE_NOT_FOUND), 3),
        (_, "RegOpenKeyExA") => c.ret(f, Some(ERROR_FILE_NOT_FOUND), 5),
        (_, "RegCreateKeyExA") => {
            let key = a(c, 7);
            c.set_u32(key, 0x7000_0001);
            c.ret(f, Some(0), 9);
        }
        (_, "RegQueryValueExA") => c.ret(f, Some(ERROR_FILE_NOT_FOUND), 6),
        (_, "RegSetValueExA") => c.ret(f, Some(0), 6),
        (_, "RegCloseKey") => c.ret(f, Some(0), 1),
        (_, "GetOpenFileNameA") => c.ret(f, Some(0), 1),
        // The DirectSound functions lib.rs does not make an object for, DirectSoundCreate8 among
        // them, fail with DSERR_NODRIVER, and the game goes on without them.
        (d, _) if d.eq_ignore_ascii_case("dsound.dll") => c.ret(f, Some(0x8878_0078), 3),
        // gamebios.dll, an arcade port's light gun driver: no gun is attached. Its functions take
        // their arguments in registers.
        (d, _) if d.eq_ignore_ascii_case("gamebios.dll") => c.ret(f, Some(0), 0),
        _ if STUBS.iter().any(|(n, ..)| *n == name) => {
            let &(_, value, args) = STUBS.iter().find(|(n, ..)| *n == name).unwrap();
            if w.trace {
                eprintln!("host: {name} stubbed");
            }
            c.ret(f, Some(value), args);
        }
        // The rest of Miles: every function returns 0 and takes off the bytes its name says.
        ("mss32.dll", _) => {
            let bytes: u32 = name.rsplit_once('@').and_then(|(_, n)| n.parse().ok()).unwrap_or(0);
            if w.trace {
                eprintln!("host: {name} answers 0");
            }
            c.ret(f, Some(0), bytes / 4);
        }
        _ => return false,
    }
    true
}
