//! Keys as Windows names them: the virtual key for window messages and GetKeyboardState, and the
//! DirectInput scan code (DIK_*) for keyboard device state. A key is found by its position's name,
//! as the DOM's `KeyboardEvent.code` gives it and winit's `KeyCode` spells its variants.

/// Each key's position, virtual key and scan code.
const KEYS: &[(&str, u8, u8)] = &[
    ("KeyA", b'A', 0x1e),
    ("KeyB", b'B', 0x30),
    ("KeyC", b'C', 0x2e),
    ("KeyD", b'D', 0x20),
    ("KeyE", b'E', 0x12),
    ("KeyF", b'F', 0x21),
    ("KeyG", b'G', 0x22),
    ("KeyH", b'H', 0x23),
    ("KeyI", b'I', 0x17),
    ("KeyJ", b'J', 0x24),
    ("KeyK", b'K', 0x25),
    ("KeyL", b'L', 0x26),
    ("KeyM", b'M', 0x32),
    ("KeyN", b'N', 0x31),
    ("KeyO", b'O', 0x18),
    ("KeyP", b'P', 0x19),
    ("KeyQ", b'Q', 0x10),
    ("KeyR", b'R', 0x13),
    ("KeyS", b'S', 0x1f),
    ("KeyT", b'T', 0x14),
    ("KeyU", b'U', 0x16),
    ("KeyV", b'V', 0x2f),
    ("KeyW", b'W', 0x11),
    ("KeyX", b'X', 0x2d),
    ("KeyY", b'Y', 0x15),
    ("KeyZ", b'Z', 0x2c),
    ("Digit1", b'1', 0x02),
    ("Digit2", b'2', 0x03),
    ("Digit3", b'3', 0x04),
    ("Digit4", b'4', 0x05),
    ("Digit5", b'5', 0x06),
    ("Digit6", b'6', 0x07),
    ("Digit7", b'7', 0x08),
    ("Digit8", b'8', 0x09),
    ("Digit9", b'9', 0x0a),
    ("Digit0", b'0', 0x0b),
    ("F1", 0x70, 0x3b),
    ("F2", 0x71, 0x3c),
    ("F3", 0x72, 0x3d),
    ("F4", 0x73, 0x3e),
    ("F5", 0x74, 0x3f),
    ("F6", 0x75, 0x40),
    ("F7", 0x76, 0x41),
    ("F8", 0x77, 0x42),
    ("F9", 0x78, 0x43),
    ("F10", 0x79, 0x44),
    ("F11", 0x7a, 0x57),
    ("F12", 0x7b, 0x58),
    ("Escape", 0x1b, 0x01),
    ("Enter", 0x0d, 0x1c),
    ("NumpadEnter", 0x0d, 0x1c),
    ("Space", 0x20, 0x39),
    ("Tab", 0x09, 0x0f),
    ("Backspace", 0x08, 0x0e),
    ("ShiftLeft", 0x10, 0x2a),
    ("ShiftRight", 0x10, 0x36),
    ("ControlLeft", 0x11, 0x1d),
    ("ControlRight", 0x11, 0x9d),
    ("AltLeft", 0x12, 0x38),
    ("AltRight", 0x12, 0xb8),
    ("ArrowLeft", 0x25, 0xcb),
    ("ArrowUp", 0x26, 0xc8),
    ("ArrowRight", 0x27, 0xcd),
    ("ArrowDown", 0x28, 0xd0),
    ("Insert", 0x2d, 0xd2),
    ("Delete", 0x2e, 0xd3),
    ("Home", 0x24, 0xc7),
    ("End", 0x23, 0xcf),
    ("PageUp", 0x21, 0xc9),
    ("PageDown", 0x22, 0xd1),
    ("Minus", 0xbd, 0x0c),
    ("Equal", 0xbb, 0x0d),
    ("Comma", 0xbc, 0x33),
    ("Period", 0xbe, 0x34),
    ("Slash", 0xbf, 0x35),
];

/// The codes of the key at position `code`.
pub fn by_code(code: &str) -> Option<(u8, u8)> {
    KEYS.iter().find(|k| k.0 == code).map(|k| (k.1, k.2))
}

/// The position of a key by a short name: a letter or digit, escape, enter, space, tab,
/// backspace, left, right, up, down, or f1 to f12.
pub fn code_by_name(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    let capitalized = || name.get(..1).map(|first| first.to_ascii_uppercase() + &name[1..]);
    let code = match name.as_str() {
        "left" | "right" | "up" | "down" => format!("Arrow{}", capitalized()?),
        n if n.len() == 1 && n.as_bytes()[0].is_ascii_alphabetic() => format!("Key{}", n.to_ascii_uppercase()),
        n if n.len() == 1 && n.as_bytes()[0].is_ascii_digit() => format!("Digit{n}"),
        n if n.starts_with('f') && n[1..].parse::<u8>().is_ok() => n.to_ascii_uppercase(),
        _ => capitalized()?,
    };
    KEYS.iter().find(|k| k.0 == code).map(|k| k.0)
}

/// The codes of a key by a short name, as [`code_by_name`] reads it.
pub fn by_name(name: &str) -> Option<(u8, u8)> {
    by_code(code_by_name(name)?)
}
