//! Prototypes from the kCFI hashes of a Linux kernel module.
//!
//! Clang's kCFI puts a hash of a function's type before every function whose address may be
//! taken, as a word an AArch64 file marks as data. The hash cannot be reversed, but it can be
//! looked up: `data/kcfi.protos`, which `data/kernel_protos.py --kcfi` makes from two Android
//! kernels' BTF, holds the hash of every function type those kernels define and the prototype
//! it names. A module's function whose hash is there takes that prototype, as a function with
//! debug information takes the one DWARF gives it.

use std::collections::HashMap;

use recore::Image;

use crate::types::{Base, Function, Named, Prototype, Type, TypeId, Types, VOID};

/// `<hash> <spelling> <prototype>` a line, sorted by hash and then spelling.
const TABLE: &str = include_str!("../data/kcfi.protos");

/// How the kernel a module was built for spells the integers of the types it hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spelling {
    /// By width and sign, `u3i32` for `int`: a kernel built with
    /// `CONFIG_CFI_ICALL_NORMALIZE_INTEGERS`.
    Normalized,
    /// As C names them.
    Plain,
}

impl Spelling {
    /// The letter the table writes it with.
    fn letter(self) -> u8 {
        match self {
            Spelling::Normalized => b'n',
            Spelling::Plain => b'p',
        }
    }
}

/// AArch64's `nop`. A function patchable for ftrace has some between its hash and its entry.
const NOP: [u8; 4] = 0xD503_201Fu32.to_le_bytes();

/// The hash before each function of a kernel module, by the function's address: a word that a
/// `$d` mapping symbol marks on its own. Empty for any other image.
pub fn hashes(image: &Image) -> Vec<(u64, u32)> {
    if !image.kernel_module {
        return Vec::new();
    }
    // Where a module has no symbol for a function, the loader finds its start from ftrace's
    // patch list, or from a pointer to it, which `-fpatchable-function-entry=4,2` puts two of
    // the `nop`s before.
    let starts = image.symbol_extents.iter().map(|extent| extent.0).chain(image.relative_targets.iter().map(|target| target.1));
    let mut entries: Vec<u64> = starts.collect();
    entries.sort_unstable();
    let data = image.marked_data.iter().filter(|(start, end)| end - start == 4);
    data.filter_map(|&(start, end)| {
        let hash = u32::from_le_bytes(image.bytes_from(start)?.get(..4)?.try_into().ok()?);
        let nops = image.bytes_from(end).map_or(0, |code| code.as_chunks::<4>().0.iter().take_while(|&&word| word == NOP).count());
        // The first start from the end of the hash on with only nops before it, or without one
        // the address the hash ends at.
        let symbol = entries.get(entries.partition_point(|&entry| entry < end)).filter(|&&entry| entry <= end + 4 * nops as u64);
        Some((symbol.copied().unwrap_or(end), hash))
    })
    .collect()
}

/// The prototype the table gives `hash` in `spelling`, found by bisecting the text, so that a
/// module pays for the hashes it has and not for an index of all of them.
fn lookup(hash: u32, spelling: Spelling) -> Option<&'static str> {
    let wanted = (hash, spelling.letter());
    let bytes = TABLE.as_bytes();
    let (mut low, mut high) = (0, bytes.len());
    while low < high {
        let middle = (low + high) / 2;
        let start = bytes[..middle].iter().rposition(|&byte| byte == b'\n').map_or(0, |at| at + 1);
        let end = bytes[start..].iter().position(|&byte| byte == b'\n').map_or(bytes.len(), |at| start + at);
        let line = &TABLE[start..end];
        let found = (u32::from_str_radix(line.get(..8)?, 16).ok()?, *line.as_bytes().get(9)?);
        match found.cmp(&wanted) {
            std::cmp::Ordering::Less => low = end + 1,
            std::cmp::Ordering::Greater => high = start,
            std::cmp::Ordering::Equal => return line.get(11..),
        }
    }
    None
}

/// The prototypes a kernel module's kCFI hashes name, in the spelling that finds more of them,
/// and that spelling. `None` for an image that is no kernel module, and for a module none of
/// whose hashes is found.
pub fn types(image: &Image) -> Option<(Spelling, Types)> {
    let hashes = hashes(image);
    let found = |spelling| -> Vec<(u64, &'static str)> { hashes.iter().filter_map(|&(addr, hash)| Some((addr, lookup(hash, spelling)?))).collect() };
    let (normalized, plain) = (found(Spelling::Normalized), found(Spelling::Plain));
    let (spelling, found) = if normalized.len() >= plain.len() { (Spelling::Normalized, normalized) } else { (Spelling::Plain, plain) };
    if found.is_empty() {
        return None;
    }
    // The table holds 64-bit kernels' types.
    let mut reader = Reader { types: Types::new(8), spelled: HashMap::new() };
    for (addr, text) in found {
        if let Some(prototype) = reader.prototype(text) {
            reader.types.functions.push(Function { addr, name: String::new(), prototype });
        }
    }
    let mut types = reader.types;
    types.finish();
    Some((spelling, types))
}

/// Builds the types the table's prototypes spell, each spelling once.
struct Reader {
    types: Types,
    spelled: HashMap<&'static str, TypeId>,
}

impl Reader {
    /// `<return> (<params>)`, with `(void)` for none and `...` last for a variadic function.
    fn prototype(&mut self, text: &'static str) -> Option<TypeId> {
        let (returns, params) = text.strip_suffix(')')?.split_once(" (")?;
        let mut prototype = Prototype { returns: self.spelling(returns)?, params: Vec::new(), variadic: false, convention: None };
        for param in params.split(", ").filter(|&param| param != "void") {
            if param == "..." {
                prototype.variadic = true;
            } else {
                prototype.params.push((String::new(), self.spelling(param)?));
            }
        }
        Some(self.types.add(Type::Function(prototype)))
    }

    /// `void`, a number such as `uint4`, `char` or `bool`, or `struct name` or `union name`,
    /// with a `*` after it for each pointer. A struct or union is only ever pointed to, so its
    /// name is all the type needs.
    fn spelling(&mut self, text: &'static str) -> Option<TypeId> {
        if let Some(&id) = self.spelled.get(text) {
            return Some(id);
        }
        let id = match (text.strip_suffix('*'), text.split_once(' ')) {
            (Some(pointee), _) => {
                let target = self.spelling(pointee.trim_end())?;
                self.types.add(Type::Pointer(target))
            }
            (None, Some(("struct", name))) => self.types.named(Named::Struct, name, 0).0,
            (None, Some(("union", name))) => self.types.named(Named::Union, name, 0).0,
            _ if text == "void" => VOID,
            _ => {
                let (base, size) = number(text)?;
                self.types.add(Type::Base { base, size })
            }
        };
        self.spelled.insert(text, id);
        Some(id)
    }
}

/// What the number the table spells `text` is, and its size in bytes.
fn number(text: &str) -> Option<(Base, u64)> {
    match text {
        "bool" => return Some((Base::Bool, 1)),
        "char" => return Some((Base::Char, 1)),
        _ => {}
    }
    let digits = text.find(|c: char| c.is_ascii_digit())?;
    let base = match &text[..digits] {
        "int" => Base::Int,
        "uint" => Base::Uint,
        "float" => Base::Float,
        _ => return None,
    };
    Some((base, text[digits..].parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// can-dev's `can_fd_dlc2len` returns a length, and DWARF says `u8 (u8)`. Normalized, its
    /// hash is the one `_Bool`, `char` and `unsigned char` share, so the table may say no more.
    #[test]
    fn a_normalized_prototype_names_only_an_integers_width_and_sign() {
        assert_eq!(lookup(0x7e25_2a92, Spelling::Normalized), Some("uint1 (uint1)"));
        let guessed = TABLE.lines().filter(|line| line.as_bytes()[9] == b'n' && line[11..].split([' ', '(', ')', ',', '*']).any(|word| word == "bool" || word == "char"));
        assert_eq!(guessed.count(), 0);
    }
}
