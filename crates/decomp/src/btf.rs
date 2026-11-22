//! Types from the BTF a Linux kernel carries: the layout of every struct and union, with its
//! members' names, and the prototype of every function, with its parameters' names.
//!
//! The kernel's build makes BTF from its DWARF and keeps it in the image, in the section `.BTF`
//! of a `vmlinux` and between the symbols `__start_BTF` and `__stop_BTF` of a raw `Image`, which
//! recore's loader makes a section of the same name. Functions are listed by name, not address,
//! so a function takes the prototype of the name the image's own symbols give it. The format is
//! the kernel's `Documentation/bpf/btf.rst`, and `data/kernel_protos.py` reads it in Python.
//!
//! The file is not trusted: every offset, count and length is checked against the bytes, a type
//! of a kind this reader does not know stops it, and chains of pointers, arrays and qualifiers
//! are followed a bounded number of steps, so that a loop of them in a crafted file ends.

use std::collections::HashMap;
use std::ops::Range;

use recore::Image;

use crate::types::{Base, Field, Function, Named, Prototype, Type, TypeId, Types, VOID};

const MAGIC: u16 = 0xEB9F;
const HEADER: usize = 24;

/// The kinds of BTF type, by their number.
const INT: u8 = 1;
const PTR: u8 = 2;
const ARRAY: u8 = 3;
const STRUCT: u8 = 4;
const UNION: u8 = 5;
const ENUM: u8 = 6;
const FWD: u8 = 7;
const TYPEDEF: u8 = 8;
const VOLATILE: u8 = 9;
const CONST: u8 = 10;
const RESTRICT: u8 = 11;
const FUNC: u8 = 12;
const FUNC_PROTO: u8 = 13;
const VAR: u8 = 14;
const DATASEC: u8 = 15;
const FLOAT: u8 = 16;
const DECL_TAG: u8 = 17;
const TYPE_TAG: u8 = 18;
const ENUM64: u8 = 19;

/// How far a chain of pointers, arrays and qualifiers is followed. C's own are a few steps long.
const CHAIN: usize = 32;

/// One type of the blob as it lies there: its kind, the rest of its info word, the word that
/// holds its size or the type it refers to, its name, and where the bytes after its header lie.
struct Entry {
    kind: u8,
    vlen: usize,
    kind_flag: bool,
    size_or_type: u32,
    name: u32,
    trailer: Range<usize>,
}

/// A little-endian BTF blob, read into its entries. Id 0 is `void` and has no entry; id `n`
/// is `entries[n - 1]`.
struct Blob<'a> {
    strings: &'a [u8],
    data: &'a [u8],
    entries: Vec<Entry>,
}

/// Why a blob cannot be read.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    NotBtf,
    Truncated,
    /// A kind newer than this reader, whose bytes it cannot step over.
    Kind(u8),
    /// The types run past where the header says they end.
    Misaligned,
}

fn word(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

impl<'a> Blob<'a> {
    fn parse(blob: &'a [u8]) -> Result<Blob<'a>, Refused> {
        let magic = blob.get(..2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
        if magic != Some(MAGIC) || blob.get(2) != Some(&1) {
            return Err(Refused::NotBtf);
        }
        let header = word(blob, 4).ok_or(Refused::Truncated)? as usize;
        let field = |index: usize| word(blob, 8 + 4 * index).map(|value| value as usize).ok_or(Refused::Truncated);
        let (type_off, type_len, str_off, str_len) = (field(0)?, field(1)?, field(2)?, field(3)?);
        if header < HEADER {
            return Err(Refused::NotBtf);
        }
        let section = |off: usize, len: usize| -> Result<&'a [u8], Refused> {
            let start = header.checked_add(off).ok_or(Refused::Truncated)?;
            blob.get(start..start.checked_add(len).ok_or(Refused::Truncated)?).ok_or(Refused::Truncated)
        };
        let (data, strings) = (section(type_off, type_len)?, section(str_off, str_len)?);
        let mut entries = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let read = |offset: usize| word(data, at + offset).ok_or(Refused::Truncated);
            let (name, info, size_or_type) = (read(0)?, read(4)?, read(8)?);
            let kind = ((info >> 24) & 0x1f) as u8;
            let vlen = (info & 0xffff) as usize;
            let (fixed, member) = match kind {
                INT | VAR | DECL_TAG => (4, 0),
                ARRAY => (12, 0),
                STRUCT | UNION | DATASEC | ENUM64 => (0, 12),
                ENUM | FUNC_PROTO => (0, 8),
                PTR | FWD | TYPEDEF | VOLATILE | CONST | RESTRICT | FUNC | FLOAT | TYPE_TAG => (0, 0),
                _ => return Err(Refused::Kind(kind)),
            };
            let start = at + 12;
            let end = start + fixed + member * vlen;
            if end > data.len() {
                return Err(Refused::Misaligned);
            }
            entries.push(Entry { kind, vlen, kind_flag: info >> 31 != 0, size_or_type, name, trailer: start..end });
            at = end;
        }
        Ok(Blob { strings, data, entries })
    }

    /// The string at `offset`, empty where the offset lies outside the strings.
    fn string(&self, offset: u32) -> &'a str {
        let Some(rest) = self.strings.get(offset as usize..) else { return "" };
        let end = rest.iter().position(|&byte| byte == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).unwrap_or("")
    }

    fn entry(&self, id: u32) -> Option<&Entry> {
        self.entries.get((id as usize).checked_sub(1)?)
    }

    /// The `index`th word after the header of `entry`.
    fn trailer(&self, entry: &Entry, index: usize) -> u32 {
        word(self.data, entry.trailer.start + 4 * index).filter(|_| entry.trailer.start + 4 * index < entry.trailer.end).unwrap_or(0)
    }

    /// Whether the chain of pointers, arrays, typedefs and qualifiers from `id` reaches another
    /// kind of type, or `void`, within [`CHAIN`] steps.
    fn ends(&self, mut id: u32) -> bool {
        for _ in 0..CHAIN {
            match self.entry(id) {
                Some(entry) if matches!(entry.kind, PTR | TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG) => id = entry.size_or_type,
                Some(entry) if entry.kind == ARRAY => id = self.trailer(entry, 0),
                _ => return true,
            }
        }
        false
    }

    /// `id` behind any typedefs and qualifiers, followed a bounded number of steps.
    fn stripped(&self, mut id: u32) -> u32 {
        for _ in 0..CHAIN {
            match self.entry(id) {
                Some(entry) if matches!(entry.kind, TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG) => id = entry.size_or_type,
                _ => break,
            }
        }
        id
    }
}

/// Reads the BTF `blob` into a table of types. With `functions`, the address and name of each
/// function, each takes the prototype of the function BTF lists by that name.
pub fn read(blob: &[u8], pointer: u64, functions: impl IntoIterator<Item = (u64, String)>) -> Result<Types, Refused> {
    let blob = Blob::parse(blob)?;
    let mut types = Types::new(pointer);
    // Every id gets its entry in the table first, so that types can refer to ones that follow.
    let mut ids: Vec<TypeId> = Vec::with_capacity(blob.entries.len() + 1);
    ids.push(VOID);
    for entry in &blob.entries {
        let name = blob.string(entry.name);
        let id = match entry.kind {
            INT => {
                let encoding = blob.trailer(entry, 0) >> 24 & 0xf;
                let size = u64::from(entry.size_or_type);
                // pahole marks no `char` as one, so its name says so.
                let base = match encoding {
                    _ if encoding & 4 != 0 => Base::Bool,
                    _ if (encoding & 2 != 0 || name == "char") && size == 1 => Base::Char,
                    _ if encoding & 1 != 0 => Base::Int,
                    _ => Base::Uint,
                };
                types.add(Type::Base { base, size })
            }
            FLOAT => types.add(Type::Base { base: Base::Float, size: u64::from(entry.size_or_type) }),
            STRUCT | UNION => types.named(if entry.kind == UNION { Named::Union } else { Named::Struct }, name, u64::from(entry.size_or_type)).0,
            FWD => types.named(if entry.kind_flag { Named::Union } else { Named::Struct }, name, 0).0,
            ENUM | ENUM64 => {
                let (id, fresh) = types.named(Named::Enum, name, u64::from(entry.size_or_type));
                if fresh {
                    let values = (0..entry.vlen).map(|index| {
                        let value = if entry.kind == ENUM {
                            let value = blob.trailer(entry, 2 * index + 1);
                            if entry.kind_flag { i64::from(value as i32) } else { i64::from(value) }
                        } else {
                            (u64::from(blob.trailer(entry, 3 * index + 2)) << 32 | u64::from(blob.trailer(entry, 3 * index + 1))) as i64
                        };
                        let stride = if entry.kind == ENUM { 2 } else { 3 };
                        (blob.string(blob.trailer(entry, stride * index)).to_string(), value)
                    });
                    types.set_values(id, values.collect());
                }
                id
            }
            // The engine has a `bool` of its own, which a kernel's typedef of `_Bool` is.
            TYPEDEF if types.is_taken(name) => types.add(Type::Alias(VOID)),
            TYPEDEF => types.named(Named::Typedef, name, 0).0,
            PTR => types.add(Type::Pointer(VOID)),
            ARRAY => types.add(Type::Array { element: VOID, count: u64::from(blob.trailer(entry, 2)) }),
            VOLATILE | CONST | RESTRICT | TYPE_TAG => types.add(Type::Alias(VOID)),
            FUNC_PROTO => types.add(Type::Function(Prototype { returns: VOID, params: Vec::new(), variadic: false, convention: None })),
            _ => VOID,
        };
        ids.push(id);
    }
    let id = |btf: u32| ids.get(btf as usize).copied().unwrap_or(VOID);
    // Then what each refers to. A chain that never ends is `void`.
    let mut functions_by_name: HashMap<&str, TypeId> = HashMap::new();
    for (index, entry) in blob.entries.iter().enumerate() {
        let own = ids[index + 1];
        match entry.kind {
            TYPEDEF if !blob.ends(index as u32 + 1) && matches!(types.types[own as usize], Type::Typedef { .. }) => types.set_target(own, VOID),
            PTR | TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG | ARRAY if !blob.ends(index as u32 + 1) => types.types[own as usize] = Type::Alias(VOID),
            PTR => types.types[own as usize] = Type::Pointer(id(entry.size_or_type)),
            VOLATILE | CONST | RESTRICT | TYPE_TAG => types.types[own as usize] = Type::Alias(id(entry.size_or_type)),
            TYPEDEF if matches!(types.types[own as usize], Type::Alias(_)) => types.types[own as usize] = Type::Alias(id(entry.size_or_type)),
            TYPEDEF => types.set_target(own, id(entry.size_or_type)),
            ARRAY => {
                if let Type::Array { element, .. } = &mut types.types[own as usize] {
                    *element = id(blob.trailer(entry, 0));
                }
            }
            STRUCT | UNION => {
                // A struct defined twice by one name and size is read once.
                if !matches!(&types.types[own as usize], Type::Composite { fields, .. } if fields.is_empty()) {
                    continue;
                }
                let fields = (0..entry.vlen).map(|index| member(&blob, entry, index, &id)).collect();
                types.set_fields(own, fields);
            }
            FUNC_PROTO => {
                let mut prototype = Prototype { returns: id(entry.size_or_type), params: Vec::with_capacity(entry.vlen), variadic: false, convention: None };
                for index in 0..entry.vlen {
                    let (name, kind) = (blob.trailer(entry, 2 * index), blob.trailer(entry, 2 * index + 1));
                    // `...` is a last parameter of no type.
                    if kind == 0 && index + 1 == entry.vlen {
                        prototype.variadic = true;
                    } else {
                        prototype.params.push((blob.string(name).to_string(), id(kind)));
                    }
                }
                types.types[own as usize] = Type::Function(prototype);
            }
            FUNC if blob.entry(entry.size_or_type).is_some_and(|proto| proto.kind == FUNC_PROTO) => {
                functions_by_name.insert(blob.string(entry.name), id(entry.size_or_type));
            }
            _ => {}
        }
    }
    for (addr, name) in functions {
        // Clang's CFI before kCFI keeps the body of a function whose address is taken as
        // `<name>.cfi`, and the name for its entry in a jump table.
        let found = functions_by_name.get(name.as_str()).or_else(|| functions_by_name.get(name.strip_suffix(".cfi")?));
        if let Some(&prototype) = found {
            types.functions.push(Function { addr, name, prototype });
        }
    }
    types.finish();
    Ok(types)
}

/// The `index`th member of the struct or union `entry`, its type mapped by `id`.
fn member(blob: &Blob, entry: &Entry, index: usize, id: &impl Fn(u32) -> TypeId) -> Field {
    let (name, kind, offset) = (blob.trailer(entry, 3 * index), blob.trailer(entry, 3 * index + 1), blob.trailer(entry, 3 * index + 2));
    // With the kind flag, the offset word holds a bitfield's width above its first bit. Without
    // it, a bitfield is an integer type whose own encoding gives its width and first bit.
    let (mut first, mut width) = if entry.kind_flag { (u64::from(offset & 0xff_ffff), offset >> 24) } else { (u64::from(offset), 0) };
    let underlying = blob.stripped(kind);
    if !entry.kind_flag
        && let Some(int) = blob.entry(underlying).filter(|int| int.kind == INT)
    {
        let encoding = blob.trailer(int, 0);
        let bits = encoding & 0xff;
        if bits != 8 * int.size_or_type || encoding >> 16 & 0xff != 0 {
            (first, width) = (first + u64::from(encoding >> 16 & 0xff), bits);
        }
    }
    let name = match blob.string(name) {
        // An unnamed struct or union inside this one, named as DWARF's reader names it.
        "" => format!("anon_{:x}", first / 8),
        name => name.to_string(),
    };
    let bitfield = width != 0 || first % 8 != 0;
    // A bitfield of a typedef, as `u8 flag : 1` is, takes the integer the typedef stands for,
    // which is what the engine takes a bitfield of.
    let kind = if bitfield { id(underlying) } else { id(kind) };
    let bits = bitfield.then(|| ((first % 8) as u32, width.max(1)));
    Field { name, offset: first / 8, kind, bits }
}

/// The types the BTF of the kernel `image` describes, with the prototype of each function its
/// symbols name. `None` for an image that is not a kernel's or has no BTF, and why its BTF could
/// not be read goes to stderr.
pub fn types(image: &Image) -> Option<Types> {
    if !image.kernel_image {
        return None;
    }
    let section = image.sections.iter().find(|section| section.name == ".BTF")?;
    let functions = image.symbol_names.iter().filter(|(addr, _)| image.is_code(**addr)).map(|(addr, name)| (*addr, name.clone()));
    read(&section.data, image.machine.pointer_size(), functions).map_err(|refused| eprintln!("BTF at {:#x}: {refused:?}", section.addr)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a BTF blob of `types`, each its 12-byte header words and the words after, and of
    /// `strings`, which start with the empty string.
    fn blob(types: &[&[u32]], strings: &str) -> Vec<u8> {
        let words: Vec<u8> = types.iter().flat_map(|words| words.iter()).flat_map(|word| word.to_le_bytes()).collect();
        let strings = format!("\0{strings}");
        let mut out = Vec::new();
        out.extend(MAGIC.to_le_bytes());
        out.extend([1, 0]);
        for value in [HEADER, 0, words.len(), words.len(), strings.len()] {
            out.extend((value as u32).to_le_bytes());
        }
        out.extend(words);
        out.extend(strings.as_bytes());
        out
    }

    fn info(kind: u8, vlen: u32) -> u32 {
        u32::from(kind) << 24 | vlen
    }

    /// `int`, `struct file { int f_flags; unsigned int f_mode : 3; struct file *next; }`, and
    /// `int file_open(struct file *f, ...)`.
    fn file() -> Vec<u8> {
        // Names: 1 int, 5 file, 10 f_flags, 18 f_mode, 25 next, 30 file_open, 40 f.
        let strings = "int\0file\0f_flags\0f_mode\0next\0file_open\0f\0";
        blob(
            &[
                &[1, info(INT, 0), 4, 1 << 24 | 32],
                &[5, info(STRUCT, 3) | 1 << 31, 16, 10, 1, 0, 18, 1, 3 << 24 | 32, 25, 3, 64],
                &[0, info(PTR, 0), 2],
                &[0, info(FUNC_PROTO, 2), 1, 40, 3, 0, 0],
                &[30, info(FUNC, 1), 4],
            ],
            strings,
        )
    }

    #[test]
    fn a_function_takes_the_prototype_of_its_name_with_its_structs_members() {
        let types = read(&file(), 8, [(0x1000, "file_open".to_string()), (0x2000, "other".to_string())]).unwrap();
        assert_eq!(types.functions.len(), 1);
        let Type::Function(prototype) = types.get(types.functions[0].prototype) else { panic!("no prototype") };
        assert!(prototype.variadic);
        assert_eq!(prototype.params.len(), 1);
        assert_eq!(prototype.params[0].0, "f");
        let Type::Pointer(file) = types.get(prototype.params[0].1) else { panic!("not a pointer") };
        let Type::Composite { name, size, fields, .. } = types.get(*file) else { panic!("not a struct") };
        assert_eq!((name.as_str(), *size), ("file", 16));
        let members: Vec<(&str, u64, Option<(u32, u32)>)> = fields.iter().map(|field| (field.name.as_str(), field.offset, field.bits)).collect();
        assert_eq!(members, [("f_flags", 0, None), ("f_mode", 4, Some((0, 3))), ("next", 8, None)]);
    }

    #[test]
    fn a_loop_of_pointers_ends_in_void() {
        // Two pointers to each other, and a const of the first.
        let looped = blob(&[&[0, info(PTR, 0), 2], &[0, info(PTR, 0), 1], &[0, info(CONST, 0), 1]], "");
        let types = read(&looped, 8, []).unwrap();
        assert!(types.types.iter().all(|kind| !matches!(kind, Type::Pointer(_))));
    }

    #[test]
    fn a_blob_that_does_not_hold_together_is_refused() {
        let whole = file();
        assert_eq!(read(&whole[..whole.len() - 50], 8, []).err(), Some(Refused::Truncated));
        let mut newer = file();
        newer[HEADER + 4 + 3] = 20;
        assert_eq!(read(&newer, 8, []).err(), Some(Refused::Kind(20)));
        // A struct whose members run past the end of the types.
        let mut long = file();
        long[HEADER + 16 + 4] = 9;
        assert_eq!(read(&long, 8, []).err(), Some(Refused::Misaligned));
        let mut huge = file();
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(read(&huge, 8, []).err(), Some(Refused::Truncated));
    }

    #[test]
    fn a_name_past_the_strings_is_empty() {
        let types = read(&blob(&[&[1 << 30, info(STRUCT, 0), 4]], ""), 8, []).unwrap();
        assert!(matches!(types.types.last(), Some(Type::Composite { name, .. }) if name.starts_with("anon_struct")));
    }
}
