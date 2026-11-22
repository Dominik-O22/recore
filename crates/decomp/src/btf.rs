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
        // `<name>.cfi`, and gives its entry in a jump table, which only jumps to the body and is
        // what pointers to the function hold, `<name>.cfi_jt` or the name itself.
        let plain = name.strip_suffix(".cfi").or_else(|| name.strip_suffix(".cfi_jt"));
        let found = functions_by_name.get(name.as_str()).or_else(|| functions_by_name.get(plain?));
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
        if u64::from(bits) != 8 * u64::from(int.size_or_type) || encoding >> 16 & 0xff != 0 {
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

/// A struct whose members point to functions, as [`objects`] gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub name: String,
    pub size: u64,
    /// Each member that is a pointer, through members that are structs, by offset: its path,
    /// such as `driver.pm`, and whether it points to a function.
    pub pointers: Vec<(u64, String, bool)>,
}

/// The objects of a kernel image that hold functions and the struct each is, sorted by address:
/// see [`objects`].
#[derive(Debug, Default)]
pub struct Objects {
    pub layouts: Vec<Layout>,
    /// The address of each object, its name and its index in `layouts`.
    pub objects: Vec<(u64, String, usize)>,
}

impl Objects {
    /// The object that holds `addr`, with its layout.
    pub fn at(&self, addr: u64) -> Option<(u64, &str, &Layout)> {
        let index = self.objects.partition_point(|object| object.0 <= addr).checked_sub(1)?;
        let (start, name, layout) = &self.objects[index];
        let layout = &self.layouts[*layout];
        (addr < start + layout.size).then_some((*start, name.as_str(), layout))
    }
}

/// How far into an object [`objects`] reads.
const OBJECT: u64 = 4096;
/// How deep [`objects`] follows members that are structs, and how many pointers of one struct
/// it takes, which keeps a crafted file's structs of thousands of structs from costing more.
const NESTED: u32 = 4;
const POINTERS: usize = 4096;

/// A prototype as the types it takes and returns, without parameter names: two that are alike
/// are one function type.
type Signature = Vec<TypeId>;

fn signature(types: &Types, id: TypeId) -> Option<Signature> {
    let Type::Function(prototype) = types.get(id) else { return None };
    let mut out = vec![types.resolve(prototype.returns), TypeId::from(prototype.variadic)];
    out.extend(prototype.params.iter().map(|param| types.resolve(param.1)));
    Some(out)
}

/// The type `id` stands for behind typedefs and qualifiers.
fn underlying(types: &Types, mut id: TypeId) -> TypeId {
    for _ in 0..CHAIN {
        match types.get(id) {
            Type::Typedef { target, .. } => id = *target,
            _ => break,
        }
    }
    types.resolve(id)
}

/// Each member of the struct `id` that is a pointer, at `base` and below `path`, with the
/// signature of the function it points to if it points to one.
fn pointers(types: &Types, id: TypeId, base: u64, path: &str, depth: u32, out: &mut Vec<(u64, String, Option<Signature>)>) {
    let Type::Composite { union: false, fields, .. } = types.get(id) else { return };
    for field in fields.iter().filter(|field| field.bits.is_none()) {
        if out.len() >= POINTERS {
            return;
        }
        let path = if path.is_empty() { field.name.clone() } else { format!("{path}.{}", field.name) };
        let offset = base.saturating_add(field.offset);
        let kind = underlying(types, field.kind);
        match types.get(kind) {
            Type::Pointer(target) => out.push((offset, path, signature(types, underlying(types, *target)))),
            Type::Composite { union: false, .. } if depth > 0 => pointers(types, kind, offset, &path, depth - 1, out),
            _ => {}
        }
    }
}

/// The objects the symbols of the kernel `image` name that hold functions, each with the struct
/// it is. An object is that struct where the struct is the only one in `types` whose members
/// point to functions of exactly the prototypes, but for parameter names, of the functions the
/// object holds at those offsets, and that has a member that points to a function wherever the
/// object holds one. An object that more than one struct fits, or that holds no function whose
/// prototype `types` has, is left out: a kernel's BTF types none of its variables but its
/// per-CPU ones, so the functions in an object are what says what it is.
pub fn objects(image: &Image, types: &Types) -> Objects {
    let prototypes: HashMap<u64, Signature> = types.functions.iter().filter_map(|function| Some((function.addr, signature(types, function.prototype)?))).collect();
    // Each struct with members that point to functions, and by the offset and signature of
    // each such member, the structs that have it.
    let mut members: HashMap<TypeId, Vec<(u64, String, Option<Signature>)>> = HashMap::new();
    let mut by_member: HashMap<(u64, &Signature), Vec<TypeId>> = HashMap::new();
    for id in 0..types.types.len() as TypeId {
        // A struct of one pointer is any word that holds the address of such a function.
        if !matches!(&types.types[id as usize], Type::Composite { union: false, size, .. } if *size > types.pointer) {
            continue;
        }
        let mut found = Vec::new();
        pointers(types, id, 0, "", NESTED, &mut found);
        if found.iter().any(|member| member.2.is_some()) {
            members.insert(id, found);
        }
    }
    for (id, found) in &members {
        for (offset, _, signature) in found {
            if let Some(signature) = signature {
                by_member.entry((*offset, signature)).or_default().push(*id);
            }
        }
    }
    let mut symbols: Vec<u64> = image.symbol_names.keys().copied().collect();
    symbols.sort_unstable();
    let mut objects = Objects::default();
    let mut layouts: HashMap<TypeId, usize> = HashMap::new();
    let size = image.machine.pointer_size();
    for (index, &addr) in symbols.iter().enumerate() {
        let Some(section) = image.section_at(addr).filter(|section| !section.executable) else { continue };
        let end = symbols.get(index + 1).map_or(u64::MAX, |&next| next).min(section.addr.saturating_add(section.data.len() as u64)).min(addr.saturating_add(OBJECT));
        // Each slot that holds the address of code, with the signature of the function there.
        let held: Vec<(u64, Option<&Signature>)> = (0..)
            .map_while(|slot| addr.checked_add(slot * size).filter(|&at| at.checked_add(size).is_some_and(|stop| stop <= end)))
            .filter_map(|at| {
                let bytes = image.bytes_from(at)?.get(..size as usize)?;
                let value = bytes.iter().rev().fold(0u64, |value, &byte| value << 8 | u64::from(byte));
                image.is_code(value).then(|| (at - addr, prototypes.get(&value)))
            })
            .collect();
        let Some(&(offset, Some(first))) = held.iter().find(|slot| slot.1.is_some()) else { continue };
        // Every struct the object could be: one whose members take each function it holds, and
        // that it has room for. A struct that holds another at its start fits where that one
        // does, and two that fit say nothing.
        let fits = |id: &&TypeId| {
            let found = &members[*id];
            types.size(**id) <= end - addr && held.iter().all(|&(offset, signature)| found.iter().any(|member| member.0 == offset && member.2.is_some() && signature.is_none_or(|signature| member.2.as_ref() == Some(signature))))
        };
        let mut fitting = by_member.get(&(offset, first)).into_iter().flatten().filter(fits);
        let (Some(&kind), None) = (fitting.next(), fitting.next()) else { continue };
        // Nor does one that leaves room for more than padding, as a word or a struct of
        // another type that holds the function in a `void *` would.
        if end - addr - types.size(kind) >= size {
            continue;
        }
        let layout = *layouts.entry(kind).or_insert_with(|| {
            let Type::Composite { name, size, .. } = types.get(kind) else { unreachable!("only structs have members") };
            let pointers = members[&kind].iter().map(|(offset, path, signature)| (*offset, path.clone(), signature.is_some())).collect();
            objects.layouts.push(Layout { name: name.clone(), size: *size, pointers });
            objects.layouts.len() - 1
        });
        objects.objects.push((addr, image.symbol_names[&addr].clone(), layout));
    }
    objects
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
        let members: Vec<_> = fields.iter().map(|field| (field.name.as_str(), field.offset, field.bits)).collect();
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

    /// `struct ops { void (*open)(struct ops *o); void (*close)(struct ops *o); long count; }`,
    /// the functions `ops_open` and `ops_close` of that prototype, and with `twice` a second
    /// struct `ops2` of the same members.
    fn ops(twice: bool) -> Vec<u8> {
        let strings = "long\0ops\0open\0close\0count\0o\0ops_open\0ops_close\0ops2\0";
        let members = [10, 4, 0, 15, 4, 64, 21, 1, 128];
        let mut types: Vec<Vec<u32>> = vec![
            vec![1, info(INT, 0), 8, 1 << 24 | 64],
            [&[6, info(STRUCT, 3), 24][..], &members].concat(),
            vec![0, info(PTR, 0), 2],
            vec![0, info(PTR, 0), 5],
            vec![0, info(FUNC_PROTO, 1), 0, 27, 3],
            vec![29, info(FUNC, 1), 5],
            vec![38, info(FUNC, 1), 5],
        ];
        if twice {
            types.push([&[48, info(STRUCT, 3), 24][..], &members].concat());
        }
        blob(&types.iter().map(Vec::as_slice).collect::<Vec<_>>(), strings)
    }

    /// An image whose code holds `ops_open` and `ops_close`, and whose data holds `table`, an
    /// `ops` of the two, and after it `word`, which holds `ops_open` alone.
    fn image() -> Image {
        use recore::image::{Format, Machine, Section};
        let data: Vec<u8> = [0x1000u64, 0x1008, 3, 0x1000].iter().flat_map(|word| word.to_le_bytes()).collect();
        let sections = vec![
            Section { name: ".text".into(), addr: 0x1000, data: vec![0; 16], file_offset: None, executable: true, writable: false },
            Section { name: ".rodata".into(), addr: 0x2000, data, file_offset: None, executable: false, writable: false },
        ];
        let mut image = Image::bare("ops".into(), Format::Raw, Machine::Aarch64, 0x1000, sections);
        for (addr, name) in [(0x1000, "ops_open"), (0x1008, "ops_close"), (0x2000, "table"), (0x2018, "word")] {
            image.symbol_names.insert(addr, name.into());
        }
        image
    }

    fn functions() -> [(u64, String); 2] {
        [(0x1000, "ops_open".into()), (0x1008, "ops_close".into())]
    }

    #[test]
    fn an_object_is_the_one_struct_whose_members_take_its_functions() {
        let objects = objects(&image(), &read(&ops(false), 8, functions()).unwrap());
        assert_eq!(objects.objects.iter().map(|object| (object.0, object.1.as_str())).collect::<Vec<_>>(), [(0x2000, "table")]);
        let (start, name, layout) = objects.at(0x2008).unwrap();
        assert_eq!((start, name, layout.name.as_str(), layout.size), (0x2000, "table", "ops", 24));
        assert_eq!(layout.pointers, [(0, "open".to_string(), true), (8, "close".to_string(), true)]);
        // `word` holds a function too, and has no room for an `ops`.
        assert!(objects.at(0x2018).is_none());
    }

    #[test]
    fn an_object_two_structs_fit_is_left_out() {
        assert!(objects(&image(), &read(&ops(true), 8, functions()).unwrap()).objects.is_empty());
    }

    #[test]
    fn a_name_past_the_strings_is_empty() {
        let types = read(&blob(&[&[1 << 30, info(STRUCT, 0), 4]], ""), 8, []).unwrap();
        assert!(matches!(types.types.last(), Some(Type::Composite { name, .. }) if name.starts_with("anon_struct")));
    }
}
