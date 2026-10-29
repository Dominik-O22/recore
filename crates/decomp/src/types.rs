//! Data types from debug information, in the one form the DWARF and the PDB reader both fill
//! and the engine takes.
//!
//! A reader builds a [`Types`]: a table of types that refer to each other by index, the
//! prototypes of functions by address, and the types of globals. [`Writer`] turns the parts of
//! it a session needs into the engine's own XML, which says where every field lies. The C
//! parser behind [`crate::Session::declare`] would lay structs out again by its own rules and
//! cannot spell a C++ name.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSection};
use recore::Image;
use recore::image::Format;

/// An index into [`Types::types`].
pub type TypeId = u32;

/// What a number is, which with its size picks the engine's name for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Int,
    Uint,
    Float,
    Bool,
    /// A character: `char`, `wchar2` or `wchar4` by size.
    Char,
    /// Bytes the code shows the size of and nothing more: `undefinedN`.
    Unknown,
}

/// One member of a struct or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    /// In bytes from the start; for a bitfield, of the byte its lowest bit is in.
    pub offset: u64,
    pub kind: TypeId,
    /// For a bitfield: its lowest bit within the byte at `offset`, and its width in bits.
    pub bits: Option<(u32, u32)>,
}

/// A function's return type and parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prototype {
    pub returns: TypeId,
    pub params: Vec<(String, TypeId)>,
    pub variadic: bool,
    /// The engine's name for the calling convention, such as `__cdecl`, where the debug
    /// information states one that the target does not imply.
    pub convention: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Void,
    Base { base: Base, size: u64 },
    Pointer(TypeId),
    Array { element: TypeId, count: u64 },
    /// A struct, or with `union` a union. One of size 0 was only ever declared.
    Composite { name: String, union: bool, size: u64, fields: Vec<Field> },
    Enum { name: String, size: u64, values: Vec<(String, i64)> },
    Typedef { name: String, target: TypeId },
    Function(Prototype),
    /// The same type as another entry.
    Alias(TypeId),
}

/// The kinds of type that have a name of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    Struct,
    Union,
    Enum,
    Typedef,
}

/// The prototype of the function at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub addr: u64,
    pub name: String,
    /// A [`Type::Function`].
    pub prototype: TypeId,
}

/// A global variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    pub addr: u64,
    pub name: String,
    pub kind: TypeId,
}

/// Everything a reader found in one binary's debug information.
#[derive(Debug)]
pub struct Types {
    pub types: Vec<Type>,
    /// At most one per address.
    pub functions: Vec<Function>,
    pub globals: Vec<Global>,
    /// Whether code reaches each global by its own address, as an IL2CPP build's code reaches
    /// its usage slots, so that the addresses a function's code refers to name every global it
    /// needs. Code compiled from C or Rust also reaches globals through pointers the engine
    /// reads from memory.
    pub globals_by_reference: bool,
    /// Bytes in a pointer.
    pub pointer: u64,
    /// The named types so far, by name, with their kind and size. The engine knows a type by
    /// its name alone, so each name is given out once.
    names: HashMap<String, (TypeId, Named, u64)>,
}

/// The entry every table starts with.
pub const VOID: TypeId = 0;

/// The size recorded for a name the engine has from the start, which no type may take.
const TAKEN: u64 = u64::MAX;

impl Types {
    pub fn new(pointer: u64) -> Types {
        // The names the engine starts out with are taken: a struct called `code` gets another.
        let sized = ["int", "uint", "float", "undefined", "wchar"].iter().flat_map(|base| [1, 2, 4, 8, 10, 16].map(|size| format!("{base}{size}")));
        let taken = ["void", "bool", "char", "code", "undefined"].map(String::from).into_iter().chain(sized);
        let names = taken.map(|name| (name, (VOID, Named::Typedef, TAKEN))).collect();
        Types { types: vec![Type::Void], functions: Vec::new(), globals: Vec::new(), globals_by_reference: false, pointer, names }
    }

    /// Whether the engine has a type called `name` from the start, such as `uint4`.
    pub fn is_taken(&self, name: &str) -> bool {
        self.names.get(name).is_some_and(|known| known.2 == TAKEN)
    }

    /// Adds a type that has no name of its own.
    pub fn add(&mut self, kind: Type) -> TypeId {
        self.types.push(kind);
        (self.types.len() - 1) as TypeId
    }

    /// The entry for the named type `name` of `size` bytes, and whether the caller is to fill
    /// it in with [`Types::set`]: it is new, or was only declared so far. Debug information
    /// repeats a type in every unit that uses it, and this is where the repeats meet. An empty
    /// `name` is an anonymous type, which is always new. A `size` of 0 is a declaration, which
    /// matches a definition of any size; two definitions of different sizes are two types, and
    /// the later one gets a name of its own.
    pub fn named(&mut self, kind: Named, name: &str, size: u64) -> (TypeId, bool) {
        let fresh = |types: &mut Types, name: String| {
            let id = types.add(match kind {
                Named::Struct | Named::Union => Type::Composite { name: name.clone(), union: kind == Named::Union, size, fields: Vec::new() },
                Named::Enum => Type::Enum { name: name.clone(), size, values: Vec::new() },
                Named::Typedef => Type::Typedef { name: name.clone(), target: VOID },
            });
            types.names.insert(name, (id, kind, size));
            id
        };
        if name.is_empty() {
            let prefix = match kind {
                Named::Struct => "anon_struct",
                Named::Union => "anon_union",
                Named::Enum => "anon_enum",
                Named::Typedef => "anon_typedef",
            };
            return (fresh(self, format!("{prefix}_{}", self.types.len())), true);
        }
        let mut candidate = name.to_string();
        for attempt in 2.. {
            match self.names.get_mut(&candidate) {
                None => return (fresh(self, candidate), true),
                Some(&mut (id, found, known)) if found == kind && kind == Named::Typedef && known != TAKEN => return (id, false),
                Some((id, found, known)) if *found == kind && (*known == size || size == 0) => return (*id, false),
                Some((id, found, known)) if *found == kind && *known == 0 => {
                    *known = size;
                    let id = *id;
                    if let Type::Composite { size: declared, .. } | Type::Enum { size: declared, .. } = &mut self.types[id as usize] {
                        *declared = size;
                    }
                    return (id, true);
                }
                Some(_) => candidate = format!("{name}_{attempt}"),
            }
        }
        unreachable!("the loop returns")
    }

    /// Fills in the fields of a struct or union [`Types::named`] handed out.
    pub fn set_fields(&mut self, id: TypeId, members: Vec<Field>) {
        if let Type::Composite { fields, .. } = &mut self.types[id as usize] {
            *fields = members;
        }
    }

    /// Fills in the values of an enum [`Types::named`] handed out.
    pub fn set_values(&mut self, id: TypeId, names: Vec<(String, i64)>) {
        if let Type::Enum { values, .. } = &mut self.types[id as usize] {
            *values = names;
        }
    }

    /// Says what a typedef [`Types::named`] handed out stands for.
    pub fn set_target(&mut self, id: TypeId, to: TypeId) {
        if let Type::Typedef { target, .. } = &mut self.types[id as usize] {
            *target = to;
        }
    }

    /// The entry a chain of aliases starting at `id` ends at. Such a chain is short, and a
    /// loop of them would be a reader's mistake.
    pub fn resolve(&self, mut id: TypeId) -> TypeId {
        for _ in 0..16 {
            match &self.types[id as usize] {
                Type::Alias(next) => id = *next,
                _ => return id,
            }
        }
        VOID
    }

    /// The type at `id`, behind any aliases.
    pub fn get(&self, id: TypeId) -> &Type {
        &self.types[self.resolve(id) as usize]
    }

    /// The size of a type in bytes; 0 for `void`, a function, and a type only declared.
    pub fn size(&self, id: TypeId) -> u64 {
        self.size_within(id, 32)
    }

    fn size_within(&self, id: TypeId, depth: u32) -> u64 {
        match self.get(id) {
            _ if depth == 0 => 0,
            Type::Void | Type::Function(_) | Type::Alias(_) => 0,
            Type::Base { size, .. } | Type::Composite { size, .. } | Type::Enum { size, .. } => *size,
            Type::Pointer(_) => self.pointer,
            Type::Array { element, count } => count.saturating_mul(self.size_within(*element, depth - 1)),
            Type::Typedef { target, .. } => self.size_within(*target, depth - 1),
        }
    }

    /// Whether the type `id` is a struct or union with no data in it: no members, or only
    /// members that are hollow themselves.
    pub fn hollow(&self, id: TypeId, depth: u32) -> bool {
        match self.get(id) {
            Type::Typedef { target, .. } if depth > 0 => self.hollow(*target, depth - 1),
            Type::Composite { size, fields, .. } if depth > 0 => *size > 0 && fields.iter().all(|field| self.hollow(field.kind, depth - 1)),
            _ => false,
        }
    }

    /// Sorts the functions and globals by address and keeps one of each address: the first in
    /// the order the reader found them.
    pub fn finish(&mut self) {
        self.functions.sort_by_key(|function| function.addr);
        self.functions.dedup_by_key(|function| function.addr);
        self.globals.sort_by_key(|global| global.addr);
        self.globals.dedup_by_key(|global| global.addr);
    }
}

/// The name of the field that holds the base class `name`: `super_` and the class without its
/// namespaces and template arguments, which keeps an access through several bases readable.
pub fn base_field(name: &str) -> String {
    let plain = name.split('<').next().unwrap_or(name);
    format!("super_{}", plain.rsplit("::").next().unwrap_or(plain))
}

/// Text as the value of an XML attribute.
fn escaped(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains(['&', '<', '>', '"']) && !text.chars().any(char::is_control) {
        return text.into();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.into()
}


/// The engine's name for a number of `size` bytes.
fn base_name(base: Base, size: u64) -> String {
    match (base, size) {
        (Base::Bool, 1) => "bool".into(),
        (Base::Char, 1) => "char".into(),
        (Base::Char, 2 | 4) => format!("wchar{size}"),
        (Base::Float, _) => format!("float{size}"),
        (Base::Int, _) => format!("int{size}"),
        (Base::Unknown, _) => format!("undefined{size}"),
        (Base::Uint | Base::Bool | Base::Char, _) => format!("uint{size}"),
    }
}

/// Writes what a session is to know as the XML [`crate::Session::add_types`] takes. Every type
/// is written once, the first time something refers to it, so a writer can be asked again and
/// again for what the next functions need.
pub struct Writer<'a> {
    types: &'a Types,
    /// Per type: its definition has been written.
    written: Vec<bool>,
    /// Structs and unions whose fields are still to be written.
    pending: Vec<TypeId>,
    /// The function types written, by name, each with the entry it was written for. Two that
    /// read the same are one type.
    function_types: HashMap<String, TypeId>,
    /// The number the engine knows the first entry by: see [`Writer::ident`].
    first_id: u64,
    /// Types the engine holds already, by the number it knows them by: see [`Writer::known`].
    known: HashMap<TypeId, u64>,
    out: String,
}

impl<'a> Writer<'a> {
    pub fn new(types: &'a Types) -> Writer<'a> {
        Writer::numbered_from(types, 1)
    }

    /// A writer whose types the engine knows by numbers from `first_id` on, to keep them apart
    /// from those of another table given to the same session.
    pub fn numbered_from(types: &'a Types, first_id: u64) -> Writer<'a> {
        Writer { types, written: vec![false; types.types.len()], pending: Vec::new(), function_types: HashMap::new(), first_id, known: HashMap::new(), out: String::new() }
    }

    /// Says that the engine holds the named type at `id` already, by the number `engine_id`:
    /// it is referred to and never written.
    pub fn known(&mut self, id: TypeId, engine_id: u64) {
        self.written[id as usize] = true;
        self.known.insert(id, engine_id);
    }

    /// The number the engine knows the named type at `id` by, next to its name. Left to itself
    /// the engine makes one up from the name, and its hash gives two of the long, similar names
    /// of C++ templates the same number often enough to confuse its bookkeeping for unions.
    pub fn ident(&self, id: TypeId) -> u64 {
        self.known.get(&id).copied().unwrap_or(self.first_id + u64::from(id))
    }

    /// An array's elements if nothing says how many there are, since the engine has no array
    /// without a size; any other type as it is.
    fn sized(&self, id: TypeId) -> TypeId {
        let id = self.types.resolve(id);
        match &self.types.types[id as usize] {
            Type::Array { element, .. } if self.types.size(id) == 0 => self.sized(*element),
            _ => id,
        }
    }

    /// Writes the definitions of the named types that `id` is built from and that are not
    /// written yet. Structs and unions are only announced here, with their size, and get their
    /// fields in [`Writer::drain`]: that is what lets types refer to each other in a circle.
    fn define(&mut self, id: TypeId) {
        let id = self.sized(id);
        let types = self.types;
        match &types.types[id as usize] {
            Type::Void | Type::Alias(_) => {}
            Type::Base { base, size } => {
                // The engine starts out with numbers of 1, 2, 4 and 8 bytes, and the floats.
                let core = matches!((base, size), (Base::Float, 4 | 8 | 10 | 16) | (Base::Int | Base::Uint | Base::Bool | Base::Char | Base::Unknown, 1 | 2 | 4 | 8));
                if !core && !std::mem::replace(&mut self.written[id as usize], true) {
                    let meta = match base {
                        Base::Int => "int",
                        Base::Float => "float",
                        Base::Unknown => "unknown",
                        _ => "uint",
                    };
                    let _ = writeln!(self.out, r#"<type name="{}" metatype="{meta}" size="{size}"/>"#, base_name(*base, *size));
                }
            }
            Type::Pointer(target) => self.define(*target),
            Type::Array { element, .. } => self.define(*element),
            Type::Composite { name, union, size, .. } => {
                if !std::mem::replace(&mut self.written[id as usize], true) {
                    let meta = if *union { "union" } else { "struct" };
                    let _ = writeln!(self.out, r#"<type name="{}" id="{}" metatype="{meta}" size="{}" incomplete="true"/>"#, escaped(name), self.ident(id), (*size).max(1));
                    self.pending.push(id);
                }
            }
            Type::Enum { name, size, values } => {
                if !std::mem::replace(&mut self.written[id as usize], true) {
                    let _ = writeln!(self.out, r#"<type name="{}" id="{}" metatype="enum_uint" size="{}">"#, escaped(name), self.ident(id), (*size).clamp(1, 8));
                    for (value_name, value) in values {
                        let _ = writeln!(self.out, r#"<val name="{}" value="{value}"/>"#, escaped(value_name));
                    }
                    self.out.push_str("</type>\n");
                }
            }
            Type::Typedef { name, target } => {
                if !std::mem::replace(&mut self.written[id as usize], true) {
                    self.define(*target);
                    let _ = write!(self.out, r#"<def name="{}" id="{}">"#, escaped(name), self.ident(id));
                    self.reference(*target);
                    self.out.push_str("</def>\n");
                }
            }
            Type::Function(prototype) => {
                if !std::mem::replace(&mut self.written[id as usize], true) {
                    self.define_prototype(prototype);
                    let name = self.function_type(prototype);
                    if !self.function_types.contains_key(&name) {
                        let _ = write!(self.out, r#"<functype name="{name}" id="{}""#, self.ident(id));
                        self.function_types.insert(name, id);
                        self.prototype(prototype);
                        self.out.push_str("</functype>\n");
                    }
                }
            }
        }
    }

    /// A word for the type `id` in the name of a function type.
    fn word(&self, id: TypeId, depth: u32) -> String {
        let id = self.sized(id);
        match &self.types.types[id as usize] {
            _ if depth == 0 => "type".into(),
            Type::Void | Type::Alias(_) => "void".into(),
            Type::Base { base, size } => base_name(*base, *size),
            Type::Pointer(target) => format!("{}_ptr", self.word(*target, depth - 1)),
            Type::Array { element, .. } => format!("{}_array", self.word(*element, depth - 1)),
            Type::Composite { name, .. } | Type::Enum { name, .. } | Type::Typedef { name, .. } => name.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect(),
            Type::Function(_) => "func".into(),
        }
    }

    /// The name a function type goes by, which spells out what it returns and takes, as
    /// Ghidra's do: `_func_int4_shape_ptr_int4`.
    fn function_type(&self, prototype: &Prototype) -> String {
        let mut name = format!("_func_{}", self.word(prototype.returns, 4));
        for (_, kind) in &prototype.params {
            name.extend(["_", &self.word(*kind, 4)]);
        }
        if prototype.variadic {
            name.push_str("_varargs");
        }
        name
    }

    fn define_prototype(&mut self, prototype: &Prototype) {
        self.define(prototype.returns);
        for (_, kind) in &prototype.params {
            self.define(*kind);
        }
    }

    /// Writes a use of the type `id`, which [`Writer::define`] has been called for.
    fn reference(&mut self, id: TypeId) {
        let id = self.sized(id);
        let types = self.types;
        match &types.types[id as usize] {
            Type::Void | Type::Alias(_) => self.out.push_str("<void/>"),
            Type::Base { base, size } => {
                let _ = write!(self.out, r#"<typeref name="{}"/>"#, base_name(*base, *size));
            }
            Type::Pointer(target) => {
                let _ = write!(self.out, r#"<type metatype="ptr" size="{}" wordsize="1">"#, types.pointer);
                self.reference(*target);
                self.out.push_str("</type>");
            }
            Type::Array { element, count } => {
                let _ = write!(self.out, r#"<type metatype="array" size="{}" arraysize="{count}">"#, types.size(id));
                self.reference(*element);
                self.out.push_str("</type>");
            }
            Type::Composite { name, .. } | Type::Enum { name, .. } | Type::Typedef { name, .. } => {
                let _ = write!(self.out, r#"<typeref name="{}" id="{}"/>"#, escaped(name), self.ident(id));
            }
            Type::Function(prototype) => {
                let name = self.function_type(prototype);
                let first = self.function_types.get(&name).copied().unwrap_or(id);
                let _ = write!(self.out, r#"<typeref name="{name}" id="{}"/>"#, self.ident(first));
            }
        }
    }

    /// Writes the rest of a prototype's opening tag and its `<p>` children.
    fn prototype(&mut self, prototype: &Prototype) {
        if prototype.variadic {
            self.out.push_str(r#" dotdotdot="true""#);
        }
        if let Some(convention) = prototype.convention {
            let _ = write!(self.out, r#" model="{convention}""#);
        }
        self.out.push_str("><p>");
        self.reference(prototype.returns);
        self.out.push_str("</p>");
        // A parameter of no size, as Rust's zero-sized types are, is not passed.
        for (index, (name, kind)) in prototype.params.iter().enumerate().filter(|(_, param)| self.types.size(param.1) > 0) {
            // Two parameters of one name would be one variable to the engine.
            let unique = !name.is_empty() && !prototype.params[..index].iter().any(|earlier| earlier.0 == *name);
            let name = if unique { escaped(name) } else { format!("param_{}", index + 1).into() };
            let _ = write!(self.out, r#"<p name="{name}">"#);
            self.reference(*kind);
            self.out.push_str("</p>");
        }
    }

    /// Writes the fields of every struct and union announced so far, and of the ones those
    /// announce in turn.
    fn drain(&mut self) {
        let types = self.types;
        while let Some(id) = self.pending.pop() {
            let Type::Composite { name, union, size, fields } = &types.types[id as usize] else { continue };
            // Declared and never defined: the announcement is all there is to say.
            if *size == 0 {
                continue;
            }
            // The engine wants fields in order and rejects a struct with one that does not fit;
            // a field that overlaps the one before it, as an empty base class does, is left out.
            // A member with nothing in it, as an empty base class is, holds no data, and the
            // engine faults on a struct that is all one such member.
            let mut kept: Vec<&Field> = fields.iter().filter(|field| !field.name.is_empty() && !types.hollow(field.kind, 8)).collect();
            if !*union {
                kept.sort_by_key(|field| (field.offset, field.bits.map_or(0, |bits| bits.0)));
            }
            // Where the last whole field ends, and the last bit of a bitfield.
            let (mut end, mut bit_end) = (0, 0);
            kept.retain(|field| {
                let bytes = match field.bits {
                    Some((first, count)) => u64::from(first + count).div_ceil(8),
                    None => types.size(field.kind),
                };
                let start = if *union { 0 } else { field.offset };
                let first_bit = 8 * start + u64::from(field.bits.map_or(0, |bits| bits.0));
                let fits = bytes > 0 && start + bytes <= *size && (*union || (start >= end && first_bit >= bit_end));
                let numeric = field.bits.is_none() || matches!(types.get(self.sized(field.kind)), Type::Base { base: Base::Int | Base::Uint | Base::Bool, .. } | Type::Enum { .. });
                if !(fits && numeric) {
                    return false;
                }
                match field.bits {
                    Some((_, count)) => bit_end = first_bit + u64::from(count),
                    None if !*union => (end, bit_end) = (start + bytes, 8 * (start + bytes)),
                    None => {}
                }
                true
            });
            for field in &kept {
                self.define(field.kind);
            }
            let meta = if *union { "union" } else { "struct" };
            let _ = writeln!(self.out, r#"<type name="{}" id="{}" metatype="{meta}" size="{size}">"#, escaped(name), self.ident(id));
            for (index, field) in kept.iter().enumerate() {
                let offset = if *union { 0 } else { field.offset };
                match field.bits {
                    Some((first, count)) => {
                        let _ = write!(self.out, r#"<bitfield name="{}" id="{index}" offset="{offset}" size="{count}" first="{first}">"#, escaped(&field.name));
                        self.reference(field.kind);
                        self.out.push_str("</bitfield>\n");
                    }
                    None => {
                        let _ = write!(self.out, r#"<field name="{}" offset="{offset}">"#, escaped(&field.name));
                        self.reference(field.kind);
                        self.out.push_str("</field>\n");
                    }
                }
            }
            self.out.push_str("</type>\n");
        }
    }

    /// Writes the named type at `id` and the types it is built from.
    pub fn named(&mut self, id: TypeId) {
        self.define(id);
        self.drain();
    }

    /// Writes the prototype of `function` and the types it is built from.
    pub fn function(&mut self, function: &Function) {
        let types = self.types;
        let Type::Function(prototype) = types.get(function.prototype) else { return };
        self.define_prototype(prototype);
        self.drain();
        let _ = write!(self.out, r#"<function addr="{:x}""#, function.addr);
        self.prototype(prototype);
        self.out.push_str("</function>\n");
    }

    /// Writes the global variable `global` and the types it is built from.
    pub fn global(&mut self, global: &Global) {
        if self.types.size(global.kind) == 0 {
            return;
        }
        self.define(global.kind);
        self.drain();
        let _ = write!(self.out, r#"<global addr="{:x}" name="{}">"#, global.addr, escaped(&global.name));
        self.reference(global.kind);
        self.out.push_str("</global>\n");
    }

    /// What was written since the last call, as one document; `None` if that is nothing.
    pub fn take(&mut self) -> Option<String> {
        if self.out.is_empty() {
            return None;
        }
        let body = std::mem::take(&mut self.out);
        Some(format!("<debug>\n{body}</debug>\n"))
    }
}

/// Hands a session the types of one binary's debug information as they come to be needed: a
/// function's prototype when it or a caller of it is decompiled, a type when something names
/// it. A large program's debug information describes tens of thousands of types, and giving
/// the engine all of them would make every session wait for what most never look at.
pub struct Importer<'a> {
    types: &'a Types,
    writer: Writer<'a>,
    /// Functions that only jump to another one, as an incremental linker's stubs do, each with
    /// the function it jumps to, whose prototype is its own.
    stubs: HashMap<u64, u64>,
    /// The functions whose prototype has been handed over.
    given: HashSet<u64>,
    /// The globals handed over, by index into [`Types::globals`].
    given_globals: HashSet<usize>,
}

impl<'a> Importer<'a> {
    pub fn new(types: &'a Types, stubs: HashMap<u64, u64>) -> Importer<'a> {
        Importer { types, writer: Writer::new(types), stubs, given: HashSet::new(), given_globals: HashSet::new() }
    }

    /// What the debug information says about the function at `addr`, or about the function it
    /// only jumps to.
    pub fn describes(&self, addr: u64) -> Option<&'a Function> {
        let described = self.stubs.get(&addr).copied().unwrap_or(addr);
        let index = self.types.functions.binary_search_by_key(&described, |function| function.addr).ok()?;
        Some(&self.types.functions[index])
    }

    /// Hands over what was written, reporting what the engine rejects on stderr.
    fn flush(&mut self, session: &mut crate::Session) {
        let Some(xml) = self.writer.take() else { return };
        match session.add_types(&xml) {
            Ok(rejected) => rejected.iter().for_each(|entry| eprintln!("debug information: {entry}")),
            Err(error) => eprintln!("debug information: {error}"),
        }
    }

    /// Gives `session` every global variable with its type.
    pub fn globals(&mut self, session: &mut crate::Session) {
        for (index, global) in self.types.globals.iter().enumerate() {
            if self.given_globals.insert(index) {
                self.writer.global(global);
            }
        }
        self.flush(session);
    }

    /// Gives `session` each global that holds one of `addrs` and was not given before, and says
    /// where those lie. Call it with the addresses a function's code refers to before
    /// decompiling it, where [`Types::globals_by_reference`] holds: an IL2CPP build has a global
    /// for every type, method and string its code looks up, and giving all of them would make
    /// every session wait for them. Its globals do not overlap, so the one before an address is
    /// the only one that can hold it.
    pub fn globals_at(&mut self, session: &mut crate::Session, addrs: impl IntoIterator<Item = u64>) -> Vec<std::ops::Range<u64>> {
        let globals = &self.types.globals;
        let mut given = Vec::new();
        for addr in addrs {
            let Some(index) = globals.partition_point(|global| global.addr <= addr).checked_sub(1) else { continue };
            let global = &globals[index];
            let extent = global.addr..global.addr + self.types.size(global.kind).max(1);
            if extent.contains(&addr) && self.given_globals.insert(index) {
                self.writer.global(global);
                given.push(extent);
            }
        }
        self.flush(session);
        given
    }

    /// Gives `session` the prototypes of the functions at `addrs` that have one and were not
    /// given before. Call it with a function and the functions it calls before decompiling it.
    pub fn functions(&mut self, session: &mut crate::Session, addrs: impl IntoIterator<Item = u64>) {
        for addr in addrs {
            if let Some(function) = self.describes(addr)
                && self.given.insert(addr)
            {
                self.writer.function(&Function { addr, ..function.clone() });
            }
        }
        self.flush(session);
    }

    /// Gives `session` the types that `text` names: a type name as a whole, or the words of a
    /// C declaration. Call it before the engine parses `text`.
    pub fn mentioned(&mut self, session: &mut crate::Session, text: &str) {
        let words = text.split(|c: char| !(c.is_alphanumeric() || c == '_'));
        for name in std::iter::once(text.trim()).chain(words) {
            if let Some(&(id, _, _)) = self.types.names.get(name).filter(|known| known.2 != TAKEN) {
                self.writer.named(id);
            }
        }
        self.flush(session);
    }
}

/// Set to `off`, keeps debug information from being read at all; otherwise names directories
/// to look for debug files in, separated by colons, besides the binary's own.
pub const DEBUG_VAR: &str = "RECORE_DEBUG";

/// The file that holds the debug information of the image at `path`: the image itself if it
/// carries DWARF, or else a `.debug` or `.pdb` file of its name, or of the name the image
/// records for it, next to it, in a `.debug` directory there, or in a directory [`DEBUG_VAR`]
/// names. `None` if there is none, which costs a few failed lookups and reads nothing.
pub fn debug_file(path: &Path, image: &Image) -> Option<PathBuf> {
    let setting = std::env::var(DEBUG_VAR).unwrap_or_default();
    if setting == "off" {
        return None;
    }
    // The sections that hold debug information are not loaded, so the image does not have them.
    let data = std::fs::read(path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let section = |name: &str| file.section_by_name(name).and_then(|section| section.uncompressed_data().ok()).filter(|data| !data.is_empty());
    if section(".debug_info").or_else(|| section("__debug_info")).is_some() {
        return Some(path.to_path_buf());
    }
    let file_name = path.file_name()?.to_string_lossy().into_owned();
    let extension = if image.format == Format::Pe { "pdb" } else { "debug" };
    let mut names = vec![format!("{file_name}.{extension}")];
    if let Some(stem) = path.file_stem().filter(|_| image.format == Format::Pe) {
        names.push(format!("{}.pdb", stem.to_string_lossy()));
    }
    if let Some(link) = section(".gnu_debuglink") {
        let end = link.iter().position(|&byte| byte == 0).unwrap_or(link.len());
        names.push(String::from_utf8_lossy(&link[..end]).into_owned());
    }
    let beside = path.parent().unwrap_or(Path::new("."));
    let mut dirs = vec![beside.to_path_buf(), beside.join(".debug")];
    dirs.extend(setting.split(':').filter(|dir| !dir.is_empty()).map(PathBuf::from));
    dirs.iter().flat_map(|dir| names.iter().map(move |name| dir.join(name))).find(|candidate| candidate.is_file() && candidate != path)
}

/// The types in the debug information of the image at `path`, if it has any that can be read,
/// or else those of the managed program of an IL2CPP build. Why debug information could not be
/// read goes to stderr: the decompiler works without. [`DEBUG_VAR`] set to `off` keeps both
/// out.
pub fn load(path: &Path, image: &Image) -> Option<Types> {
    if std::env::var(DEBUG_VAR).is_ok_and(|setting| setting == "off") {
        return None;
    }
    let Some(file) = debug_file(path, image) else { return image.il2cpp.as_deref().map(crate::il2cpp::types) };
    let loaded = if file.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("pdb")) {
        crate::pdb::types(&file, image)
    } else {
        crate::dwarf::types(&file, image.machine)
    };
    loaded.map_err(|error| eprintln!("debug information in {file:?}: {error:#}")).ok()
}
