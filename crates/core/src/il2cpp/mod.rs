//! The managed program of a Unity IL2CPP build: its types, methods and fields, from the
//! build's `global-metadata.dat` and the registration tables the binary carries.
//!
//! The metadata file names every type, method, field and parameter, but holds no address. The
//! binary holds the rest in tables it registers with the runtime at startup:
//!
//! - A code generation module per assembly, named after it, lists the code of each method by
//!   the low bits of the method's token.
//! - The code registration lists the modules and the code of generic methods compiled for
//!   particular type arguments.
//! - The metadata registration holds the table of types every type index refers to, the
//!   offset of each field, the size of each type, and the generic instances.
//!
//! The binary does not name these tables. Each is found by what it holds: a module by a
//! pointer to its assembly's name, the metadata registration by its two counts of types.
//!
//! Code that uses a type, method, field or string literal loads it from a usage slot, a
//! pointer in writable data. Until the runtime first fills it, the slot holds which item it
//! is for: `kind << 29 | index << 1 | 1`.

mod metadata;
mod tables;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rustc_hash::FxHashMap;

use crate::image::Image;
pub use metadata::Metadata;
use tables::{Tables, code};

/// The type a field, parameter or return value has, as the binary's type table spells it.
#[derive(Debug, Clone, PartialEq)]
pub enum Ty {
    Void,
    Bool,
    Char,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    IntPtr,
    UIntPtr,
    String,
    Object,
    /// An instance of a type definition: a reference to an object for a class or interface,
    /// the value itself for a struct or enum.
    Def(u32),
    /// A generic type definition given arguments, such as `List<int>`.
    Generic(u32, Vec<Ty>),
    Array(Box<Ty>),
    Pointer(Box<Ty>),
    /// A parameter passed by reference, `ref` or `out`.
    ByRef(Box<Ty>),
    /// A generic parameter, by name.
    Param(String),
    Unknown,
}

/// A field of a type, with where it lies.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: Ty,
    /// From the start of an object, of a value type's value, or of the type's static data for
    /// a static field. `None` for a constant, and for a thread-static field, which lives
    /// elsewhere.
    pub offset: Option<u32>,
    pub is_static: bool,
}

/// A class, struct, enum or interface.
#[derive(Debug, Clone)]
pub struct TypeDef {
    /// As C# spells it within its namespace, enclosing types first: `Outer<T>.Inner`. A name
    /// that types of several namespaces share is qualified by the namespace, and one that is
    /// still not unique, such as a compiler's helper class in each assembly, numbered.
    pub name: String,
    pub namespace: String,
    /// The type definition it derives from.
    pub parent: Option<u32>,
    pub is_value_type: bool,
    pub is_enum: bool,
    pub is_interface: bool,
    /// Its own fields, in declaration order. A class also has those of its parents.
    pub fields: Vec<Field>,
    /// Indices into [`Il2Cpp::methods`].
    pub methods: std::ops::Range<u32>,
    /// The method each vtable slot holds, by name; `None` where the metadata leaves it open.
    pub vtable: Vec<Option<String>>,
    /// Bytes in an object, its header included, or in a value type's value; and in the
    /// type's static data.
    pub instance_size: u32,
    pub static_size: u32,
    /// An enum's members and their values.
    pub members: Vec<(String, i64)>,
}

#[derive(Debug, Clone)]
pub struct Method {
    pub name: String,
    pub owner: u32,
    pub returns: Ty,
    pub params: Vec<(String, Ty)>,
    pub is_static: bool,
    /// Where its code is; `None` for an abstract or generic method, or one the build left out.
    pub addr: Option<u64>,
}

/// What a usage slot refers to.
#[derive(Debug, Clone, PartialEq)]
pub enum Usage {
    /// The runtime's class of a type: `Il2CppClass *`.
    Class(Ty),
    /// A type as a value, such as `typeof(T)` passes: `Il2CppType *`.
    Type(Ty),
    /// A method, by its name: `MethodInfo *`.
    Method(String),
    /// A field, by its owner's name and its own: `FieldInfo *`.
    Field(String),
    /// A string literal: `String *`.
    Literal(String),
}

/// Where the runtime's class record keeps what code reaches through it, for the layout of the
/// metadata version: the pointer to a type's static fields, the word that says its static
/// constructor has run, and the start of its vtable, each entry of which is the method's code
/// and then its `MethodInfo`.
#[derive(Debug, Clone, Copy)]
pub struct ClassLayout {
    pub static_fields: u64,
    pub cctor_finished: u64,
    pub vtable: u64,
}

/// The managed program of an IL2CPP build.
#[derive(Debug)]
pub struct Il2Cpp {
    pub version: u32,
    pub types: Vec<TypeDef>,
    pub methods: Vec<Method>,
    /// Code compiled for a generic method with particular type arguments, by name:
    /// `List<int>.Add`. Several instances can share one body.
    pub generic_methods: Vec<(u64, String)>,
    /// Usage slots by address, sorted.
    pub usages: Vec<(u64, Usage)>,
    pub class_layout: ClassLayout,
    /// How C# writes the build's types.
    pub names: Names,
}

/// Gives `image`, loaded from `path`, the managed program and the names of its IL2CPP build, if
/// it is one whose metadata can be found. Why the metadata could not be read goes to stderr:
/// the binary is analyzed without it.
#[inline(never)]
pub(crate) fn attach(image: &mut Image, path: &Path) {
    let Some(metadata) = find(path) else { return };
    match load(image, &metadata) {
        Ok(il2cpp) => {
            // A name the file carries for an address keeps it.
            for (addr, name) in il2cpp.function_names().into_iter().chain(il2cpp.usage_names()) {
                image.symbol_names.entry(addr).or_insert(name);
            }
            image.il2cpp = Some(std::sync::Arc::new(il2cpp));
        }
        Err(error) => eprintln!("IL2CPP metadata in {metadata:?}: {error:#}"),
    }
}

/// The `global-metadata.dat` of the IL2CPP build whose code is the binary at `binary`: beside
/// it; for `GameAssembly`, in the player's data directory beside it,
/// `<Game>_Data/il2cpp_data/Metadata/`; or for `libil2cpp`, in `assets/bin/Data/Managed/Metadata/`
/// of an Android package, two directories above `lib/<abi>/libil2cpp.so`. Another binary costs
/// one failed lookup.
pub fn find(binary: &Path) -> Option<PathBuf> {
    const FILE: &str = "global-metadata.dat";
    let dir = binary.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let beside = dir.join(FILE);
    if beside.is_file() {
        return Some(beside);
    }
    match binary.file_stem()?.to_str()? {
        "libil2cpp" => Some(dir.join("../../assets/bin/Data/Managed/Metadata").join(FILE)).filter(|android| android.is_file()),
        // The first in order, where a directory holds the data of several builds.
        "GameAssembly" => std::fs::read_dir(dir)
            .ok()?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with("_Data"))
            .map(|entry| entry.path().join("il2cpp_data/Metadata").join(FILE))
            .filter(|candidate| candidate.is_file())
            .min(),
        _ => None,
    }
}

/// Reads the managed program of the IL2CPP build whose code `image` is, from the metadata file
/// at `path`.
pub fn load(image: &Image, path: &Path) -> Result<Il2Cpp> {
    let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
    let metadata = metadata::parse(&data).with_context(|| format!("reading {path:?}"))?;
    Builder::new(image, &metadata)?.build()
}

/// The 64-bit words of the binary, with the targets its relocations put in them.
struct Words<'a> {
    image: &'a Image,
    relocated: FxHashMap<u64, u64>,
}

impl Words<'_> {
    fn u32(&self, addr: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.image.bytes_from(addr)?.get(..4)?.try_into().ok()?))
    }

    fn u64(&self, addr: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.image.bytes_from(addr)?.get(..8)?.try_into().ok()?))
    }

    /// The pointer stored at `addr`: what a relocation puts there, or else the word itself.
    /// `None` for a null pointer.
    fn pointer(&self, addr: u64) -> Option<u64> {
        self.relocated.get(&addr).copied().or_else(|| self.u64(addr)).filter(|&target| target != 0)
    }

    /// Entry `index` of the array of pointers at `array`.
    fn entry(&self, array: u64, index: u64) -> Option<u64> {
        self.pointer(array + 8 * index)
    }

    fn text(&self, addr: u64) -> Option<&str> {
        let bytes = self.image.bytes_from(addr)?;
        std::str::from_utf8(&bytes[..bytes.iter().take(512).position(|&byte| byte == 0)?]).ok()
    }
}

/// Bytes in an object's header: its class and its monitor.
const HEADER: u32 = 16;

/// Deeper than any real build goes: classes deriving from classes, and types nested in type
/// arguments.
const MAX_ANCESTORS: usize = 64;
const MAX_NESTING: u32 = 32;

/// Kinds of usage slot.
const CLASS: u64 = 1;
const TYPE: u64 = 2;
const METHOD_DEF: u64 = 3;
const FIELD: u64 = 4;
const LITERAL: u64 = 5;
const METHOD_SPEC: u64 = 6;

struct Builder<'a> {
    words: Words<'a>,
    metadata: &'a Metadata,
    tables: Tables,
    modules: Vec<(usize, u64)>,
    /// Type records read so far, by address. Records refer to each other, the same ones from
    /// many places, and in a damaged binary in a loop: one being read stands for no type.
    read: std::cell::RefCell<FxHashMap<u64, Ty>>,
}

impl<'a> Builder<'a> {
    fn new(image: &'a Image, metadata: &'a Metadata) -> Result<Builder<'a>> {
        ensure!(image.machine.pointer_size() == 8, "IL2CPP builds are read for 64-bit code only");
        let words = Words { image, relocated: image.relative_targets.iter().copied().collect() };
        let modules = tables::find_modules(&words, metadata);
        let tables = if metadata.version >= 100 { Tables::discovered(&words, metadata) } else { Tables::registered(&words, metadata, &modules) };
        let tables = tables.context("the binary's type table is not where it was looked for")?;
        Ok(Builder { words, metadata, tables, modules, read: Default::default() })
    }

    fn build(&self) -> Result<Il2Cpp> {
        let metadata = self.metadata;
        let names = self.type_names();
        let mut types: Vec<TypeDef> = metadata.types.iter().enumerate().map(|(index, def)| self.type_def(index as u32, def, &names)).collect();
        // A class's objects hold its ancestors' fields before its own, the root's first.
        let own: Vec<Vec<Field>> = types.iter().map(|def| def.fields.iter().filter(|field| !field.is_static).cloned().collect()).collect();
        let parents: Vec<Option<u32>> = types.iter().map(|def| def.parent).collect();
        for (index, def) in types.iter_mut().enumerate().filter(|(_, def)| !def.is_value_type) {
            let mut ancestors = Vec::new();
            let mut parent = def.parent;
            // Damaged metadata can chain every type into one line of parents.
            while let Some(base) = parent.filter(|&base| base as usize != index && !ancestors.contains(&base) && ancestors.len() < MAX_ANCESTORS) {
                ancestors.push(base);
                parent = parents[base as usize];
            }
            let inherited = ancestors.iter().rev().flat_map(|&base| own[base as usize].iter().cloned());
            def.fields.splice(0..0, inherited.collect::<Vec<_>>());
        }

        // An enum's members are its constant fields, each of the type of its one instance field.
        let defaults: FxHashMap<u32, usize> = metadata.field_default_values.iter().copied().collect();
        for (index, def) in metadata.types.iter().enumerate().filter(|(_, def)| def.is_enum()) {
            let Some(start) = def.field_start else {
                continue;
            };
            let under = types[index].fields.iter().find(|field| !field.is_static).map(|field| field.ty.clone());
            types[index].members = (start..start + u32::from(def.field_count))
                .filter_map(|field| {
                    let data = metadata.default_value_data.get(*defaults.get(&field)?..)?;
                    let value = match under.as_ref()? {
                        Ty::Bool | Ty::U8 => i64::from(*data.first()?),
                        Ty::I8 => i64::from(*data.first()? as i8),
                        Ty::Char | Ty::U16 => i64::from(u16::from_le_bytes(data.get(..2)?.try_into().ok()?)),
                        Ty::I16 => i64::from(i16::from_le_bytes(data.get(..2)?.try_into().ok()?)),
                        Ty::U32 => i64::from(metadata::compressed_u32(data)?),
                        Ty::I32 => i64::from(metadata::compressed_i32(data)?),
                        Ty::I64 | Ty::U64 => i64::from_le_bytes(data.get(..8)?.try_into().ok()?),
                        _ => return None,
                    };
                    Some((metadata.fields[field as usize].name.clone(), value))
                })
                .collect();
        }

        let mut methods: Vec<Method> = metadata.methods.iter().map(|method| self.method(method)).collect();
        for &(image, module) in &self.modules {
            let image = &metadata.images[image];
            let (Some(start), Some(count), Some(table)) =
                (image.type_start, self.words.u32(module + code::MODULE_METHOD_COUNT), self.words.pointer(module + code::MODULE_METHODS))
            else {
                continue;
            };
            for def in metadata.types.iter().skip(start as usize).take(image.type_count as usize) {
                let Some(first) = def.method_start else {
                    continue;
                };
                for index in first..first + u32::from(def.method_count) {
                    let row = (metadata.methods[index as usize].token & 0xff_ffff) as u64;
                    if row > 0 && row <= u64::from(count) {
                        methods[index as usize].addr = self.words.entry(table, row - 1);
                    }
                }
            }
        }

        for (index, def) in metadata.types.iter().enumerate() {
            let mut vtable: Vec<Option<String>> = (0..u32::from(def.vtable_count))
                .map(|slot| {
                    let encoded = *metadata.vtable_methods.get(def.vtable_start?.checked_add(slot)? as usize)?;
                    self.method_name(u64::from(encoded >> 29), u64::from(encoded & 0x1fff_ffff) >> 1, &names, &methods)
                })
                .collect();
            // The table leaves an abstract method's slot empty; the method says which it is.
            for method in def.method_start.map_or(0..0, |start| start..start + u32::from(def.method_count)) {
                let slot = usize::from(metadata.methods[method as usize].slot);
                if let Some(entry @ None) = vtable.get_mut(slot) {
                    *entry = Some(format!("{}.{}", names.names[index], methods[method as usize].name));
                }
            }
            types[index].vtable = vtable;
        }

        let generic_methods = self.generic_methods(&names, &methods);
        let usages = self.usages(&names, &methods);
        // Where code reaches into the class record, as Unity 6's code does: static fields at
        // `klass + 0xb8`, the check before them at `klass + 0xe4` and virtual calls at
        // `klass + 0x138 + 16 * slot`. Version 107 keeps the static fields at `klass + 0xa0`.
        let static_fields = if metadata.version >= 100 { 0xa0 } else { 0xb8 };
        let class_layout = ClassLayout { static_fields, cctor_finished: 0xe4, vtable: 0x138 };
        Ok(Il2Cpp { version: metadata.version, types, methods, generic_methods, usages, class_layout, names })
    }

    /// The `Il2CppType` at `addr`, read to the depth of nested types it needs.
    fn ty_at(&self, addr: u64, depth: u32) -> Ty {
        if let Some(ty) = self.read.borrow().get(&addr) {
            return ty.clone();
        }
        self.read.borrow_mut().insert(addr, Ty::Unknown);
        let ty = self.read_ty(addr, depth).unwrap_or(Ty::Unknown);
        self.read.borrow_mut().insert(addr, ty.clone());
        ty
    }

    fn read_ty(&self, addr: u64, depth: u32) -> Option<Ty> {
        // Past a depth no real type nests to, the file is damaged, and the read stops to spare
        // the stack. What was read stays in the memo, so deep nesting costs no more than wide,
        // and a record first reached that deep keeps its cut-off reading.
        if depth > MAX_NESTING {
            return Some(Ty::Unknown);
        }
        let data = self.words.pointer(addr).unwrap_or(0);
        let bits = self.words.u32(addr + 8)?;
        let element = || self.words.pointer(addr).map_or(Ty::Unknown, |inner| self.ty_at(inner, depth + 1));
        let ty = match (bits >> 16) & 0xff {
            0x01 => Ty::Void,
            0x02 => Ty::Bool,
            0x03 => Ty::Char,
            0x04 => Ty::I8,
            0x05 => Ty::U8,
            0x06 => Ty::I16,
            0x07 => Ty::U16,
            0x08 => Ty::I32,
            0x09 => Ty::U32,
            0x0a => Ty::I64,
            0x0b => Ty::U64,
            0x0c => Ty::F32,
            0x0d => Ty::F64,
            0x0e => Ty::String,
            0x0f => Ty::Pointer(Box::new(element())),
            0x11 | 0x12 => Ty::Def(u32::try_from(data).ok().filter(|&def| (def as usize) < self.metadata.types.len())?),
            0x13 | 0x1e => Ty::Param(self.metadata.generic_parameters.get(data as usize).cloned().unwrap_or_else(|| "T".into())),
            // A multi-dimensional array's record starts with the element type.
            0x14 => Ty::Array(Box::new(self.words.pointer(data).map_or(Ty::Unknown, |inner| self.ty_at(inner, depth + 1)))),
            0x15 => {
                // A generic class: the type it instantiates, then its arguments.
                let generic = self.words.pointer(addr)?;
                let Ty::Def(def) = self.ty_at(self.words.pointer(generic)?, depth + 1) else {
                    return Some(Ty::Unknown);
                };
                let args = self.words.pointer(generic + 8).map_or_else(Vec::new, |inst| self.generic_args(inst, depth + 1));
                Ty::Generic(def, args)
            }
            0x18 => Ty::IntPtr,
            0x19 => Ty::UIntPtr,
            0x1c => Ty::Object,
            0x1d => Ty::Array(Box::new(element())),
            _ => Ty::Unknown,
        };
        // Bit 29 marks a type passed by reference.
        Some(if bits & (1 << 29) != 0 { Ty::ByRef(Box::new(ty)) } else { ty })
    }

    /// The type arguments of the generic instance record at `inst`: a count, then an array.
    fn generic_args(&self, inst: u64, depth: u32) -> Vec<Ty> {
        let count = self.words.u32(inst).unwrap_or(0).min(32);
        let Some(argv) = self.words.pointer(inst + 8) else {
            return Vec::new();
        };
        (0..u64::from(count)).map(|index| self.words.entry(argv, index).map_or(Ty::Unknown, |arg| self.ty_at(arg, depth))).collect()
    }

    /// The type that type index `index` refers to.
    fn ty(&self, index: Option<u32>) -> Ty {
        let (types, count) = self.tables.types;
        match index.map(u64::from).filter(|&index| index < count) {
            Some(index) => self.words.entry(types, index).map_or(Ty::Unknown, |addr| self.ty_at(addr, 0)),
            None => Ty::Unknown,
        }
    }

    /// Each type definition's name, whole and in parts, with its own generic parameters.
    fn type_names(&self) -> Names {
        let defs = &self.metadata.types;
        // A name says how many generic parameters are the type's own: `Dictionary`2`.
        let own: Vec<(String, usize)> = defs
            .iter()
            .map(|def| match def.name.split_once('`') {
                Some((base, arity)) => (base.to_string(), arity.parse().unwrap_or(0)),
                None => (def.name.clone(), 0),
            })
            .collect();
        let enclosing: Vec<Option<u32>> = defs
            .iter()
            .map(|def| match self.ty(def.declaring) {
                Ty::Def(outer) | Ty::Generic(outer, _) => Some(outer),
                _ => None,
            })
            .collect();
        // A nested type's namespace is that of the type it is nested in, outermost.
        let mut namespaces = Vec::with_capacity(defs.len());
        let mut parts: Vec<Vec<(String, usize)>> = (0..defs.len())
            .map(|index| {
                let mut chain = vec![own[index].clone()];
                let mut outermost = index;
                while let Some(next) = enclosing[outermost].filter(|_| chain.len() < 16) {
                    chain.push(own[next as usize].clone());
                    outermost = next as usize;
                }
                namespaces.push(defs[outermost].namespace.as_str());
                chain.reverse();
                chain
            })
            .collect();
        let params: Vec<Vec<String>> = defs.iter().map(|def| self.generic_parameters(def.generic_container)).collect();
        let render_all = |parts: &[Vec<(String, usize)>]| -> Vec<String> { parts.iter().zip(&params).map(|(parts, params)| render(parts, params)).collect() };
        let mut counts: FxHashMap<String, usize> = FxHashMap::default();
        render_all(&parts).into_iter().for_each(|name| *counts.entry(name).or_default() += 1);
        for (index, name) in render_all(&parts).into_iter().enumerate() {
            if counts[&name] > 1 && !namespaces[index].is_empty() {
                parts[index][0].0.insert_str(0, &format!("{}.", namespaces[index]));
            }
        }
        let mut seen: FxHashMap<String, usize> = FxHashMap::default();
        for (index, name) in render_all(&parts).into_iter().enumerate() {
            let count = seen.entry(name).or_default();
            *count += 1;
            if *count > 1
                && let Some(last) = parts[index].last_mut()
            {
                last.0.push_str(&format!("_{count}"));
            }
        }
        Names { names: render_all(&parts), parts }
    }

    fn generic_parameters(&self, container: Option<u32>) -> Vec<String> {
        let Some(&(start, count)) = container.and_then(|container| self.metadata.generic_containers.get(container as usize)) else {
            return Vec::new();
        };
        self.metadata.generic_parameters.iter().skip(start as usize).take(usize::from(count)).cloned().collect()
    }

    fn type_def(&self, index: u32, def: &metadata::TypeDefinition, names: &Names) -> TypeDef {
        let parent = match self.ty(def.parent) {
            Ty::Def(parent) | Ty::Generic(parent, _) if parent != index => Some(parent),
            _ => None,
        };
        let offsets = self.tables.field_offsets.and_then(|table| self.words.entry(table, u64::from(index)));
        let (types, type_count) = self.tables.types;
        let fields = (0..u32::from(def.field_count))
            .filter_map(|position| {
                let field = self.metadata.fields.get((def.field_start? + position) as usize)?;
                let ty = self.ty(field.kind);
                // The field's attributes are in the type record: 0x10 static, 0x40 constant.
                let attrs = field
                    .kind
                    .map(u64::from)
                    .filter(|&kind| kind < type_count)
                    .and_then(|kind| self.words.u32(self.words.entry(types, kind)? + 8))
                    .unwrap_or(0)
                    & 0xffff;
                let is_static = attrs & 0x10 != 0;
                let offset =
                    offsets.and_then(|offsets| self.words.u32(offsets + 4 * u64::from(position))).filter(|&offset| offset as i32 >= 0 && attrs & 0x40 == 0);
                // A value type's offsets count the header of the object it would be boxed in.
                let offset = if def.is_value_type() && !is_static { offset.and_then(|offset| offset.checked_sub(HEADER)) } else { offset };
                Some(Field { name: field.name.clone(), ty: strip_by_ref(ty), offset, is_static })
            })
            .collect();
        let sizes = self.tables.sizes.and_then(|table| self.words.entry(table, u64::from(index)));
        TypeDef {
            name: names.names[index as usize].clone(),
            namespace: def.namespace.clone(),
            parent,
            is_value_type: def.is_value_type(),
            is_enum: def.is_enum(),
            is_interface: def.is_interface(),
            fields,
            methods: def.method_start.map_or(0..0, |start| start..start + u32::from(def.method_count)),
            vtable: Vec::new(),
            instance_size: sizes.and_then(|sizes| self.words.u32(sizes)).unwrap_or(0).saturating_sub(if def.is_value_type() { HEADER } else { 0 }),
            static_size: sizes.and_then(|sizes| self.words.u32(sizes + 8)).unwrap_or(0),
            members: Vec::new(),
        }
    }

    fn method(&self, method: &metadata::MethodDefinition) -> Method {
        let params = (0..u32::from(method.parameter_count))
            .map(|position| {
                let param = method.parameter_start.and_then(|start| self.metadata.parameters.get(start.checked_add(position)? as usize));
                param.map_or_else(|| (format!("arg{position}"), Ty::Unknown), |param| (param.name.clone(), self.ty(param.kind)))
            })
            .collect();
        Method {
            name: method.name.clone(),
            owner: method.declaring.unwrap_or(0),
            returns: self.ty(method.returns),
            params,
            is_static: method.flags & 0x10 != 0,
            addr: None,
        }
    }

    /// The name of the method an encoded index refers to: a definition, or a generic instance.
    fn method_name(&self, kind: u64, index: u64, names: &Names, methods: &[Method]) -> Option<String> {
        match kind {
            METHOD_DEF => {
                let method = methods.get(index as usize)?;
                Some(format!("{}.{}", names.names.get(method.owner as usize)?, method.name))
            }
            METHOD_SPEC => self.spec_name(index, names, methods),
            _ => None,
        }
    }

    /// The name of method instance `index`: `List<int>.Add`, or `Enumerable.Select<int,string>`.
    fn spec_name(&self, index: u64, names: &Names, methods: &[Method]) -> Option<String> {
        let (specs, count) = self.tables.method_specs?;
        (index < count).then_some(())?;
        let spec = specs + 12 * index;
        let method = methods.get(self.words.u32(spec)? as usize)?;
        let (insts, _) = self.tables.generic_insts?;
        let args = |at: u64| -> Option<Vec<Ty>> {
            let inst = self.words.u32(at)? as i32;
            (inst >= 0).then(|| self.words.entry(insts, inst as u64).map_or_else(Vec::new, |inst| self.generic_args(inst, 0)))
        };
        let owner = match args(spec + 4) {
            Some(class_args) => names.display(&Ty::Generic(method.owner, class_args)),
            None => names.names.get(method.owner as usize)?.clone(),
        };
        let method_args =
            args(spec + 8).map(|args| format!("<{}>", args.iter().map(|arg| names.display(arg)).collect::<Vec<_>>().join(","))).unwrap_or_default();
        Some(format!("{owner}.{}{method_args}", method.name))
    }

    /// The code of each generic method instance the build compiled, with its name.
    fn generic_methods(&self, names: &Names, methods: &[Method]) -> Vec<(u64, String)> {
        let (Some((pointers, pointer_count)), Some((table, count))) = (self.tables.generic_method_pointers, self.tables.generic_method_table) else {
            return Vec::new();
        };
        // Each entry: the method instance, then the index of its code among the pointers.
        (0..count.min(1 << 22))
            .filter_map(|entry| {
                let at = table + 16 * entry;
                let (spec, code) = (u64::from(self.words.u32(at)?), u64::from(self.words.u32(at + 4)?));
                (code < pointer_count).then_some(())?;
                Some((self.words.entry(pointers, code)?, self.spec_name(spec, names, methods)?))
            })
            .collect()
    }

    /// Usage slots: words in writable data that hold an encoded usage the program has.
    fn usages(&self, names: &Names, methods: &[Method]) -> Vec<(u64, Usage)> {
        let metadata = self.metadata;
        let spec_count = self.tables.method_specs.map_or(0, |(_, count)| count);
        let type_count = self.tables.types.1;
        let mut usages = Vec::new();
        for section in self.words.image.sections.iter().filter(|section| section.writable && !section.executable) {
            // Slots are pointers, at addresses that are multiples of 8.
            let skip = (section.addr.next_multiple_of(8) - section.addr) as usize;
            let start = section.addr + skip as u64;
            for (slot, bytes) in (start..).step_by(8).zip(section.data.get(skip..).unwrap_or_default().as_chunks::<8>().0) {
                let word = u64::from_le_bytes(*bytes);
                if word & 1 == 0 || word >> 32 != 0 || self.words.relocated.contains_key(&slot) {
                    continue;
                }
                let (kind, index) = (word >> 29, (word & 0x1fff_ffff) >> 1);
                let usage = match kind {
                    CLASS | TYPE if index < type_count => {
                        let ty = self.ty(Some(index as u32));
                        if ty == Ty::Unknown {
                            continue;
                        }
                        if kind == CLASS { Usage::Class(ty) } else { Usage::Type(ty) }
                    }
                    METHOD_DEF if (index as usize) < methods.len() => Usage::Method(self.method_name(kind, index, names, methods).unwrap_or_default()),
                    METHOD_SPEC if index < spec_count => match self.method_name(kind, index, names, methods) {
                        Some(name) => Usage::Method(name),
                        None => continue,
                    },
                    FIELD => {
                        let Some(&(owner, position)) = metadata.field_refs.get(index as usize) else {
                            continue;
                        };
                        let owner = self.ty(owner);
                        let def = match owner {
                            Ty::Def(def) | Ty::Generic(def, _) => def,
                            _ => continue,
                        };
                        let Some(field) = metadata.types[def as usize].field_start.and_then(|start| metadata.fields.get(start.checked_add(position)? as usize))
                        else {
                            continue;
                        };
                        Usage::Field(format!("{}.{}", names.display(&owner), field.name))
                    }
                    LITERAL => match metadata.string_literals.get(index as usize) {
                        Some(text) => Usage::Literal(text.clone()),
                        None => continue,
                    },
                    _ => continue,
                };
                usages.push((slot, usage));
            }
        }
        usages
    }
}

fn strip_by_ref(ty: Ty) -> Ty {
    match ty {
        Ty::ByRef(inner) => *inner,
        other => other,
    }
}

/// How C# writes the types of a build: `int`, `string`, `List<int>`,
/// `Dictionary<int,string>.KeyCollection[]`.
#[derive(Debug)]
pub struct Names {
    /// Each type definition's name with its own generic parameters.
    names: Vec<String>,
    /// The same in parts, enclosing types first, each with how many of the type's generic
    /// arguments are its own: `Dictionary<TKey,TValue>.KeyCollection` is `Dictionary` with 2
    /// and `KeyCollection` with none.
    parts: Vec<Vec<(String, usize)>>,
}

impl Names {
    /// The name of type definition `def`.
    pub fn name(&self, def: u32) -> &str {
        self.names.get(def as usize).map_or("?", String::as_str)
    }

    pub fn display(&self, ty: &Ty) -> String {
        match ty {
            Ty::Void => "void".into(),
            Ty::Bool => "bool".into(),
            Ty::Char => "char".into(),
            Ty::I8 => "sbyte".into(),
            Ty::U8 => "byte".into(),
            Ty::I16 => "short".into(),
            Ty::U16 => "ushort".into(),
            Ty::I32 => "int".into(),
            Ty::U32 => "uint".into(),
            Ty::I64 => "long".into(),
            Ty::U64 => "ulong".into(),
            Ty::F32 => "float".into(),
            Ty::F64 => "double".into(),
            Ty::IntPtr => "IntPtr".into(),
            Ty::UIntPtr => "UIntPtr".into(),
            Ty::String => "string".into(),
            Ty::Object => "object".into(),
            Ty::Def(def) => self.name(*def).to_string(),
            Ty::Generic(def, args) => match self.parts.get(*def as usize) {
                Some(parts) => render(parts, &args.iter().map(|arg| self.display(arg)).collect::<Vec<_>>()),
                None => "?".into(),
            },
            Ty::Array(element) => format!("{}[]", self.display(element)),
            Ty::Pointer(target) => format!("{}*", self.display(target)),
            Ty::ByRef(target) => format!("ref {}", self.display(target)),
            Ty::Param(name) => name.clone(),
            Ty::Unknown => "?".into(),
        }
    }
}

/// A name in parts with the generic arguments given out to the parts they belong to:
/// `Dictionary<int,string>.KeyCollection`. Arguments the parts do not account for go to the
/// last.
fn render(parts: &[(String, usize)], args: &[String]) -> String {
    let fits = parts.iter().map(|(_, arity)| arity).sum::<usize>() == args.len();
    let mut args = args.iter().map(String::as_str);
    let last = parts.len().saturating_sub(1);
    let mut out = Vec::with_capacity(parts.len());
    for (index, (name, arity)) in parts.iter().enumerate() {
        let take = if fits {
            *arity
        } else if index == last {
            usize::MAX
        } else {
            0
        };
        let own: Vec<&str> = args.by_ref().take(take).collect();
        out.push(if own.is_empty() { name.clone() } else { format!("{name}<{}>", own.join(",")) });
    }
    out.join(".")
}

impl Il2Cpp {
    /// Whether `addr` is a usage slot.
    pub fn is_usage(&self, addr: u64) -> bool {
        self.usages.binary_search_by_key(&addr, |(slot, _)| *slot).is_ok()
    }

    /// A function name for the code at each method's address, and for each generic method
    /// instance's: `Player.Update`, `List<int>.Add`. Where several methods share code, the
    /// first keeps the name.
    pub fn function_names(&self) -> FxHashMap<u64, String> {
        let mut names = FxHashMap::default();
        for method in &self.methods {
            if let Some(addr) = method.addr {
                names.entry(addr).or_insert_with(|| format!("{}.{}", self.types[method.owner as usize].name, method.name));
            }
        }
        for (addr, name) in &self.generic_methods {
            names.entry(*addr).or_insert_with(|| name.clone());
        }
        names
    }

    /// The name of each usage slot: `Player_TypeInfo` for a class, `typeof(Player)` for a
    /// type, `Player.Update_MethodInfo` for a method, `Player.speed_FieldInfo` for a field,
    /// and the text in quotes for a string literal.
    pub fn usage_names(&self) -> Vec<(u64, String)> {
        let names = &self.names;
        self.usages
            .iter()
            .map(|(slot, usage)| {
                let name = match usage {
                    Usage::Class(ty) => format!("{}_TypeInfo", names.display(ty)),
                    Usage::Type(ty) => format!("typeof({})", names.display(ty)),
                    Usage::Method(method) => format!("{method}_MethodInfo"),
                    Usage::Field(field) => format!("{field}_FieldInfo"),
                    Usage::Literal(text) => {
                        format!("{:?}", text.chars().take(80).collect::<String>())
                    }
                };
                (*slot, name)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn generic_arguments_go_to_the_parts_they_belong_to() {
        let parts = |parts: &[(&str, usize)]| parts.iter().map(|&(name, arity)| (name.to_string(), arity)).collect::<Vec<_>>();
        let args = |args: &[&str]| args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        assert_eq!(render(&parts(&[("Dictionary", 2), ("KeyCollection", 0)]), &args(&["int", "string"])), "Dictionary<int,string>.KeyCollection");
        assert_eq!(render(&parts(&[("Outer", 1), ("Middle", 1), ("Inner", 0)]), &args(&["int", "string"])), "Outer<int>.Middle<string>.Inner");
        // Arguments the parts do not account for go to the last.
        assert_eq!(render(&parts(&[("List", 1), ("Enumerator", 0)]), &args(&["int", "bool"])), "List.Enumerator<int,bool>");
    }
}
