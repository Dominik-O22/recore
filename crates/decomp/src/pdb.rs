//! Data types, function prototypes and globals from the PDB of a Windows binary.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use pdb2::{FallibleIterator, PrimitiveKind, SymbolData, TypeData, TypeFinder, TypeIndex};
use recore::Image;

use crate::types::{Base, Field, Function, Global, Named, Prototype, Type, TypeId, Types, VOID};

/// Reads the types that the functions and globals of a PDB are declared with.
struct Reader<'t> {
    finder: TypeFinder<'t>,
    /// Where each struct, union and enum is defined, by name. What uses one usually refers to a
    /// record that only declares it.
    definitions: HashMap<Vec<u8>, TypeIndex>,
    /// The names that typedefs give to types, which is the only name an unnamed struct has.
    typedefs: HashMap<TypeIndex, String>,
    /// The type each record read so far became.
    seen: HashMap<TypeIndex, TypeId>,
    /// Structs and unions whose field list is still to be read.
    pending: Vec<(TypeId, TypeIndex)>,
    /// The calling convention is only told apart on 32-bit x86.
    conventions: bool,
    types: Types,
}

/// The types, function prototypes and globals in the PDB at `path`, which belongs to `image`.
pub fn types(path: &Path, image: &Image) -> Result<Types> {
    let pointer = if image.machine == recore::image::Machine::X86 { 4 } else { 8 };
    let mut pdb = pdb2::PDB::open(std::fs::File::open(path)?)?;
    let address_map = pdb.address_map()?;
    let information = pdb.type_information()?;
    let mut reader = Reader { finder: information.finder(), definitions: HashMap::new(), typedefs: HashMap::new(), seen: HashMap::new(), pending: Vec::new(), conventions: pointer == 4, types: Types::new(pointer) };
    let mut walk = information.iter();
    while let Some(item) = walk.next()? {
        reader.finder.update(&walk);
        let (name, unique, properties) = match item.parse() {
            Ok(TypeData::Class(class)) => (class.name, class.unique_name, class.properties),
            Ok(TypeData::Union(union)) => (union.name, union.unique_name, union.properties),
            Ok(TypeData::Enumeration(enumeration)) => (enumeration.name, enumeration.unique_name, enumeration.properties),
            _ => continue,
        };
        if !properties.forward_reference() {
            reader.definitions.insert(unique.unwrap_or(name).as_bytes().to_vec(), item.index());
        }
    }

    let globals = pdb.global_symbols()?;
    let mut symbols = globals.iter();
    while let Some(symbol) = symbols.next()? {
        if let Ok(SymbolData::UserDefinedType(typedef)) = symbol.parse() {
            reader.typedefs.entry(typedef.type_index).or_insert_with(|| typedef.name.to_string().into_owned());
        }
    }

    // A function's parameter names follow it, as the first variables of its scope.
    struct Open {
        function: usize,
        depth: usize,
        marked: Vec<String>,
        unmarked: Vec<String>,
    }
    let close = |types: &mut Types, open: Open| {
        let Type::Function(prototype) = &mut types.types[types.functions[open.function].prototype as usize] else { return };
        let this = usize::from(prototype.params.first().is_some_and(|param| param.0 == "this"));
        let named = prototype.params.len() - this;
        // Newer compilers mark which variables are parameters; older ones list them first.
        let names = if open.marked.len() >= named { open.marked } else { open.unmarked };
        if names.len() >= named {
            for (param, name) in prototype.params[this..].iter_mut().zip(names) {
                param.0 = name;
            }
        }
    };
    let data = |reader: &mut Reader, symbol: &pdb2::DataSymbol| {
        if let Some(rva) = symbol.offset.to_rva(&address_map) {
            let kind = reader.resolve(symbol.type_index);
            reader.types.globals.push(Global { addr: image.base + u64::from(rva.0), name: symbol.name.to_string().into_owned(), kind });
        }
    };
    let debug_information = pdb.debug_information()?;
    let mut modules = debug_information.modules()?;
    while let Some(module) = modules.next()? {
        let Some(info) = pdb.module_info(&module)? else { continue };
        let mut symbols = info.symbols()?;
        let mut open: Option<Open> = None;
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(SymbolData::Procedure(procedure)) => {
                    if let Some(open) = open.take() {
                        close(&mut reader.types, open);
                    }
                    let (Some(rva), Some(prototype)) = (procedure.offset.to_rva(&address_map), reader.prototype(procedure.type_index)) else { continue };
                    let prototype = reader.types.add(Type::Function(prototype));
                    reader.types.functions.push(Function { addr: image.base + u64::from(rva.0), name: procedure.name.to_string().into_owned(), prototype });
                    open = Some(Open { function: reader.types.functions.len() - 1, depth: 1, marked: Vec::new(), unmarked: Vec::new() });
                }
                Ok(SymbolData::Block(_) | SymbolData::InlineSite(_)) => open.iter_mut().for_each(|open| open.depth += 1),
                Ok(SymbolData::ScopeEnd | SymbolData::InlineSiteEnd | SymbolData::ProcedureEnd) => {
                    if let Some(open) = open.take_if(|open| {
                        open.depth -= 1;
                        open.depth == 0
                    }) {
                        close(&mut reader.types, open);
                    }
                }
                Ok(SymbolData::Local(local)) => {
                    if let Some(open) = open.as_mut().filter(|open| open.depth == 1 && local.flags.isparam) {
                        open.marked.push(local.name.to_string().into_owned());
                    }
                }
                Ok(SymbolData::RegisterRelative(variable)) => {
                    if let Some(open) = open.as_mut().filter(|open| open.depth == 1) {
                        open.unmarked.push(variable.name.to_string().into_owned());
                    }
                }
                Ok(SymbolData::Data(symbol)) => data(&mut reader, &symbol),
                _ => {}
            }
        }
        if let Some(open) = open.take() {
            close(&mut reader.types, open);
        }
    }
    let mut symbols = globals.iter();
    while let Some(symbol) = symbols.next()? {
        if let Ok(SymbolData::Data(symbol)) = symbol.parse() {
            data(&mut reader, &symbol);
        }
    }
    while let Some((id, fields)) = reader.pending.pop() {
        reader.members(id, fields);
    }
    reader.types.finish();
    Ok(reader.types)
}

impl Reader<'_> {
    fn parse(&self, index: TypeIndex) -> Option<TypeData<'_>> {
        self.finder.find(index).ok()?.parse().ok()
    }

    /// The type the record at `index` describes.
    fn resolve(&mut self, index: TypeIndex) -> TypeId {
        if let Some(&id) = self.seen.get(&index) {
            return id;
        }
        let Some(data) = self.parse(index) else { return VOID };
        // What the record says, with the borrow of the type stream ended.
        enum Record {
            Number(Option<(Base, u64)>, bool),
            Named(Named, String, Vec<u8>, bool, u64, Option<TypeIndex>),
            Pointer(TypeIndex, Option<u64>),
            Same(TypeIndex),
            Array(TypeIndex, u64),
            Function,
            Unknown,
        }
        let record = match data {
            TypeData::Primitive(primitive) => {
                let number = match primitive.kind {
                    PrimitiveKind::Char | PrimitiveKind::RChar | PrimitiveKind::Char8 => Some((Base::Char, 1)),
                    PrimitiveKind::WChar | PrimitiveKind::RChar16 => Some((Base::Char, 2)),
                    PrimitiveKind::RChar32 => Some((Base::Char, 4)),
                    PrimitiveKind::UChar | PrimitiveKind::U8 => Some((Base::Uint, 1)),
                    PrimitiveKind::I8 => Some((Base::Int, 1)),
                    PrimitiveKind::Short | PrimitiveKind::I16 => Some((Base::Int, 2)),
                    PrimitiveKind::UShort | PrimitiveKind::U16 => Some((Base::Uint, 2)),
                    PrimitiveKind::Long | PrimitiveKind::I32 | PrimitiveKind::HRESULT => Some((Base::Int, 4)),
                    PrimitiveKind::ULong | PrimitiveKind::U32 => Some((Base::Uint, 4)),
                    PrimitiveKind::Quad | PrimitiveKind::I64 => Some((Base::Int, 8)),
                    PrimitiveKind::UQuad | PrimitiveKind::U64 => Some((Base::Uint, 8)),
                    PrimitiveKind::Octa | PrimitiveKind::I128 => Some((Base::Int, 16)),
                    PrimitiveKind::UOcta | PrimitiveKind::U128 => Some((Base::Uint, 16)),
                    PrimitiveKind::F16 => Some((Base::Float, 2)),
                    PrimitiveKind::F32 | PrimitiveKind::F32PP => Some((Base::Float, 4)),
                    PrimitiveKind::F64 => Some((Base::Float, 8)),
                    PrimitiveKind::F80 => Some((Base::Float, 10)),
                    PrimitiveKind::F128 => Some((Base::Float, 16)),
                    PrimitiveKind::Bool8 => Some((Base::Bool, 1)),
                    PrimitiveKind::Bool16 => Some((Base::Bool, 2)),
                    PrimitiveKind::Bool32 => Some((Base::Bool, 4)),
                    PrimitiveKind::Bool64 => Some((Base::Bool, 8)),
                    _ => None,
                };
                Record::Number(number, primitive.indirection.is_some())
            }
            TypeData::Class(class) => {
                Record::Named(Named::Struct, class.name.to_string().into_owned(), class.unique_name.unwrap_or(class.name).as_bytes().to_vec(), class.properties.forward_reference(), class.size, class.fields)
            }
            TypeData::Union(union) => {
                Record::Named(Named::Union, union.name.to_string().into_owned(), union.unique_name.unwrap_or(union.name).as_bytes().to_vec(), union.properties.forward_reference(), union.size, Some(union.fields))
            }
            TypeData::Enumeration(enumeration) => {
                let key = enumeration.unique_name.unwrap_or(enumeration.name).as_bytes().to_vec();
                let (name, forward, underlying, fields) = (enumeration.name.to_string().into_owned(), enumeration.properties.forward_reference(), enumeration.underlying_type, enumeration.fields);
                let size = match self.resolve(underlying) {
                    VOID => 4,
                    underlying => self.types.size(underlying),
                };
                Record::Named(Named::Enum, name, key, forward, size, Some(fields))
            }
            // A pointer to a member is an offset, or more than one word for a member function.
            TypeData::Pointer(pointer) => Record::Pointer(pointer.underlying_type, pointer.containing_class.map(|_| u64::from(pointer.attributes.size()))),
            TypeData::Modifier(modifier) => Record::Same(modifier.underlying_type),
            // The one dimension a record has is its size in bytes.
            TypeData::Array(array) => Record::Array(array.element_type, array.dimensions.last().map_or(0, |&bytes| u64::from(bytes))),
            TypeData::Procedure(_) | TypeData::MemberFunction(_) => Record::Function,
            _ => Record::Unknown,
        };
        let id = match record {
            Record::Number(number, indirect) => {
                let number = number.map_or(VOID, |(base, size)| self.types.add(Type::Base { base, size }));
                if indirect { self.types.add(Type::Pointer(number)) } else { number }
            }
            Record::Named(kind, name, key, forward, size, fields) => {
                if let Some(&definition) = self.definitions.get(&key).filter(|&&definition| forward && definition != index) {
                    self.resolve(definition)
                } else {
                    // The compiler's names for unnamed types, such as `<unnamed-tag>`, are not unique.
                    let unnamed = name.starts_with('<') || name.contains("::<unnamed") || name.contains("::<anonymous");
                    let name = if unnamed { self.typedefs.get(&index).cloned().unwrap_or_default() } else { name };
                    let (id, fill) = self.types.named(kind, &name, if forward { 0 } else { size });
                    self.seen.insert(index, id);
                    if let Some(fields) = fields.filter(|_| fill && !forward) {
                        if kind == Named::Enum {
                            let values = self.field_list(fields).into_iter().filter_map(|field| if let TypeData::Enumerate(value) = field { Some(value) } else { None });
                            let values = values.map(|value| {
                                let number = match value.value {
                                    pdb2::Variant::U8(value) => i64::from(value),
                                    pdb2::Variant::U16(value) => i64::from(value),
                                    pdb2::Variant::U32(value) => i64::from(value),
                                    pdb2::Variant::U64(value) => value as i64,
                                    pdb2::Variant::I8(value) => i64::from(value),
                                    pdb2::Variant::I16(value) => i64::from(value),
                                    pdb2::Variant::I32(value) => i64::from(value),
                                    pdb2::Variant::I64(value) => value,
                                };
                                (value.name.to_string().into_owned(), number)
                            });
                            let values = values.collect();
                            self.types.set_values(id, values);
                        } else {
                            self.pending.push((id, fields));
                        }
                    }
                    id
                }
            }
            Record::Pointer(_, Some(size)) => {
                let word = self.types.add(Type::Base { base: Base::Uint, size: self.types.pointer });
                if size > self.types.pointer { self.types.add(Type::Array { element: word, count: size / self.types.pointer }) } else { word }
            }
            Record::Pointer(target, None) => {
                // Entered before its target is read, which may be a function type that takes
                // this very pointer.
                let id = self.types.add(Type::Pointer(VOID));
                self.seen.insert(index, id);
                let target = self.resolve(target);
                self.types.types[id as usize] = Type::Pointer(target);
                id
            }
            Record::Same(target) => self.resolve(target),
            Record::Array(element, bytes) => {
                let element = self.resolve(element);
                let count = bytes.checked_div(self.types.size(element)).unwrap_or(0);
                self.types.add(Type::Array { element, count })
            }
            Record::Function => match self.prototype(index) {
                Some(prototype) => self.types.add(Type::Function(prototype)),
                None => VOID,
            },
            Record::Unknown => VOID,
        };
        self.seen.insert(index, id);
        id
    }

    /// The entries of the field list at `index` and of the lists that continue it.
    fn field_list(&self, index: TypeIndex) -> Vec<TypeData<'_>> {
        let mut fields = Vec::new();
        let mut next = Some(index);
        while let Some(TypeData::FieldList(list)) = next.and_then(|index| self.parse(index)) {
            fields.extend(list.fields);
            next = list.continuation;
        }
        fields
    }

    /// Reads the members and base classes in the field list at `list` into the type `id`.
    fn members(&mut self, id: TypeId, list: TypeIndex) {
        // (name, offset, type) of each, with the type still an index into the stream.
        let mut members: Vec<(String, u64, Option<TypeIndex>)> = Vec::new();
        for field in self.field_list(list) {
            match field {
                TypeData::Member(member) => members.push((member.name.to_string().into_owned(), member.offset, Some(member.field_type))),
                TypeData::BaseClass(base) => members.push((String::from("super_"), u64::from(base.offset), Some(base.base_class))),
                // Where the class that first has virtual functions keeps the pointer to them.
                TypeData::VirtualFunctionTablePointer(_) => members.push((String::from("vftable"), 0, None)),
                _ => {}
            }
        }
        let mut fields = Vec::new();
        for (name, offset, kind) in members {
            let Some(kind) = kind else {
                let pointer = self.types.add(Type::Pointer(VOID));
                fields.push(Field { name, offset, kind: pointer, bits: None });
                continue;
            };
            if let Some(TypeData::Bitfield(bitfield)) = self.parse(kind) {
                let (underlying, position, length) = (bitfield.underlying_type, u64::from(bitfield.position), u32::from(bitfield.length));
                let kind = self.resolve(underlying);
                fields.push(Field { name, offset: offset + position / 8, kind, bits: Some(((position % 8) as u32, length)) });
                continue;
            }
            let kind = self.resolve(kind);
            let name = match self.types.get(kind) {
                Type::Composite { name: base, .. } if name == "super_" => crate::types::base_field(base),
                _ => name,
            };
            fields.push(Field { name, offset, kind, bits: None });
        }
        self.types.set_fields(id, fields);
    }

    /// The prototype the function type at `index` declares.
    fn prototype(&mut self, index: TypeIndex) -> Option<Prototype> {
        let (returns, arguments, this, attributes) = match self.parse(index)? {
            TypeData::Procedure(procedure) => (procedure.return_type, procedure.argument_list, None, procedure.attributes),
            TypeData::MemberFunction(method) => (Some(method.return_type), method.argument_list, method.this_pointer_type, method.attributes),
            _ => return None,
        };
        let TypeData::ArgumentList(list) = self.parse(arguments)? else { return None };
        let mut arguments = list.arguments;
        // A variable argument list ends in an argument of no type.
        let variadic = arguments.last().is_some_and(|last| last.0 == 0);
        arguments.truncate(arguments.len() - usize::from(variadic));
        let convention = match attributes.calling_convention() {
            _ if !self.conventions => None,
            0x00 => Some("__cdecl"),
            0x04 => Some("__fastcall"),
            0x07 => Some("__stdcall"),
            0x0b => Some("__thiscall"),
            _ => None,
        };
        let mut prototype = Prototype { returns: returns.map_or(VOID, |index| self.resolve(index)), params: Vec::new(), variadic, convention };
        if let Some(this) = this {
            let kind = self.resolve(this);
            prototype.params.push((String::from("this"), kind));
        }
        for argument in arguments {
            let kind = self.resolve(argument);
            prototype.params.push((String::new(), kind));
        }
        Some(prototype)
    }
}
