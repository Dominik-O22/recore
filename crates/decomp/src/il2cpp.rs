//! The types of an IL2CPP build's managed program, as the decompiler takes debug information.
//!
//! Each class becomes a struct of its objects: the class record and monitor every object
//! starts with, then each field at its offset, inherited ones first. The class record is a
//! struct of its own, `<class>_c`, holding the class's static fields and its vtable, whose
//! entries are named after the methods in them: a virtual call reads as a call through
//! `this->klass->ToString`. A value type is its fields without a header, an enum the number
//! under it. Each method's prototype takes `this` first where it has one, and last the
//! `MethodInfo *` IL2CPP passes every method. Each usage slot is a global of the type it holds.

use std::collections::HashMap;

use recore::il2cpp::{Il2Cpp, Ty, TypeDef, Usage};

use crate::types::{Base, Field, Function, Global, Named, Prototype, Type, TypeId, Types, VOID};

/// Builds the types of `il2cpp`'s program.
pub fn types(il2cpp: &Il2Cpp) -> Types {
    let mut builder = Builder::new(il2cpp);
    builder.functions();
    builder.globals();
    builder.types.finish();
    builder.types.globals_by_reference = true;
    builder.types
}

struct Builder<'a> {
    il2cpp: &'a Il2Cpp,
    types: Types,
    /// Per type definition: the struct of its objects or values, and that of its class record.
    objects: Vec<TypeId>,
    classes: Vec<TypeId>,
    /// Types already built, by how C# writes them.
    built: HashMap<String, TypeId>,
    method_info: TypeId,
}

impl<'a> Builder<'a> {
    fn new(il2cpp: &'a Il2Cpp) -> Builder<'a> {
        let mut types = Types::new(8);
        let method_info = opaque(&mut types, "Il2CppMethodInfo");
        let mut builder = Builder { il2cpp, types, objects: Vec::new(), classes: Vec::new(), built: HashMap::new(), method_info };
        // Every struct is named first, so that fields can refer to any of them. An enum is the
        // number its one instance field holds, with its members.
        for def in &il2cpp.types {
            // A struct called as one of the engine's own types, as Unity.Mathematics has `uint4`,
            // would be told from it only by a number.
            let name =
                if builder.types.is_taken(&def.name) && !def.namespace.is_empty() { format!("{}.{}", def.namespace, def.name) } else { def.name.clone() };
            let object = match enum_size(def) {
                Some(size) => {
                    let id = builder.types.named(Named::Enum, &name, size).0;
                    builder.types.set_values(id, def.members.clone());
                    id
                }
                None => builder.types.named(Named::Struct, &name, u64::from(def.instance_size)).0,
            };
            builder.objects.push(object);
        }
        for def in &il2cpp.types {
            let size = il2cpp.class_layout.vtable + 16 * def.vtable.len() as u64;
            let class = builder.types.named(Named::Struct, &format!("{}_c", def.name), size).0;
            builder.classes.push(class);
        }
        for index in 0..il2cpp.types.len() {
            builder.fill(index);
        }
        builder
    }

    /// Fills in the fields of type definition `index`'s structs.
    fn fill(&mut self, index: usize) {
        let def: &TypeDef = &self.il2cpp.types[index];
        if enum_size(def).is_some() {
            return;
        }
        let mut fields = Vec::new();
        if !def.is_value_type {
            let class = self.pointer(self.classes[index]);
            let void_pointer = self.pointer(VOID);
            fields.push(Field { name: "klass".into(), offset: 0, kind: class, bits: None });
            fields.push(Field { name: "monitor".into(), offset: 8, kind: void_pointer, bits: None });
        }
        let mut statics = Vec::new();
        for field in &def.fields {
            let Some(offset) = field.offset else { continue };
            let Some(kind) = self.field_type(&field.ty) else {
                continue;
            };
            let member = Field { name: field.name.clone(), offset: u64::from(offset), kind, bits: None };
            if field.is_static { statics.push(member) } else { fields.push(member) }
        }
        fields.sort_by_key(|field| field.offset);
        fields.dedup_by_key(|field| field.offset);
        self.types.set_fields(self.objects[index], fields);

        let layout = self.il2cpp.class_layout;
        let mut members = Vec::new();
        if !statics.is_empty() {
            statics.sort_by_key(|field| field.offset);
            statics.dedup_by_key(|field| field.offset);
            let holder = self.types.named(Named::Struct, &format!("{}_StaticFields", def.name), u64::from(def.static_size)).0;
            self.types.set_fields(holder, statics);
            let pointer = self.pointer(holder);
            members.push(Field { name: "static_fields".into(), offset: layout.static_fields, kind: pointer, bits: None });
        }
        let finished = self.base(Base::Int, 4);
        members.push(Field { name: "cctor_finished".into(), offset: layout.cctor_finished, kind: finished, bits: None });
        // A vtable entry is the method's code, then its `MethodInfo`.
        let code = self.pointer(VOID);
        let info = self.pointer(self.method_info);
        let mut taken: HashMap<String, usize> = HashMap::new();
        for (slot, method) in def.vtable.iter().enumerate() {
            let short = method.as_deref().map_or_else(|| format!("slot{slot}"), short_name);
            let uses = taken.entry(short.clone()).or_default();
            *uses += 1;
            let name = if *uses > 1 { format!("{short}_{uses}") } else { short };
            let at = layout.vtable + 16 * slot as u64;
            members.push(Field { name: format!("{name}_info"), offset: at + 8, kind: info, bits: None });
            members.push(Field { name, offset: at, kind: code, bits: None });
        }
        members.sort_by_key(|field| field.offset);
        self.types.set_fields(self.classes[index], members);
    }

    fn pointer(&mut self, to: TypeId) -> TypeId {
        let key = format!("*{to}");
        if let Some(&id) = self.built.get(&key) {
            return id;
        }
        let id = self.types.add(Type::Pointer(to));
        self.built.insert(key, id);
        id
    }

    fn base(&mut self, base: Base, size: u64) -> TypeId {
        let key = format!("{base:?}{size}");
        if let Some(&id) = self.built.get(&key) {
            return id;
        }
        let id = self.types.add(Type::Base { base, size });
        self.built.insert(key, id);
        id
    }

    /// The type a field or parameter of type `ty` has: an object by a pointer to it, a value by
    /// itself. `None` for a value whose size is not known, such as an instance of a generic
    /// struct, which is left out rather than guessed at.
    fn field_type(&mut self, ty: &Ty) -> Option<TypeId> {
        Some(match ty {
            Ty::Void => VOID,
            Ty::Bool => self.base(Base::Bool, 1),
            Ty::Char => self.base(Base::Char, 2),
            Ty::I8 => self.base(Base::Int, 1),
            Ty::U8 => self.base(Base::Uint, 1),
            Ty::I16 => self.base(Base::Int, 2),
            Ty::U16 => self.base(Base::Uint, 2),
            Ty::I32 => self.base(Base::Int, 4),
            Ty::U32 => self.base(Base::Uint, 4),
            Ty::I64 | Ty::IntPtr => self.base(Base::Int, 8),
            Ty::U64 | Ty::UIntPtr => self.base(Base::Uint, 8),
            Ty::F32 => self.base(Base::Float, 4),
            Ty::F64 => self.base(Base::Float, 8),
            Ty::String => self.object_named("System", "String"),
            Ty::Object => self.object_named("System", "Object"),
            Ty::Def(def) => {
                let index = *def as usize;
                let def = &self.il2cpp.types[index];
                if !def.is_value_type {
                    self.pointer(self.objects[index])
                } else if def.is_enum && enum_size(def).is_none() {
                    return None;
                } else if def.instance_size > 0 || def.is_enum {
                    self.objects[index]
                } else {
                    return None;
                }
            }
            Ty::Generic(def, _) => {
                if self.il2cpp.types[*def as usize].is_value_type {
                    return None;
                }
                let name = self.il2cpp.names.display(ty);
                let declared = match self.built.get(&name) {
                    Some(&id) => id,
                    None => {
                        let id = opaque(&mut self.types, &name);
                        self.built.insert(name, id);
                        id
                    }
                };
                self.pointer(declared)
            }
            Ty::Array(element) => {
                let name = self.il2cpp.names.display(ty);
                if let Some(&id) = self.built.get(&name) {
                    return Some(self.pointer(id));
                }
                // An array object: its header, its bounds, its length and then its elements.
                let element = self.field_type(element).unwrap_or(VOID);
                let element = if element == VOID { self.base(Base::Unknown, 8) } else { element };
                let items = self.types.add(Type::Array { element, count: 0 });
                let (array, _) = self.types.named(Named::Struct, &name, 0x20);
                let void_pointer = self.pointer(VOID);
                let length = self.base(Base::Uint, 8);
                self.types.set_fields(
                    array,
                    vec![
                        Field { name: "klass".into(), offset: 0, kind: void_pointer, bits: None },
                        Field { name: "monitor".into(), offset: 8, kind: void_pointer, bits: None },
                        Field { name: "bounds".into(), offset: 0x10, kind: void_pointer, bits: None },
                        Field { name: "max_length".into(), offset: 0x18, kind: length, bits: None },
                        Field { name: "items".into(), offset: 0x20, kind: items, bits: None },
                    ],
                );
                self.built.insert(name, array);
                self.pointer(array)
            }
            Ty::Pointer(target) | Ty::ByRef(target) => {
                let target = self.field_type(target).unwrap_or(VOID);
                self.pointer(target)
            }
            Ty::Param(_) | Ty::Unknown => self.base(Base::Unknown, 8),
        })
    }

    /// A pointer to the objects of the type definition `namespace.name`, or to nothing known.
    fn object_named(&mut self, namespace: &str, name: &str) -> TypeId {
        // A name types of several namespaces share is qualified.
        let qualified = format!("{namespace}.{name}");
        let found = self.il2cpp.types.iter().position(|def| def.namespace == namespace && (def.name == name || def.name == qualified));
        let target = found.map_or(VOID, |index| self.objects[index]);
        self.pointer(target)
    }

    /// The prototype of every method with code.
    fn functions(&mut self) {
        let il2cpp = self.il2cpp;
        for method in il2cpp.methods.iter().filter(|method| method.addr.is_some()) {
            let owner = &il2cpp.types[method.owner as usize];
            let mut params = Vec::new();
            if !method.is_static {
                params.push(("this".to_string(), self.pointer(self.objects[method.owner as usize])));
            }
            for (name, ty) in &method.params {
                let kind = self.field_type(ty).unwrap_or_else(|| self.base(Base::Unknown, 8));
                params.push((name.clone(), kind));
            }
            let info = self.pointer(self.method_info);
            params.push(("method".to_string(), info));
            let returns = self.field_type(&method.returns).unwrap_or_else(|| self.base(Base::Unknown, 8));
            let prototype = self.types.add(Type::Function(Prototype { returns, params, variadic: false, convention: None }));
            let name = format!("{}.{}", owner.name, method.name);
            self.types.functions.push(Function { addr: method.addr.unwrap_or_default(), name, prototype });
        }
    }

    /// A global for every usage slot, of the type of what it holds once the runtime fills it.
    fn globals(&mut self) {
        let il2cpp = self.il2cpp;
        let names = il2cpp.usage_names();
        let il2cpp_type = opaque(&mut self.types, "Il2CppType");
        let field_info = opaque(&mut self.types, "Il2CppFieldInfo");
        for ((addr, usage), (_, name)) in il2cpp.usages.iter().zip(names) {
            let kind = match usage {
                Usage::Class(Ty::Def(def) | Ty::Generic(def, _)) => self.pointer(self.classes[*def as usize]),
                Usage::Class(_) => self.pointer(VOID),
                Usage::Type(_) => self.pointer(il2cpp_type),
                Usage::Method(_) => self.pointer(self.method_info),
                Usage::Field(_) => self.pointer(field_info),
                Usage::Literal(_) => self.object_named("System", "String"),
            };
            self.types.globals.push(Global { addr: *addr, name, kind });
        }
    }
}

/// The size of the number an enum holds in its one instance field; `None` for another type.
fn enum_size(def: &TypeDef) -> Option<u64> {
    if !def.is_enum {
        return None;
    }
    match def.fields.iter().find(|field| !field.is_static)?.ty {
        Ty::Bool | Ty::I8 | Ty::U8 => Some(1),
        Ty::Char | Ty::I16 | Ty::U16 => Some(2),
        Ty::I32 | Ty::U32 => Some(4),
        Ty::I64 | Ty::U64 => Some(8),
        _ => None,
    }
}

/// A struct that is only declared: what the code points to and the metadata does not lay out.
fn opaque(types: &mut Types, name: &str) -> TypeId {
    types.named(Named::Struct, name, 0).0
}

/// A vtable entry's name: the method without its class, `ToString` for `Object.ToString`.
fn short_name(method: &str) -> String {
    let mut depth = 0;
    let mut cut = 0;
    for (at, c) in method.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            '.' if depth == 0 => cut = at + 1,
            _ => {}
        }
    }
    method[cut..].to_string()
}
