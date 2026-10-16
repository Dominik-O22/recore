//! Struct recovery inside the decompiler. When the engine starts typing a function, the shim
//! hands over the objects the function's parameters point to, each as the set of values the
//! engine will give one type, with the accesses made through them. [`Registry::plan`] decides
//! which struct, if any, each object gets. The shim defines the structs and locks them on the
//! parameters, and the engine's own propagation prints the fields.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CStr, CString, c_char, c_void};

use recore::structs::{Field, FieldType, Layout, Refusal, Slot, auto_name};

use crate::ffi;
use crate::types::{self, Base, Named, Type, Types, Writer};

/// A read or a write through a member of an object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Access {
    /// From the object's base, which is where its first root points.
    pub offset: i64,
    pub size: u32,
    /// What the engine makes of the value from the operations around it: never a struct.
    pub ty: FieldType,
}

/// One object: every value the engine will give one pointer type, as one function uses it.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Object {
    /// The parameters that point to it, each with its offset from the base.
    pub roots: Vec<(Slot, i64)>,
    /// The lowest and highest offset any member points to, accessed or not.
    pub span: (i64, i64),
    pub accesses: Vec<Access>,
    /// Steps between elements: loop steps, and the factors of indexes.
    pub strides: Vec<u64>,
    /// Fields that hold pointers to other objects: offset, index into [`Evidence::objects`].
    pub points_to: Vec<(i64, usize)>,
    /// A member has a locked type.
    pub locked: bool,
    /// A member is in global memory.
    pub global: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Evidence {
    pub function: u64,
    /// Bytes in a pointer.
    pub pointer: u32,
    pub objects: Vec<Object>,
}

/// A struct a plan uses, with whether it is the element of an array the code steps through.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Planned {
    pub name: String,
    pub layout: Layout,
    pub array: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    /// Per object, in [`Evidence::objects`] order: the name of its struct, or why it has none.
    pub decisions: Vec<Result<String, Refusal>>,
    pub structs: Vec<Planned>,
    /// Whether the structs are new to the engine. A plan either defines all of its structs or
    /// finds all of them defined as they are.
    pub new: bool,
}

/// What the session's engine holds. Lives as long as the session and is used only on its
/// thread, also from inside a decompilation through the shim's hook.
#[derive(Default)]
pub(crate) struct Registry {
    /// Every struct defined in the engine, by name. A name is defined once.
    defined: HashMap<String, Layout>,
    /// The auto name each defined struct stands for, by name.
    bases: HashMap<String, String>,
    /// Auto names of structs that wrapped in the output. Not recovered again this session.
    wrapped: HashSet<String>,
    /// The number the engine knows the next struct by.
    next_id: u64,
    /// What the last plan handed the shim, which reads it until the next.
    out: Out,
}

/// The buffers an [`ffi::RdPlan`] points into. A `CString` keeps its bytes in place when it
/// moves, so the pointers stay good as long as the strings are kept.
#[derive(Default)]
struct Out {
    xml: Option<CString>,
    _names: Vec<Option<CString>>,
    name_ptrs: Vec<*const c_char>,
    recovered: Vec<CString>,
    recovered_ptrs: Vec<*const c_char>,
    arrays: Vec<u8>,
}

/// Numbers above those any table of debug information gives its types.
const FIRST_ID: u64 = 1 << 40;

impl Registry {
    /// Pure policy: the struct for each object of one function.
    pub(crate) fn plan(&mut self, evidence: &Evidence) -> Plan {
        let pointer = evidence.pointer;
        let mut decisions: Vec<Result<(Layout, bool), Refusal>> = evidence.objects.iter().map(|object| shape(object)).collect();
        // Names follow pointers out from the parameters, through recovered structs only: a
        // struct reached otherwise would be given to nothing.
        let mut paths: Vec<Option<(Slot, Vec<u64>)>> = vec![None; decisions.len()];
        let mut queue = Vec::new();
        for (index, object) in evidence.objects.iter().enumerate() {
            if let (Some((slot, _)), Ok(_)) = (object.roots.first(), &decisions[index]) {
                paths[index] = Some((slot.clone(), Vec::new()));
                queue.push(index);
            }
        }
        let mut at = 0;
        while at < queue.len() {
            let index = queue[at];
            at += 1;
            let (slot, path) = paths[index].clone().expect("queued with a path");
            if self.wrapped.contains(&auto_name(evidence.function, &slot, &path)) {
                decisions[index] = Err(Refusal::Wrapped);
                continue;
            }
            let Ok((_, array)) = &decisions[index] else { continue };
            let stride = array.then(|| evidence.objects[index].strides[0] as i64);
            let mut fields: Vec<(u64, usize)> = evidence.objects[index].points_to.iter().map(|&(offset, child)| (reduced(offset, stride), child)).collect();
            fields.sort();
            for (offset, child) in fields {
                if paths[child].is_none() && decisions[child].is_ok() {
                    paths[child] = Some((slot.clone(), [path.as_slice(), &[offset]].concat()));
                    queue.push(child);
                }
            }
        }
        let names: Vec<Option<String>> = paths.iter().zip(&decisions).map(|(path, decision)| {
            let (slot, path) = path.as_ref().filter(|_| decision.is_ok())?;
            Some(auto_name(evidence.function, slot, path))
        }).collect();
        for (decision, name) in decisions.iter_mut().zip(&names) {
            if decision.is_ok() && name.is_none() {
                *decision = Err(Refusal::NoRoot);
            }
        }
        // A field that holds pointers to one recovered object points to its struct.
        for index in 0..decisions.len() {
            let Ok((layout, array)) = &decisions[index] else { continue };
            let stride = array.then(|| evidence.objects[index].strides[0] as i64);
            let mut targets: BTreeMap<u64, HashSet<&str>> = BTreeMap::new();
            for &(offset, child) in &evidence.objects[index].points_to {
                if let Some(name) = &names[child] {
                    targets.entry(reduced(offset, stride)).or_default().insert(name);
                }
            }
            let mut layout = layout.clone();
            for (offset, targets) in targets {
                let pointer_sized = layout.fields().get(&offset).is_some_and(|field| field.size == pointer);
                if let (true, [target]) = (pointer_sized, targets.into_iter().collect::<Vec<_>>().as_slice()) {
                    layout.set_type(offset, FieldType::Struct(target.to_string()));
                }
            }
            decisions[index] = Ok((layout, *array));
        }

        let based: Vec<(String, Layout, bool)> = decisions.iter().zip(&names).filter_map(|(decision, name)| Some((name.clone()?, decision.as_ref().ok()?.0.clone(), decision.as_ref().ok()?.1))).collect();
        // The engine cannot redefine a type. Struct names taken with other layouts, as by an
        // earlier decompilation of the function with other callee prototypes, make every
        // struct of the plan take the next free version.
        let (version, new) = self.version(&based);
        let structs: Vec<Planned> = based.into_iter().map(|(name, layout, array)| Planned { name: versioned(&name, version), layout: layout.renamed(|target| versioned(target, version)), array }).collect();
        if new {
            for (planned, base) in structs.iter().zip(names.iter().flatten()) {
                self.defined.insert(planned.name.clone(), planned.layout.clone());
                self.bases.insert(planned.name.clone(), base.clone());
            }
        }
        let decisions = decisions.into_iter().zip(names).map(|(decision, name)| decision.map(|_| versioned(&name.expect("named when kept"), version))).collect();
        Plan { decisions, structs, new }
    }

    /// The version of the names that `structs` can take, and whether they are new to the
    /// engine: all of them are, or all are defined with these layouts already. Names are
    /// finitely many, so a version that is free comes.
    fn version(&self, structs: &[(String, Layout, bool)]) -> (u32, bool) {
        if structs.is_empty() {
            return (1, false);
        }
        for version in 1.. {
            let defined: Vec<Option<bool>> = structs.iter().map(|(name, layout, _)| self.defined.get(&versioned(name, version)).map(|defined| *defined == layout.renamed(|target| versioned(target, version)))).collect();
            if defined.iter().all(Option::is_none) {
                return (version, true);
            }
            if defined.iter().all(|defined| *defined == Some(true)) {
                return (version, false);
            }
        }
        unreachable!("the loop returns")
    }

    /// The struct `name` wrapped in the output. What it stands for is not recovered again.
    pub(crate) fn wrapped(&mut self, name: &str) {
        if let Some(base) = self.bases.get(name) {
            self.wrapped.insert(base.clone());
        }
    }

    /// The engine XML that defines `structs`, numbered after every struct defined before.
    fn xml(&mut self, pointer: u32, structs: &[Planned]) -> String {
        let mut table = Types::new(u64::from(pointer));
        let ids: HashMap<&str, types::TypeId> = structs.iter().map(|planned| (planned.name.as_str(), table.named(Named::Struct, &planned.name, planned.layout.size()).0)).collect();
        for planned in structs {
            let fields = planned.layout.fields().iter().map(|(&offset, field)| {
                let kind = match &field.ty {
                    FieldType::Struct(target) => Type::Pointer(ids[target.as_str()]),
                    number => number_type(&mut table, number, field.size),
                };
                types::Field { name: format!("field_0x{offset:x}"), offset, kind: table.add(kind), bits: None }
            });
            let fields = fields.collect();
            table.set_fields(ids[planned.name.as_str()], fields);
        }
        let first_id = FIRST_ID + self.next_id;
        self.next_id += table.types.len() as u64;
        let mut writer = Writer::numbered_from(&table, first_id);
        for planned in structs {
            writer.named(ids[planned.name.as_str()]);
        }
        writer.take().unwrap_or_default()
    }
}

/// An offset into an element of `stride` bytes, or as it is without one.
fn reduced(offset: i64, stride: Option<i64>) -> u64 {
    stride.map_or(offset, |stride| offset.rem_euclid(stride)) as u64
}

fn versioned(name: &str, version: u32) -> String {
    if version == 1 { name.to_string() } else { format!("{name}_v{version}") }
}

/// The engine type of a number field of `size` bytes. A size the engine has no number of is
/// bytes of unknown use.
fn number_type(table: &mut Types, ty: &FieldType, size: u32) -> Type {
    let base = match ty {
        FieldType::Int => Base::Int,
        FieldType::Uint => Base::Uint,
        FieldType::Float => Base::Float,
        FieldType::Bool => Base::Bool,
        FieldType::Unknown | FieldType::Struct(_) => Base::Unknown,
    };
    let known = match base {
        Base::Float => matches!(size, 4 | 8 | 10 | 16),
        Base::Bool => size == 1,
        _ => matches!(size, 1 | 2 | 4 | 8),
    };
    if known {
        return Type::Base { base, size: u64::from(size) };
    }
    let byte = table.add(Type::Base { base: Base::Unknown, size: 1 });
    Type::Array { element: byte, count: u64::from(size) }
}

/// The layout of one object, with no field pointing to a struct yet, and whether it is the
/// element of an array; or why it gets none.
fn shape(object: &Object) -> Result<(Layout, bool), Refusal> {
    if object.locked {
        return Err(Refusal::Locked);
    }
    if object.global {
        return Err(Refusal::Global);
    }
    if object.roots.iter().any(|&(_, offset)| offset != 0) {
        return Err(Refusal::IntoMiddle);
    }
    let mut strides = object.strides.clone();
    strides.sort_unstable();
    strides.dedup();
    let stride = match strides.as_slice() {
        [] => None,
        &[stride] if stride > 0 && stride < 1 << 20 => Some(stride as i64),
        _ => return Err(Refusal::Stride),
    };
    let ends = object.accesses.iter().map(|access| access.offset + i64::from(access.size));
    let size = match stride {
        Some(stride) => {
            if object.accesses.iter().any(|access| access.offset.rem_euclid(stride) + i64::from(access.size) > stride) {
                return Err(Refusal::Stride);
            }
            stride
        }
        None => {
            if object.span.0 < 0 || object.accesses.iter().any(|access| access.offset < 0) {
                return Err(Refusal::IntoMiddle);
            }
            // Past every member, so that no offset the code adds reaches the next element.
            ends.chain([object.span.1 + 1]).max().unwrap_or(0)
        }
    };
    // Accesses that start alike are one field, the widest; others print as a cast of it.
    let mut fields: BTreeMap<u64, Field> = BTreeMap::new();
    for access in &object.accesses {
        let field = Field { size: access.size, ty: access.ty.clone() };
        match fields.entry(reduced(access.offset, stride)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(field);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let known = entry.get_mut();
                if field.size > known.size {
                    *known = field;
                } else if field.size == known.size && field.ty != known.ty {
                    known.ty = FieldType::Unknown;
                }
            }
        }
    }
    Ok((Layout::new(size as u64, fields)?, stride.is_some()))
}

/// Reads what the shim hands over.
///
/// # Safety
/// `raw` and every array it points to are valid for the call, as the shim's hook keeps them.
unsafe fn evidence(raw: &ffi::RdEvidence) -> Evidence {
    let mut objects: Vec<Object> = unsafe { crate::slice(raw.objects, raw.object_count) }
        .iter()
        .map(|object| Object { span: (object.low, object.high), locked: object.locked != 0, global: object.global != 0, ..Default::default() })
        .collect();
    for root in unsafe { crate::slice(raw.roots, raw.root_count) } {
        let slot = if root.register.is_null() { Slot::Stack(root.stack) } else { Slot::Register(unsafe { CStr::from_ptr(root.register) }.to_string_lossy().into_owned()) };
        objects[root.object as usize].roots.push((slot, root.offset));
    }
    for access in unsafe { crate::slice(raw.accesses, raw.access_count) } {
        let ty = match access.kind {
            1 => FieldType::Int,
            2 => FieldType::Uint,
            3 => FieldType::Float,
            4 => FieldType::Bool,
            _ => FieldType::Unknown,
        };
        objects[access.object as usize].accesses.push(Access { offset: access.offset, size: access.size, ty });
    }
    for link in unsafe { crate::slice(raw.links, raw.link_count) } {
        objects[link.object as usize].points_to.push((link.offset, link.child as usize));
    }
    for stride in unsafe { crate::slice(raw.strides, raw.stride_count) } {
        objects[stride.object as usize].strides.push(stride.stride);
    }
    Evidence { function: raw.function, pointer: raw.pointer, objects }
}

/// The shim's plan hook. `ctx` is the session's [`Registry`]; what `out` points to stays valid
/// until the next call. Returns 0, leaving every object to the engine, on a panic.
pub(crate) extern "C" fn plan_hook(ctx: *mut c_void, raw: *const ffi::RdEvidence, out: *mut ffi::RdPlan) -> i32 {
    std::panic::catch_unwind(|| {
        // SAFETY: the shim calls this only from inside `rd_decompile`, while `Session` holds
        // the registry behind a pointer it touches nowhere else, with live arguments.
        let (registry, raw, out) = unsafe { (&mut *(ctx as *mut Registry), &*raw, &mut *out) };
        let evidence = unsafe { evidence(raw) };
        let plan = registry.plan(&evidence);
        let xml = if plan.new && !plan.structs.is_empty() { Some(registry.xml(evidence.pointer, &plan.structs)) } else { None };
        let text = |text: &str| CString::new(text).expect("names and XML hold no NUL");
        let names: Vec<Option<CString>> = plan.decisions.iter().map(|decision| decision.as_ref().ok().map(|name| text(name))).collect();
        let recovered: Vec<CString> = plan.structs.iter().map(|planned| text(&planned.name)).collect();
        registry.out = Out {
            xml: xml.map(|xml| text(&xml)),
            name_ptrs: names.iter().map(|name| name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr())).collect(),
            _names: names,
            recovered_ptrs: recovered.iter().map(|name| name.as_ptr()).collect(),
            recovered,
            arrays: plan.structs.iter().map(|planned| planned.array.into()).collect(),
        };
        let kept = &registry.out;
        *out = ffi::RdPlan {
            xml: kept.xml.as_ref().map_or(std::ptr::null(), |xml| xml.as_ptr()),
            names: kept.name_ptrs.as_ptr(),
            recovered: kept.recovered_ptrs.as_ptr(),
            arrays: kept.arrays.as_ptr(),
            recovered_count: kept.recovered.len(),
        };
        1
    })
    .unwrap_or(0)
}

/// The shim's hook for a struct that wrapped in the output.
pub(crate) extern "C" fn wrapped_hook(ctx: *mut c_void, name: *const c_char) {
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: as for `plan_hook`.
        let (registry, name) = unsafe { (&mut *(ctx as *mut Registry), CStr::from_ptr(name)) };
        registry.wrapped(&name.to_string_lossy());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(offset: i64, size: u32, ty: FieldType) -> Access {
        Access { offset, size, ty }
    }

    /// An object `RDI` points to, reading 4-byte numbers at each offset.
    fn object(offsets: &[i64]) -> Object {
        let accesses = offsets.iter().map(|&offset| access(offset, 4, FieldType::Int)).collect();
        Object { roots: vec![(Slot::Register("RDI".into()), 0)], span: (0, 0), accesses, ..Default::default() }
    }

    fn plan(objects: Vec<Object>) -> Plan {
        Registry::default().plan(&Evidence { function: 0x401000, pointer: 8, objects })
    }

    fn layout(fields: &[(u64, u32, FieldType)], size: u64) -> Layout {
        Layout::new(size, fields.iter().map(|(offset, size, ty)| (*offset, Field { size: *size, ty: ty.clone() })).collect()).unwrap()
    }

    #[test]
    fn a_parameter_gets_the_fields_read_through_it() {
        let mut fields = object(&[0, 8]);
        fields.accesses.push(access(8, 2, FieldType::Uint));
        let plan = plan(vec![fields]);
        assert_eq!(plan.decisions, [Ok("S_401000_RDI".to_string())]);
        assert_eq!(plan.structs, [Planned { name: "S_401000_RDI".into(), layout: layout(&[(0, 4, FieldType::Int), (8, 4, FieldType::Int)], 12), array: false }]);
        assert!(plan.new);
    }

    #[test]
    fn a_struct_reaches_past_every_pointer_into_it() {
        let mut end = object(&[0, 4]);
        end.span = (0, 0x20);
        assert_eq!(plan(vec![end]).structs[0].layout.size(), 0x21);
    }

    #[test]
    fn objects_the_engine_could_not_print_are_refused() {
        let mut middle = object(&[0, 4]);
        middle.span = (-8, 0);
        let mut second_root = object(&[0, 4]);
        second_root.roots.push((Slot::Register("RSI".into()), 8));
        let mut strides = object(&[0, 4]);
        strides.strides = vec![12, 16];
        let mut past_stride = object(&[0, 10]);
        past_stride.strides = vec![12];
        let mut locked = object(&[0, 4]);
        locked.locked = true;
        let mut global = object(&[0, 4]);
        global.global = true;
        let decisions = plan(vec![object(&[0, 2]), object(&[0]), object(&[]), middle, second_root, strides, past_stride, locked, global]).decisions;
        let refusals = [Refusal::Overlap, Refusal::Primitive, Refusal::Unused, Refusal::IntoMiddle, Refusal::IntoMiddle, Refusal::Stride, Refusal::Stride, Refusal::Locked, Refusal::Global];
        assert_eq!(decisions, refusals.map(Err));
    }

    #[test]
    fn an_array_of_structs_is_one_element() {
        let mut points = object(&[0x18, 0x20, 0x24]);
        points.strides = vec![12, 12];
        let plan = plan(vec![points]);
        assert_eq!(plan.structs[0].layout, layout(&[(0, 4, FieldType::Int), (8, 4, FieldType::Int)], 12));
        assert!(plan.structs[0].array);
    }

    #[test]
    fn pointer_fields_name_the_structs_they_point_to() {
        let mut list = object(&[0]);
        list.accesses.push(access(8, 8, FieldType::Unknown));
        list.accesses.push(access(0x10, 8, FieldType::Unknown));
        // The field at 8 points back to the list itself, the one at 0x10 to another object.
        list.points_to = vec![(8, 0), (0x10, 1)];
        let mut session = object(&[4, 8]);
        session.roots.clear();
        let mut orphan = object(&[0, 4]);
        orphan.roots.clear();
        let plan = plan(vec![list, session, orphan]);
        assert_eq!(plan.decisions, [Ok("S_401000_RDI".to_string()), Ok("S_401000_RDI_10".to_string()), Err(Refusal::NoRoot)]);
        let fields = plan.structs[0].layout.fields();
        assert_eq!((&fields[&8].ty, &fields[&0x10].ty), (&FieldType::Struct("S_401000_RDI".into()), &FieldType::Struct("S_401000_RDI_10".into())));
    }

    #[test]
    fn a_name_taken_with_another_layout_moves_every_struct_on() {
        let mut registry = Registry::default();
        let evidence = |offsets: &[i64]| {
            let mut parent = object(offsets);
            parent.accesses.push(access(0x10, 8, FieldType::Unknown));
            parent.points_to = vec![(0x10, 1)];
            let mut child = object(&[0, 4]);
            child.roots.clear();
            Evidence { function: 0x401000, pointer: 8, objects: vec![parent, child] }
        };
        assert!(registry.plan(&evidence(&[0, 4])).new);
        let again = registry.plan(&evidence(&[0, 4]));
        assert_eq!((again.decisions[0].clone(), again.new), (Ok("S_401000_RDI".to_string()), false));
        let changed = registry.plan(&evidence(&[0, 8]));
        assert_eq!(changed.decisions, [Ok("S_401000_RDI_v2".to_string()), Ok("S_401000_RDI_10_v2".to_string())]);
        assert_eq!(changed.structs[0].layout.fields()[&0x10].ty, FieldType::Struct("S_401000_RDI_10_v2".into()));
        assert!(changed.new);
    }

    #[test]
    fn a_struct_that_wrapped_is_not_recovered_again() {
        let mut registry = Registry::default();
        let evidence = Evidence { function: 0x401000, pointer: 8, objects: vec![object(&[0, 4])] };
        let name = registry.plan(&evidence).decisions[0].clone().unwrap();
        registry.wrapped(&name);
        assert_eq!(registry.plan(&evidence).decisions, [Err(Refusal::Wrapped)]);
    }

    #[test]
    fn the_engine_xml_defines_each_struct_once_with_exact_offsets() {
        let mut registry = Registry::default();
        let mut list = object(&[0]);
        list.accesses.push(access(8, 8, FieldType::Unknown));
        list.accesses.push(access(0x10, 16, FieldType::Unknown));
        list.points_to = vec![(8, 0)];
        let plan = registry.plan(&Evidence { function: 0x401000, pointer: 8, objects: vec![list] });
        let xml = registry.xml(8, &plan.structs);
        let id = FIRST_ID + 1;
        assert_eq!(
            xml,
            format!(
                r#"<debug>
<type name="S_401000_RDI" id="{id}" metatype="struct" size="32" incomplete="true"/>
<type name="S_401000_RDI" id="{id}" metatype="struct" size="32">
<field name="field_0x0" offset="0"><typeref name="int4"/></field>
<field name="field_0x8" offset="8"><type metatype="ptr" size="8" wordsize="1"><typeref name="S_401000_RDI" id="{id}"/></type></field>
<field name="field_0x10" offset="16"><type metatype="array" size="16" arraysize="16"><typeref name="undefined1"/></type></field>
</type>
</debug>
"#
            )
        );
    }
}
