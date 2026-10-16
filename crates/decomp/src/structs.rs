//! Struct recovery inside the decompiler. When the engine starts typing a function, the shim
//! hands over the objects the function's parameters point to, each as the set of values the
//! engine will give one type, with the accesses made through them and the calls they are
//! handed to. [`Registry::plan`] decides which struct, if any, each object gets: a named one
//! that a holder says the object is and that fits it, or one recovered from the accesses. The
//! shim defines the structs and locks them on the parameters, and the engine's own
//! propagation prints the fields.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CStr, CString, c_char, c_void};

use recore::structs::{Field, FieldType, Layout, Recovered, Refusal, Slot, auto_name, field_name};
use serde::{Deserialize, Serialize};

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
    /// Members handed to calls: the callee, the slot it takes the member in, and the member's
    /// offset from the base.
    pub passed: Vec<(u64, Slot, i64)>,
    /// A member has a locked type.
    pub locked: bool,
    /// A member is in global memory.
    pub global: bool,
    /// A member is used as a number: compared with a constant other than null, or added to
    /// the address of a table.
    pub number: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Evidence {
    pub function: u64,
    /// Bytes in a pointer.
    pub pointer: u32,
    pub objects: Vec<Object>,
}

/// A struct a plan recovers, with whether it is the element of an array the code steps through.
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
    /// The structs the plan recovers.
    pub structs: Vec<Planned>,
    /// Whether the recovered structs are new to the engine. A plan either defines all of them
    /// or finds all of them defined as they are.
    pub new: bool,
    /// The named structs the plan puts on objects, each with whether one of those is stepped
    /// through as an array.
    pub named: Vec<(String, bool)>,
    /// Lines for the function's warning header.
    pub warnings: Vec<String>,
}

/// What struct recovery made of one object of a function, for an agent who asks why a pointer
/// prints as it does.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ObjectReport {
    /// Where the function is passed pointers to it.
    pub slots: Vec<Slot>,
    /// The struct of the same function whose field points to it, and the field's offset.
    pub field: Option<(String, u64)>,
    /// The struct it got, or why it got none.
    pub decision: Result<String, Refusal>,
    /// Its struct is one that has a name in the edits.
    pub named: bool,
    /// Reads and writes through it.
    pub accesses: usize,
    /// The lowest offset they touch and the end of the highest.
    pub span: (i64, i64),
}

/// What struct recovery made of one function's objects, as of its last decompilation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct StructReport {
    pub objects: Vec<ObjectReport>,
    pub warnings: Vec<String>,
}

/// What the edits ask of the engine: see [`Registry::converge`].
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Converge {
    /// A struct the engine holds has another layout in the edits, and the engine cannot
    /// redefine a type. Nothing else was done.
    pub restart: bool,
    /// The structs new to the engine.
    pub xml: Option<String>,
    /// Fields of structs the engine holds to rename: struct, offset, name.
    pub renames: Vec<(String, u64, String)>,
}

/// One function's last plan, kept for [`Registry::recovered`] and the `structs` tool.
struct Last {
    report: StructReport,
    /// Per object, the slot and path of pointer fields its recovered name says, if any.
    paths: Vec<Option<(Slot, Vec<u64>)>>,
}

/// What the session's engine holds. Lives as long as the session and is used only on its
/// thread, also from inside a decompilation through the shim's hook.
#[derive(Default)]
pub(crate) struct Registry {
    /// Every struct defined in the engine, by name, with the number the engine knows it by.
    /// A name is defined once.
    defined: HashMap<String, (Layout, u64)>,
    /// The structs of the edits, by name.
    named: BTreeMap<String, Layout>,
    /// The structs the edits say functions are passed pointers to: function, slot, name.
    holders: BTreeMap<u64, BTreeMap<Slot, String>>,
    /// Recovered names of objects whose struct wrapped in the output. Not given one again
    /// this session.
    wrapped: HashSet<String>,
    last: HashMap<u64, Last>,
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
    used: Vec<CString>,
    used_ptrs: Vec<*const c_char>,
    arrays: Vec<u8>,
    warnings: Vec<CString>,
    warning_ptrs: Vec<*const c_char>,
}

/// Numbers above those any table of debug information gives its types.
const FIRST_ID: u64 = 1 << 40;

/// What a plan makes of one object, on the way to its decision.
#[derive(Debug, Clone)]
enum Choice {
    /// A layout from its accesses, and whether it is an array's element.
    Recover(Layout, bool),
    /// A named struct a holder says it is, which fits it.
    Named(String),
    /// The named struct a field of a named struct says it is.
    Typed(String),
    Refused(Refusal),
}

impl Registry {
    /// Pure policy: the struct for each object of one function.
    pub(crate) fn plan(&mut self, evidence: &Evidence) -> Plan {
        let function = evidence.function;
        let objects = &evidence.objects;
        let mut choices: Vec<Choice> = objects.iter().map(|object| shape(object).map_or_else(Choice::Refused, |(layout, array)| Choice::Recover(layout, array))).collect();
        let mut warnings = Vec::new();
        // A named struct goes where a holder says, if the code uses the object as it lays out.
        for (index, object) in objects.iter().enumerate() {
            if matches!(choices[index], Choice::Refused(Refusal::Locked | Refusal::Global | Refusal::Number)) {
                continue;
            }
            match self.candidates(function, object).as_slice() {
                [] => {}
                [name] => match self.fits(evidence, index, name, &mut HashSet::new()) {
                    Ok(()) => choices[index] = Choice::Named(name.clone()),
                    Err(why) => warnings.push(format!("{name} does not fit what {} points to, which gets a struct of its own: {why}", place(object))),
                },
                _ => choices[index] = Choice::Refused(Refusal::NamedConflict),
            }
        }
        // What fields of named structs point to has the type they say.
        let mut queue: Vec<usize> = (0..objects.len()).filter(|&index| matches!(choices[index], Choice::Named(_))).collect();
        while let Some(index) = queue.pop() {
            let (Choice::Named(name) | Choice::Typed(name)) = &choices[index] else { continue };
            let Some(layout) = self.named.get(name) else { continue };
            let stride = (!objects[index].strides.is_empty()).then_some(layout.size() as i64);
            for &(offset, child) in &objects[index].points_to {
                let Some(FieldType::Struct(target)) = layout.fields().get(&reduced(offset, stride)).map(|field| &field.ty) else { continue };
                if !matches!(choices[child], Choice::Named(_) | Choice::Typed(_)) {
                    choices[child] = Choice::Typed(target.clone());
                    queue.push(child);
                }
            }
        }
        // Recovered names follow pointers out from the parameters, through recovered structs
        // only: a struct reached otherwise would be given to nothing.
        let mut paths: Vec<Option<(Slot, Vec<u64>)>> = objects.iter().map(|object| object.roots.first().map(|(slot, _)| (slot.clone(), Vec::new()))).collect();
        let mut queue: Vec<usize> = (0..objects.len()).filter(|&index| paths[index].is_some() && matches!(choices[index], Choice::Recover(..))).collect();
        let mut at = 0;
        while at < queue.len() {
            let index = queue[at];
            at += 1;
            let (slot, path) = paths[index].clone().expect("queued with a path");
            if self.wrapped.contains(&auto_name(function, &slot, &path)) {
                choices[index] = Choice::Refused(Refusal::Wrapped);
                continue;
            }
            let Choice::Recover(_, array) = &choices[index] else { continue };
            let stride = array.then(|| objects[index].strides[0] as i64);
            let mut fields: Vec<(u64, usize)> = objects[index].points_to.iter().map(|&(offset, child)| (reduced(offset, stride), child)).collect();
            fields.sort();
            for (offset, child) in fields {
                if paths[child].is_none() && matches!(choices[child], Choice::Recover(..)) {
                    paths[child] = Some((slot.clone(), [path.as_slice(), &[offset]].concat()));
                    queue.push(child);
                }
            }
        }
        // A named object whose struct wrapped is left to the engine too.
        for (choice, path) in choices.iter_mut().zip(&paths) {
            if let (Choice::Named(_), Some((slot, path))) = (&choice, path)
                && self.wrapped.contains(&auto_name(function, slot, path))
            {
                *choice = Choice::Refused(Refusal::Wrapped);
            }
        }
        let names: Vec<Option<String>> = choices
            .iter()
            .zip(&paths)
            .map(|(choice, path)| match choice {
                Choice::Recover(..) => path.as_ref().map(|(slot, path)| auto_name(function, slot, path)),
                Choice::Named(name) | Choice::Typed(name) => Some(name.clone()),
                Choice::Refused(_) => None,
            })
            .collect();
        for (choice, name) in choices.iter_mut().zip(&names) {
            if matches!(choice, Choice::Recover(..)) && name.is_none() {
                *choice = Choice::Refused(Refusal::NoRoot);
            }
        }
        // A field that holds pointers to one object with a struct points to that struct.
        for (object, choice) in objects.iter().zip(choices.iter_mut()) {
            let Choice::Recover(layout, array) = choice else { continue };
            let stride = array.then(|| object.strides[0] as i64);
            let mut targets: BTreeMap<u64, HashSet<&str>> = BTreeMap::new();
            for &(offset, child) in &object.points_to {
                if let Some(name) = &names[child] {
                    targets.entry(reduced(offset, stride)).or_default().insert(name);
                }
            }
            for (offset, targets) in targets {
                let pointer_sized = layout.fields().get(&offset).is_some_and(|field| field.size == evidence.pointer);
                if let (true, [target]) = (pointer_sized, targets.into_iter().collect::<Vec<_>>().as_slice()) {
                    layout.set_type(offset, FieldType::Struct(target.to_string()));
                }
            }
        }

        let based: Vec<(String, Layout, bool)> = choices
            .iter()
            .zip(&names)
            .filter_map(|(choice, name)| match choice {
                Choice::Recover(layout, array) => Some((name.clone()?, layout.clone(), *array)),
                _ => None,
            })
            .collect();
        let recovered: HashSet<String> = based.iter().map(|(name, ..)| name.clone()).collect();
        let rename = |version: u32| {
            let recovered = &recovered;
            move |target: &str| if recovered.contains(target) { versioned(target, version) } else { target.to_string() }
        };
        // The engine cannot redefine a type. Struct names taken with other layouts, as by an
        // earlier decompilation of the function with other callee prototypes, make every
        // struct of the plan take the next free version.
        let version = self.version(&based, &rename);
        let new = !based.is_empty() && based.iter().all(|(name, ..)| !self.defined.contains_key(&versioned(name, version)));
        let structs: Vec<Planned> = based.iter().map(|(name, layout, array)| Planned { name: versioned(name, version), layout: layout.renamed(rename(version)), array: *array }).collect();
        let decisions: Vec<Result<String, Refusal>> = choices
            .iter()
            .zip(&names)
            .map(|(choice, name)| match choice {
                Choice::Recover(..) => Ok(versioned(name.as_ref().expect("named when kept"), version)),
                Choice::Named(name) | Choice::Typed(name) => Ok(name.clone()),
                Choice::Refused(refusal) => Err(*refusal),
            })
            .collect();
        let mut named: BTreeMap<String, bool> = BTreeMap::new();
        for (object, choice) in objects.iter().zip(&choices) {
            if let Choice::Named(name) | Choice::Typed(name) = choice {
                *named.entry(name.clone()).or_default() |= !object.strides.is_empty();
            }
        }
        let report = report(objects, &choices, &decisions, &warnings);
        self.last.insert(function, Last { report, paths });
        Plan { decisions, structs, new, named: named.into_iter().collect(), warnings }
    }

    /// The named structs that holders say `object` is: the function's own, for the slots that
    /// point to the object's base, and the callees', for the slots they are handed it in.
    fn candidates(&self, function: u64, object: &Object) -> Vec<String> {
        let held = |function: u64, slot: &Slot| self.holders.get(&function)?.get(slot).filter(|name| self.named.contains_key(*name)).cloned();
        let own = object.roots.iter().filter(|(_, offset)| *offset == 0).filter_map(|(slot, _)| held(function, slot));
        let passed = object.passed.iter().filter(|(_, _, offset)| *offset == 0).filter_map(|(callee, slot, _)| held(*callee, slot));
        let mut names: Vec<String> = own.chain(passed).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Whether the named struct `name` fits the object at `index`: the code reads and writes
    /// inside it and across no field's edge, steps through it only by its size, and what its
    /// struct fields point to fits their structs in turn. Errs with the first misfit.
    fn fits(&self, evidence: &Evidence, index: usize, name: &str, seen: &mut HashSet<(usize, String)>) -> Result<(), String> {
        if !seen.insert((index, name.to_string())) {
            return Ok(());
        }
        let Some(layout) = self.named.get(name) else { return Err(format!("{name} is not among the structs")) };
        let object = &evidence.objects[index];
        let size = layout.size() as i64;
        let mut strides = object.strides.clone();
        strides.sort_unstable();
        strides.dedup();
        let stride = match strides.as_slice() {
            [] => None,
            [step] if *step as i64 == size => Some(size),
            [step, ..] => return Err(format!("the code steps through it by {step:#x} bytes, and {name} has {size:#x}")),
        };
        if object.span.0 < 0 {
            return Err(format!("it points {:#x} bytes into something", -object.span.0));
        }
        // As for a recovered struct, no constant the code adds may reach the next element.
        let end = object.accesses.iter().map(|access| access.offset + i64::from(access.size)).chain([object.span.1 + i64::from(stride.is_none())]).max().unwrap_or(0);
        if end > size || object.accesses.iter().any(|access| access.offset < 0) {
            return Err(format!("it is used to +{end:#x}, past the end of {name} ({size:#x} bytes)"));
        }
        for access in &object.accesses {
            let (start, stop) = (access.offset as u64, access.offset as u64 + u64::from(access.size));
            let across = layout.fields().iter().find(|&(&at, field)| {
                let field_end = at + u64::from(field.size);
                start < field_end && at < stop && !(at <= start && stop <= field_end)
            });
            if let Some((&at, field)) = across {
                return Err(format!("it has {} bytes at +{start:#x}, across {name}.{}", access.size, field_name(at, field)));
            }
        }
        for &(offset, child) in &object.points_to {
            let offset = reduced(offset, stride);
            if let Some(field @ Field { ty: FieldType::Struct(target), .. }) = layout.fields().get(&offset) {
                self.fits(evidence, child, target, seen).map_err(|why| format!("what {name}.{} points to does not fit {target}: {why}", field_name(offset, field)))?;
            }
        }
        Ok(())
    }

    /// The version of the names that `structs` can take: the first under which none of them
    /// is defined, or all are, with these layouts. Names are finitely many, so one comes.
    fn version<F: Fn(&str) -> String>(&self, structs: &[(String, Layout, bool)], rename: &impl Fn(u32) -> F) -> u32 {
        if structs.is_empty() {
            return 1;
        }
        for version in 1.. {
            let defined: Vec<Option<bool>> = structs.iter().map(|(name, layout, _)| self.defined.get(&versioned(name, version)).map(|(defined, _)| defined.same_shape(&layout.renamed(rename(version))))).collect();
            if defined.iter().all(Option::is_none) || defined.iter().all(|defined| *defined == Some(true)) {
                return version;
            }
        }
        unreachable!("the loop returns")
    }

    /// The struct `name` wrapped in the output of the function at `function`. The objects it
    /// was put on there are not given one again.
    pub(crate) fn wrapped(&mut self, function: u64, name: &str) {
        let Some(last) = self.last.get(&function) else { return };
        for (object, path) in last.report.objects.iter().zip(&last.paths) {
            if let (Ok(given), Some((slot, path))) = (&object.decision, path)
                && given == name
            {
                self.wrapped.insert(auto_name(function, slot, path));
            }
        }
    }

    /// Brings the named structs and holders to those of the edits. Structs new to the engine
    /// are defined; one the engine holds with other names of fields has them renamed; one it
    /// holds with another layout asks for a new session.
    pub(crate) fn converge(&mut self, pointer: u32, structs: &BTreeMap<String, Layout>, holders: &BTreeMap<u64, BTreeMap<Slot, String>>) -> Converge {
        let mut renames = Vec::new();
        let mut new = Vec::new();
        for (name, layout) in structs {
            match self.defined.get(name) {
                Some((held, _)) if held.same_shape(layout) => {
                    for (&offset, field) in layout.fields() {
                        if held.fields()[&offset].name != field.name {
                            renames.push((name.clone(), offset, field_name(offset, field)));
                        }
                    }
                }
                Some(_) => return Converge { restart: true, ..Default::default() },
                None => new.push(Planned { name: name.clone(), layout: layout.clone(), array: false }),
            }
        }
        for (name, ..) in &renames {
            self.defined.get_mut(name).expect("held").0 = structs[name].clone();
        }
        self.named = structs.clone();
        self.holders = holders.clone();
        let xml = (!new.is_empty()).then(|| self.xml(pointer, &new));
        Converge { restart: false, xml, renames }
    }

    /// The recovered struct `name` stands for in this session, with the one its slot points
    /// to first and every struct reached from that through fields.
    pub(crate) fn recovered(&self, name: &str) -> Option<Recovered> {
        for (&function, last) in &self.last {
            let Some(index) = last.report.objects.iter().position(|object| !object.named && object.decision.as_ref().is_ok_and(|given| given == name)) else { continue };
            let (slot, _) = last.paths[index].clone()?;
            let root = last.paths.iter().zip(&last.report.objects).find_map(|(path, object)| (path.as_ref() == Some(&(slot.clone(), Vec::new()))).then(|| object.decision.clone().ok()).flatten())?;
            let mut structs: Vec<(String, Layout)> = Vec::new();
            let mut queue = vec![root];
            while let Some(name) = queue.pop() {
                if structs.iter().any(|(known, _)| *known == name) {
                    continue;
                }
                let (layout, _) = self.defined.get(&name)?;
                queue.extend(layout.fields().values().rev().filter_map(|field| match &field.ty {
                    FieldType::Struct(target) => Some(target.clone()),
                    _ => None,
                }));
                structs.push((name, layout.clone()));
            }
            return Some(Recovered { function, slot, structs });
        }
        None
    }

    /// What the last plan for the function at `function` made of its objects.
    pub(crate) fn report(&self, function: u64) -> Option<StructReport> {
        self.last.get(&function).map(|last| last.report.clone())
    }

    /// The engine XML that defines `structs`, numbered after every struct defined before. A
    /// field may point to a struct the engine holds already.
    fn xml(&mut self, pointer: u32, structs: &[Planned]) -> String {
        let mut table = Types::new(u64::from(pointer));
        let mut ids: HashMap<String, types::TypeId> = structs.iter().map(|planned| (planned.name.clone(), table.named(Named::Struct, &planned.name, planned.layout.size()).0)).collect();
        let mut known = Vec::new();
        for planned in structs {
            let mut fields = Vec::new();
            for (&offset, field) in planned.layout.fields() {
                let kind = match &field.ty {
                    FieldType::Struct(target) => match (ids.get(target), self.defined.get(target)) {
                        (Some(&id), _) => Type::Pointer(id),
                        (None, Some((layout, engine_id))) => {
                            let id = table.named(Named::Struct, target, layout.size()).0;
                            ids.insert(target.clone(), id);
                            known.push((id, *engine_id));
                            Type::Pointer(id)
                        }
                        (None, None) => number_type(&mut table, &FieldType::Unknown, field.size),
                    },
                    number => number_type(&mut table, number, field.size),
                };
                fields.push(types::Field { name: field_name(offset, field), offset, kind: table.add(kind), bits: None });
            }
            table.set_fields(ids[&planned.name], fields);
        }
        let first_id = FIRST_ID + self.next_id;
        self.next_id += table.types.len() as u64;
        let mut writer = Writer::numbered_from(&table, first_id);
        for (id, engine_id) in known {
            writer.known(id, engine_id);
        }
        for planned in structs {
            writer.named(ids[&planned.name]);
            self.defined.insert(planned.name.clone(), (planned.layout.clone(), writer.ident(ids[&planned.name])));
        }
        writer.take().unwrap_or_default()
    }
}

/// Says where an object comes from, in a warning.
fn place(object: &Object) -> String {
    match (object.roots.first(), object.passed.first()) {
        (Some((slot, _)), _) => slot.to_string(),
        (None, Some((callee, slot, _))) => format!("the pointer passed to {callee:#x} in {slot}"),
        (None, None) => "a pointer".into(),
    }
}

/// The report of one plan.
fn report(objects: &[Object], choices: &[Choice], decisions: &[Result<String, Refusal>], warnings: &[String]) -> StructReport {
    let mut field: Vec<Option<(String, u64)>> = vec![None; objects.len()];
    for (object, (decision, choice)) in objects.iter().zip(decisions.iter().zip(choices)) {
        let Ok(name) = decision else { continue };
        let stride = match choice {
            Choice::Recover(layout, true) => Some(layout.size() as i64),
            _ => None,
        };
        for &(offset, child) in &object.points_to {
            field[child].get_or_insert_with(|| (name.clone(), reduced(offset, stride)));
        }
    }
    let objects = objects
        .iter()
        .zip(choices.iter().zip(decisions))
        .zip(field)
        .map(|((object, (choice, decision)), field)| ObjectReport {
            slots: object.roots.iter().map(|(slot, _)| slot.clone()).collect(),
            field,
            decision: decision.clone(),
            named: matches!(choice, Choice::Named(_) | Choice::Typed(_)),
            accesses: object.accesses.len(),
            span: (object.accesses.iter().map(|access| access.offset).min().unwrap_or(0), object.accesses.iter().map(|access| access.offset + i64::from(access.size)).max().unwrap_or(0)),
        })
        .collect();
    StructReport { objects, warnings: warnings.to_vec() }
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
    if object.number {
        return Err(Refusal::Number);
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
            // Through the root itself the code reaches the first element only, and steps to
            // the next. Further on is a header before the array, or an element by a constant
            // index, and either would print as one past the struct.
            let past = object.span.0 < 0 || object.span.1 > stride;
            if past || object.accesses.iter().any(|access| access.offset < 0 || access.offset + i64::from(access.size) > stride) {
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
        let field = Field::new(access.size, access.ty.clone());
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

/// A register by name, or with a null name the stack at `stack`.
///
/// # Safety
/// `register` is null or a valid C string.
unsafe fn slot(register: *const c_char, stack: u64) -> Slot {
    if register.is_null() { Slot::Stack(stack) } else { Slot::Register(unsafe { CStr::from_ptr(register) }.to_string_lossy().into_owned()) }
}

/// Reads what the shim hands over.
///
/// # Safety
/// `raw` and every array it points to are valid for the call, as the shim's hook keeps them.
unsafe fn evidence(raw: &ffi::RdEvidence) -> Evidence {
    let mut objects: Vec<Object> = unsafe { crate::slice(raw.objects, raw.object_count) }
        .iter()
        .map(|object| Object { span: (object.low, object.high), locked: object.locked != 0, global: object.global != 0, number: object.number != 0, ..Default::default() })
        .collect();
    for root in unsafe { crate::slice(raw.roots, raw.root_count) } {
        objects[root.object as usize].roots.push((unsafe { slot(root.register, root.stack) }, root.offset));
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
    for pass in unsafe { crate::slice(raw.passed, raw.pass_count) } {
        objects[pass.object as usize].passed.push((pass.callee, unsafe { slot(pass.register, pass.stack) }, pass.offset));
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
        let xml = if plan.new { Some(registry.xml(evidence.pointer, &plan.structs)) } else { None };
        let text = |text: &str| CString::new(text).expect("names and XML hold no NUL");
        let names: Vec<Option<CString>> = plan.decisions.iter().map(|decision| decision.as_ref().ok().map(|name| text(name))).collect();
        let used: Vec<(&str, bool)> = plan.structs.iter().map(|planned| (planned.name.as_str(), planned.array)).chain(plan.named.iter().map(|(name, array)| (name.as_str(), *array))).collect();
        let used_names: Vec<CString> = used.iter().map(|(name, _)| text(name)).collect();
        let warnings: Vec<CString> = plan.warnings.iter().map(|warning| text(warning)).collect();
        registry.out = Out {
            xml: xml.map(|xml| text(&xml)),
            name_ptrs: names.iter().map(|name| name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr())).collect(),
            _names: names,
            used_ptrs: used_names.iter().map(|name| name.as_ptr()).collect(),
            used: used_names,
            arrays: used.iter().map(|(_, array)| (*array).into()).collect(),
            warning_ptrs: warnings.iter().map(|warning| warning.as_ptr()).collect(),
            warnings,
        };
        let kept = &registry.out;
        *out = ffi::RdPlan {
            xml: kept.xml.as_ref().map_or(std::ptr::null(), |xml| xml.as_ptr()),
            names: kept.name_ptrs.as_ptr(),
            recovered: kept.used_ptrs.as_ptr(),
            arrays: kept.arrays.as_ptr(),
            recovered_count: kept.used.len(),
            warnings: kept.warning_ptrs.as_ptr(),
            warning_count: kept.warnings.len(),
        };
        1
    })
    .unwrap_or(0)
}

/// The shim's hook for a struct that wrapped in the output of the function at `function`.
pub(crate) extern "C" fn wrapped_hook(ctx: *mut c_void, function: u64, name: *const c_char) {
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: as for `plan_hook`.
        let (registry, name) = unsafe { (&mut *(ctx as *mut Registry), CStr::from_ptr(name)) };
        registry.wrapped(function, &name.to_string_lossy());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(offset: i64, size: u32, ty: FieldType) -> Access {
        Access { offset, size, ty }
    }

    fn rdi() -> Slot {
        Slot::Register("RDI".into())
    }

    /// An object `RDI` points to, reading 4-byte numbers at each offset.
    fn object(offsets: &[i64]) -> Object {
        let accesses = offsets.iter().map(|&offset| access(offset, 4, FieldType::Int)).collect();
        Object { roots: vec![(rdi(), 0)], span: (0, 0), accesses, ..Default::default() }
    }

    fn plan(objects: Vec<Object>) -> Plan {
        Registry::default().plan(&Evidence { function: 0x401000, pointer: 8, objects })
    }

    fn layout(fields: &[(u64, u32, FieldType)], size: u64) -> Layout {
        Layout::new(size, fields.iter().map(|(offset, size, ty)| (*offset, Field::new(*size, ty.clone()))).collect()).unwrap()
    }

    /// A registry that holds `Connection` (0x20 bytes, an int at 8 and a `Session` pointer at
    /// 0x10) and `Session` (an int at 4, 8 bytes), with `Connection` in `RDI` of 0x402000.
    fn named() -> Registry {
        let mut registry = Registry::default();
        let structs = BTreeMap::from([
            ("Connection".to_string(), layout(&[(8, 4, FieldType::Int), (0x10, 8, FieldType::Struct("Session".into()))], 0x20)),
            ("Session".to_string(), layout(&[(4, 4, FieldType::Int)], 8)),
        ]);
        let holders = BTreeMap::from([(0x402000, BTreeMap::from([(rdi(), "Connection".to_string())]))]);
        let converge = registry.converge(8, &structs, &holders);
        assert!(!converge.restart && converge.xml.is_some());
        registry
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
        let mut number = object(&[0, 4]);
        number.number = true;
        let mut beyond = object(&[0, 4]);
        (beyond.strides, beyond.span) = (vec![12], (0, 0x20));
        let decisions = plan(vec![object(&[0, 2]), object(&[0]), object(&[]), middle, second_root, strides, past_stride, locked, global, number, beyond]).decisions;
        let refusals = [Refusal::Overlap, Refusal::Primitive, Refusal::Unused, Refusal::IntoMiddle, Refusal::IntoMiddle, Refusal::Stride, Refusal::Stride, Refusal::Locked, Refusal::Global, Refusal::Number, Refusal::Stride];
        assert_eq!(decisions, refusals.map(Err));
    }

    #[test]
    fn an_array_of_structs_is_one_element() {
        let mut points = object(&[0, 8]);
        points.strides = vec![12, 12];
        let plan = plan(vec![points]);
        assert_eq!(plan.structs[0].layout, layout(&[(0, 4, FieldType::Int), (8, 4, FieldType::Int)], 12));
        assert!(plan.structs[0].array);
    }

    #[test]
    fn a_read_past_the_first_element_refuses_the_array() {
        let mut header = object(&[0, 0x20]);
        header.strides = vec![12];
        assert_eq!(plan(vec![header]).decisions, [Err(Refusal::Stride)]);
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
        let mut decompile = |offsets: &[i64]| {
            let mut parent = object(offsets);
            parent.accesses.push(access(0x10, 8, FieldType::Unknown));
            parent.points_to = vec![(0x10, 1)];
            let mut child = object(&[0, 4]);
            child.roots.clear();
            let plan = registry.plan(&Evidence { function: 0x401000, pointer: 8, objects: vec![parent, child] });
            if plan.new {
                registry.xml(8, &plan.structs);
            }
            plan
        };
        assert!(decompile(&[0, 4]).new);
        let again = decompile(&[0, 4]);
        assert_eq!((again.decisions[0].clone(), again.new), (Ok("S_401000_RDI".to_string()), false));
        let changed = decompile(&[0, 8]);
        assert_eq!(changed.decisions, [Ok("S_401000_RDI_v2".to_string()), Ok("S_401000_RDI_10_v2".to_string())]);
        assert_eq!(changed.structs[0].layout.fields()[&0x10].ty, FieldType::Struct("S_401000_RDI_10_v2".into()));
        assert!(changed.new);
    }

    #[test]
    fn a_struct_that_wrapped_is_not_recovered_again() {
        let mut registry = Registry::default();
        let evidence = Evidence { function: 0x401000, pointer: 8, objects: vec![object(&[0, 4])] };
        let name = registry.plan(&evidence).decisions[0].clone().unwrap();
        registry.wrapped(0x401000, &name);
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

    /// The function's own holder and a callee's both name the struct, and what its field
    /// points to has the struct the field says.
    #[test]
    fn a_holder_names_the_struct_that_fits() {
        let mut registry = named();
        let mut connection = object(&[8]);
        connection.accesses.push(access(0x10, 8, FieldType::Unknown));
        connection.points_to = vec![(0x10, 1)];
        let mut session = object(&[4]);
        session.roots.clear();
        let own = registry.plan(&Evidence { function: 0x402000, pointer: 8, objects: vec![connection, session] });
        assert_eq!(own.decisions, [Ok("Connection".to_string()), Ok("Session".to_string())]);
        assert!(own.structs.is_empty() && own.warnings.is_empty());

        let mut relayed = object(&[]);
        relayed.passed = vec![(0x402000, rdi(), 0)];
        let caller = registry.plan(&Evidence { function: 0x403000, pointer: 8, objects: vec![relayed] });
        assert_eq!(caller.decisions, [Ok("Connection".to_string())]);
    }

    #[test]
    fn a_named_struct_that_does_not_fit_leaves_a_warning_and_a_recovered_struct() {
        let mut registry = named();
        let past = object(&[8, 0x28]);
        let plan = registry.plan(&Evidence { function: 0x402000, pointer: 8, objects: vec![past] });
        assert_eq!(plan.decisions, [Ok("S_402000_RDI".to_string())]);
        assert_eq!(plan.warnings, ["Connection does not fit what RDI points to, which gets a struct of its own: it is used to +0x2c, past the end of Connection (0x20 bytes)"]);

        let mut nested = object(&[8]);
        nested.accesses.push(access(0x10, 8, FieldType::Unknown));
        nested.points_to = vec![(0x10, 1)];
        nested.passed = vec![(0x402000, rdi(), 0)];
        let mut session = object(&[2]);
        session.roots.clear();
        let plan = registry.plan(&Evidence { function: 0x403000, pointer: 8, objects: vec![nested, session] });
        assert_eq!(plan.warnings, ["Connection does not fit what RDI points to, which gets a struct of its own: what Connection.field_0x10 points to does not fit Session: it has 4 bytes at +0x2, across Session.field_0x4"]);
    }

    #[test]
    fn edits_converge_in_place_until_a_layout_changes() {
        let mut registry = named();
        let mut structs = registry.named.clone();
        let holders = registry.holders.clone();
        assert_eq!(registry.converge(8, &structs, &holders), Converge::default());
        let mut renamed = structs["Connection"].clone();
        renamed.rename_field(0x10, "session").unwrap();
        structs.insert("Connection".into(), renamed);
        assert_eq!(registry.converge(8, &structs, &holders).renames, [("Connection".to_string(), 0x10, "session".to_string())]);
        structs.insert("Connection".into(), layout(&[(8, 8, FieldType::Int)], 0x20));
        assert!(registry.converge(8, &structs, &holders).restart);
    }
}
