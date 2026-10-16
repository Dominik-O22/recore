//! Structs that recore recovers from how a function uses the pointers it is passed. Checked
//! here once; every other module trusts a [`Layout`].

use std::collections::BTreeMap;
use std::fmt;

/// What one field holds, as far as the code that touches it shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// `undefinedN`: the code shows the size only.
    Unknown,
    Int,
    Uint,
    Float,
    Bool,
    /// A pointer to the struct of this name.
    Struct(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub size: u32,
    pub ty: FieldType,
}

/// A struct's size and its fields by offset. Fields don't overlap, each ends inside `size`, and
/// no single field fills the whole struct, which the engine would resolve as a union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    size: u64,
    fields: BTreeMap<u64, Field>,
}

/// Why recore leaves the pointers of an object to the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Nothing is read or written through it.
    Unused,
    /// One field fills it: a pointer to a number is the right type.
    Primitive,
    /// Accesses at different starts overlap: two layouts for one pointer.
    Overlap,
    /// A member lies below the root, or two roots point to different places of it.
    IntoMiddle,
    /// Steps between elements disagree, or the code reaches past the first element through
    /// the pointer it was passed.
    Stride,
    /// A member already has a locked type: declared, or from debug information.
    Locked,
    /// A member lives in global memory, which every function shares.
    Global,
    /// The code uses a member as a number: an index, or a count.
    Number,
    /// Reached from no parameter, and from no field of a recovered struct.
    NoRoot,
    /// Its struct wrapped in the output once this session.
    Wrapped,
}

impl Layout {
    /// The one constructor.
    pub fn new(size: u64, fields: BTreeMap<u64, Field>) -> Result<Layout, Refusal> {
        if fields.is_empty() {
            return Err(Refusal::Unused);
        }
        let mut end = 0;
        for (&offset, field) in &fields {
            if offset < end {
                return Err(Refusal::Overlap);
            }
            end = offset + u64::from(field.size);
        }
        if end > size {
            return Err(Refusal::Overlap);
        }
        if fields.len() == 1 && fields.get(&0).is_some_and(|field| u64::from(field.size) == size) {
            return Err(Refusal::Primitive);
        }
        Ok(Layout { size, fields })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn fields(&self) -> &BTreeMap<u64, Field> {
        &self.fields
    }

    /// Says what the field at `offset` holds. Its place and size stay as they are.
    pub fn set_type(&mut self, offset: u64, ty: FieldType) {
        if let Some(field) = self.fields.get_mut(&offset) {
            field.ty = ty;
        }
    }

    /// The same layout with each struct a field points to renamed by `rename`.
    pub fn renamed(&self, rename: impl Fn(&str) -> String) -> Layout {
        let fields = self.fields.iter().map(|(&offset, field)| {
            let ty = match &field.ty {
                FieldType::Struct(name) => FieldType::Struct(rename(name)),
                other => other.clone(),
            };
            (offset, Field { size: field.size, ty })
        });
        Layout { size: self.size, fields: fields.collect() }
    }
}

/// Where a function is passed a value: a register, or the stack at an offset from the stack
/// pointer on entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Slot {
    Register(String),
    Stack(u64),
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Slot::Register(name) => f.write_str(name),
            Slot::Stack(offset) => write!(f, "stack{offset:x}"),
        }
    }
}

/// The engine name of a recovered struct: what `slot` of the function at `function` points to,
/// then what the fields at `path` point to in turn. `S_401a20_RDI`, `S_401a20_RDI_10_8`.
pub fn auto_name(function: u64, slot: &Slot, path: &[u64]) -> String {
    let mut name = format!("S_{function:x}_{slot}");
    for offset in path {
        name.push_str(&format!("_{offset:x}"));
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(size: u32) -> Field {
        Field { size, ty: FieldType::Int }
    }

    #[test]
    fn a_layout_refuses_what_the_engine_cannot_print() {
        assert_eq!(Layout::new(8, BTreeMap::new()), Err(Refusal::Unused));
        assert_eq!(Layout::new(8, BTreeMap::from([(0, int(8))])), Err(Refusal::Primitive));
        assert_eq!(Layout::new(8, BTreeMap::from([(0, int(4)), (2, int(4))])), Err(Refusal::Overlap));
        assert_eq!(Layout::new(6, BTreeMap::from([(4, int(4))])), Err(Refusal::Overlap));
        let layout = Layout::new(16, BTreeMap::from([(0, int(8))])).unwrap();
        assert_eq!((layout.size(), layout.fields().len()), (16, 1));
    }

    #[test]
    fn names_lead_back_to_the_slot_and_the_fields() {
        assert_eq!(auto_name(0x401a20, &Slot::Register("RDI".into()), &[]), "S_401a20_RDI");
        assert_eq!(auto_name(0x401a20, &Slot::Stack(4), &[0x10, 8]), "S_401a20_stack4_10_8");
    }
}
