//! Structs: the layouts recore recovers from how a function uses the pointers it is passed, and
//! the ones an agent has named. Checked here once, also when read back from the edits file;
//! every other module trusts a [`Layout`].

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// What one field holds, as far as the code that touches it shows.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub size: u32,
    #[serde(rename = "type")]
    pub ty: FieldType,
    /// None prints as `field_0x28`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Field {
    pub fn new(size: u32, ty: FieldType) -> Field {
        Field { size, ty, name: None }
    }
}

/// The name a field at `offset` goes by until it is given one.
pub fn field_name(offset: u64, field: &Field) -> String {
    field.name.clone().unwrap_or_else(|| format!("field_0x{offset:x}"))
}

/// A struct's size and its fields by offset. Fields don't overlap, each ends inside `size`, and
/// no single field fills the whole struct, which the engine would resolve as a union.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(try_from = "RawLayout")]
pub struct Layout {
    size: u64,
    fields: BTreeMap<u64, Field>,
}

#[derive(Deserialize)]
struct RawLayout {
    size: u64,
    fields: BTreeMap<u64, Field>,
}

impl TryFrom<RawLayout> for Layout {
    type Error = String;
    fn try_from(raw: RawLayout) -> Result<Layout, String> {
        Layout::new(raw.size, raw.fields).map_err(|refusal| format!("not a struct layout: {}", refusal.reason()))
    }
}

/// Why recore leaves the pointers of an object to the engine.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Two different named structs reach it.
    NamedConflict,
    /// Every read or write is one byte, within its first four: a string or a buffer of bytes
    /// tested a byte at a time, as `s[0] == '-' && s[1] == '-'`.
    Bytes,
}

impl Refusal {
    /// Says why, for an agent who wonders why a pointer prints as `*(int8 *)(p + 0x28)`.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Unused => "nothing is read or written through it",
            Refusal::Primitive => "one field fills it, so it points to a number",
            Refusal::Overlap => "reads at different offsets overlap, as two layouts for one pointer",
            Refusal::IntoMiddle => "it points into the middle of something: a read lies below where it points",
            Refusal::Stride => "it steps through elements by different sizes, or reads past the first element",
            Refusal::Locked => "a value of it has a declared type or one from debug information",
            Refusal::Global => "a value of it lives in global memory",
            Refusal::Number => "the code uses it as a number: compared with a constant or added to a table's address",
            Refusal::NoRoot => "no parameter and no field of a recovered struct points to it",
            Refusal::Wrapped => "its struct came out too small once this session",
            Refusal::NamedConflict => "two different named structs reach it",
            Refusal::Bytes => "every read is one byte near its start, as of a string",
        }
    }
}

/// Two layouts that cannot be one: the field of `theirs` at `at` lies partly inside `ours`'.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clash {
    pub at: u64,
    pub size: u32,
    pub field_at: u64,
    pub field: String,
    pub field_size: u32,
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
        let mut layout = self.clone();
        for field in layout.fields.values_mut() {
            if let FieldType::Struct(name) = &field.ty {
                field.ty = FieldType::Struct(rename(name));
            }
        }
        layout
    }

    /// Whether the two differ in nothing but the names of fields.
    pub fn same_shape(&self, other: &Layout) -> bool {
        self.size == other.size && self.fields.len() == other.fields.len() && self.fields.iter().zip(&other.fields).all(|((a, x), (b, y))| a == b && x.size == y.size && x.ty == y.ty)
    }

    /// Both layouts as one: every field of either, and the larger size. Fields that start
    /// alike keep the wider; names and pointed-to structs already in `self` win, and number
    /// kinds that disagree become unknown. Errs with the first field of `theirs` that lies
    /// partly inside one of `self`'s, or the other way round.
    pub fn merge(&self, theirs: &Layout) -> Result<Layout, Clash> {
        let mut fields = self.fields.clone();
        for (&offset, field) in &theirs.fields {
            let merged = match fields.get(&offset) {
                None => field.clone(),
                Some(ours) => {
                    let ty = match (&ours.ty, &field.ty) {
                        (a, b) if a == b => a.clone(),
                        (FieldType::Struct(_), _) => ours.ty.clone(),
                        (_, FieldType::Struct(_)) => field.ty.clone(),
                        _ => FieldType::Unknown,
                    };
                    Field { size: ours.size.max(field.size), ty, name: ours.name.clone().or_else(|| field.name.clone()) }
                }
            };
            fields.insert(offset, merged);
        }
        // Where two fields overlap, one of them came from each side.
        let mut previous: Option<(u64, u64)> = None;
        for (&offset, field) in &fields {
            if let Some((at, size)) = previous
                && at + size > offset
            {
                let ours_reaches = self.fields.get(&at).is_some_and(|ours| at + u64::from(ours.size) > offset);
                let (theirs_at, ours_at) = if ours_reaches && theirs.fields.contains_key(&offset) { (offset, at) } else { (at, offset) };
                let (theirs_field, ours_field) = (&theirs.fields[&theirs_at], &self.fields[&ours_at]);
                return Err(Clash { at: theirs_at, size: theirs_field.size, field_at: ours_at, field: field_name(ours_at, ours_field), field_size: ours_field.size });
            }
            previous = Some((offset, u64::from(field.size)));
        }
        Ok(Layout { size: self.size.max(theirs.size), fields })
    }

    /// Names the field at `offset`; an empty name gives it back the one it had at first.
    pub fn rename_field(&mut self, offset: u64, name: &str) -> Result<(), NameError> {
        if !self.fields.contains_key(&offset) {
            return Err(NameError::NoSuchField(format!("+{offset:#x}")));
        }
        if !name.is_empty() && !is_identifier(name) {
            return Err(NameError::NotAName(name.to_string()));
        }
        if self.fields.iter().any(|(&other, field)| other != offset && field_name(other, field) == name) {
            return Err(NameError::Taken(name.to_string()));
        }
        self.fields.get_mut(&offset).expect("checked").name = (!name.is_empty() && name != format!("field_0x{offset:x}")).then(|| name.to_string());
        Ok(())
    }

    /// The offset of the field called `name`.
    pub fn field_named(&self, name: &str) -> Option<u64> {
        self.fields.iter().find(|&(&offset, field)| field_name(offset, field) == name).map(|(&offset, _)| offset)
    }
}

/// Where a function is passed a value: a register, or the stack at an offset from the stack
/// pointer on entry. Written `RDI` or `stack4`, which is also how the edits file keys it.
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

impl FromStr for Slot {
    type Err = String;
    fn from_str(text: &str) -> Result<Slot, String> {
        if let Some(offset) = text.strip_prefix("stack").and_then(|hex| u64::from_str_radix(hex, 16).ok()) {
            return Ok(Slot::Stack(offset));
        }
        if text.is_empty() || !text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("`{text}` is no register or stack slot"));
        }
        Ok(Slot::Register(text.to_string()))
    }
}

impl Serialize for Slot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Slot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Slot, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
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

/// The function a name of [`auto_name`]'s form says the struct was recovered in.
pub fn auto_function(name: &str) -> Option<u64> {
    let (hex, rest) = name.strip_prefix("S_")?.split_once('_')?;
    (!rest.is_empty()).then_some(())?;
    u64::from_str_radix(hex, 16).ok()
}

/// Whether `name` can name a C type or field.
pub fn is_identifier(name: &str) -> bool {
    !name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A recovered struct and the ones it points to, as one function's decompilation left them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Recovered {
    pub function: u64,
    /// Where the function is passed the pointer to the first struct.
    pub slot: Slot,
    /// The struct of the slot's object first, then those its fields point to, which field
    /// types name.
    pub structs: Vec<(String, Layout)>,
}

/// Why a struct or field cannot take a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    NotAName(String),
    /// A name of the form recovered structs take, which says where one came from.
    AutoForm(String),
    Taken(String),
    NoSuchStruct(String),
    /// No field goes by this name, or starts at this offset.
    NoSuchField(String),
    /// Joining two structs under one name.
    Clash { joining: String, into: String, clash: Clash },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NameError::NotAName(name) => write!(f, "`{name}` is not a C identifier"),
            NameError::AutoForm(name) => write!(f, "`{name}` has the form of a recovered struct's name; choose another"),
            NameError::Taken(name) => write!(f, "`{name}` is taken"),
            NameError::NoSuchStruct(name) => write!(f, "there is no struct `{name}`"),
            NameError::NoSuchField(field) => write!(f, "there is no field {field}"),
            NameError::Clash { joining, into, clash } => write!(
                f,
                "cannot join {into}: {joining} has {} bytes at +{:#x}, across {into}.{} (+{:#x}, {} bytes)",
                clash.size, clash.at, clash.field, clash.field_at, clash.field_size
            ),
        }
    }
}

impl std::error::Error for NameError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(size: u32) -> Field {
        Field::new(size, FieldType::Int)
    }

    fn layout(size: u64, fields: &[(u64, Field)]) -> Layout {
        Layout::new(size, fields.iter().cloned().collect()).unwrap()
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
        assert_eq!(auto_function("S_401a20_stack4_10_8"), Some(0x401a20));
        assert_eq!(auto_function("Connection"), None);
        assert_eq!("stack4".parse(), Ok(Slot::Stack(4)));
        assert_eq!("RDI".parse(), Ok(Slot::Register("RDI".into())));
    }

    #[test]
    fn a_layout_read_back_is_checked() {
        let text = r#"{"size":16,"fields":{"0":{"size":8,"type":"int"},"8":{"size":8,"type":{"struct":"Session"},"name":"session"}}}"#;
        let layout: Layout = serde_json::from_str(text).unwrap();
        assert_eq!(layout.fields()[&8], Field { size: 8, ty: FieldType::Struct("Session".into()), name: Some("session".into()) });
        assert_eq!(serde_json::to_string(&layout).unwrap(), text);
        let overlapping = r#"{"size":16,"fields":{"0":{"size":8,"type":"int"},"4":{"size":8,"type":"int"}}}"#;
        assert!(serde_json::from_str::<Layout>(overlapping).unwrap_err().to_string().contains("not a struct layout"));
    }

    #[test]
    fn two_layouts_merge_into_every_field_of_both() {
        let mut ours = layout(0x30, &[(8, int(4)), (0x10, Field::new(8, FieldType::Struct("Session".into())))]);
        ours.rename_field(8, "limit").unwrap();
        let theirs = layout(0x38, &[(8, Field::new(4, FieldType::Uint)), (0x10, Field::new(8, FieldType::Struct("S_402b00_RDI_10".into()))), (0x30, int(8))]);
        let merged = ours.merge(&theirs).unwrap();
        assert_eq!(merged.size(), 0x38);
        assert_eq!(merged.fields()[&8], Field { size: 4, ty: FieldType::Unknown, name: Some("limit".into()) });
        assert_eq!(merged.fields()[&0x10].ty, FieldType::Struct("Session".into()));
        assert_eq!(merged.fields()[&0x30], int(8));
    }

    #[test]
    fn layouts_whose_fields_cross_do_not_merge() {
        let ours = layout(0x30, &[(8, int(8))]);
        let theirs = layout(0x10, &[(0xc, int(4))]);
        assert_eq!(ours.merge(&theirs), Err(Clash { at: 0xc, size: 4, field_at: 8, field: "field_0x8".into(), field_size: 8 }));
    }

    #[test]
    fn a_field_takes_a_name_no_other_field_has() {
        let mut layout = layout(0x10, &[(0, int(4)), (8, int(4))]);
        assert_eq!(layout.rename_field(4, "x"), Err(NameError::NoSuchField("+0x4".into())));
        assert_eq!(layout.rename_field(0, "2x"), Err(NameError::NotAName("2x".into())));
        assert_eq!(layout.rename_field(0, "field_0x8"), Err(NameError::Taken("field_0x8".into())));
        layout.rename_field(8, "count").unwrap();
        assert_eq!(layout.field_named("count"), Some(8));
        layout.rename_field(8, "").unwrap();
        assert_eq!(layout.field_named("field_0x8"), Some(8));
    }
}
