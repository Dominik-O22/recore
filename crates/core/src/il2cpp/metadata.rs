//! The tables of `global-metadata.dat`, as Unity 6 writes them: metadata version 39 (Unity
//! 6000.0 to 6000.4) and version 107 (6000.5 on).
//!
//! The file opens with a magic number, the version, and a table of sections, each an
//! `(offset, size, count)` triplet. Rows refer to rows of other sections by index. An index is
//! as wide as the count of the section it points into needs: one byte for fewer than 256 rows,
//! two for fewer than 65536, and four otherwise, with all ones for none. Version 39 narrows
//! only some indices so; version 107 narrows nearly all, and adds a section.

use anyhow::{Context, Result, bail, ensure};

const MAGIC: u32 = 0xFAB1_1BAF;

/// What a section holds, which picks its place in the header for each version.
#[derive(Clone, Copy)]
enum Table {
    StringLiterals,
    StringLiteralData,
    Strings,
    Events,
    Properties,
    Methods,
    FieldDefaultValues,
    FieldAndParameterDefaultValueData,
    Parameters,
    Fields,
    GenericParameters,
    GenericContainers,
    NestedTypes,
    Interfaces,
    VtableMethods,
    InterfaceOffsets,
    TypeDefinitions,
    Images,
    FieldRefs,
}

impl Table {
    /// The section's place in the header of `version`. Version 107 adds a section before the
    /// images.
    fn section(self, version: u32) -> usize {
        let index = match self {
            Table::StringLiterals => 0,
            Table::StringLiteralData => 1,
            Table::Strings => 2,
            Table::Events => 3,
            Table::Properties => 4,
            Table::Methods => 5,
            Table::FieldDefaultValues => 7,
            Table::FieldAndParameterDefaultValueData => 8,
            Table::Parameters => 10,
            Table::Fields => 11,
            Table::GenericParameters => 12,
            Table::GenericContainers => 14,
            Table::NestedTypes => 15,
            Table::Interfaces => 16,
            Table::VtableMethods => 17,
            Table::InterfaceOffsets => 18,
            Table::TypeDefinitions => 19,
            Table::Images => 20,
            Table::FieldRefs => 22,
        };
        if version >= 100 && index >= 20 { index + 1 } else { index }
    }
}

/// A type definition: a class, struct, enum or interface.
#[derive(Debug, Clone)]
pub struct TypeDefinition {
    pub name: String,
    pub namespace: String,
    /// The type itself, the type that encloses it and its base type, as indices into the
    /// binary's table of types.
    pub byval: Option<u32>,
    pub declaring: Option<u32>,
    pub parent: Option<u32>,
    pub generic_container: Option<u32>,
    /// `TypeAttributes`: 0x20 marks an interface.
    pub flags: u32,
    pub field_start: Option<u32>,
    pub method_start: Option<u32>,
    pub vtable_start: Option<u32>,
    pub method_count: u16,
    pub field_count: u16,
    pub vtable_count: u16,
    /// Bit 0 marks a value type, bit 1 an enum.
    pub bits: u32,
}

impl TypeDefinition {
    pub fn is_value_type(&self) -> bool {
        self.bits & 1 != 0
    }

    pub fn is_enum(&self) -> bool {
        self.bits & 2 != 0
    }

    pub fn is_interface(&self) -> bool {
        self.flags & 0x20 != 0
    }
}

#[derive(Debug, Clone)]
pub struct MethodDefinition {
    pub name: String,
    pub declaring: Option<u32>,
    pub returns: Option<u32>,
    pub parameter_start: Option<u32>,
    pub generic_container: Option<u32>,
    /// The metadata token, whose low 24 bits number the method within its image from 1.
    pub token: u32,
    /// `MethodAttributes`: 0x10 marks a static method.
    pub flags: u16,
    /// The vtable slot of a virtual method; 0xffff for none.
    pub slot: u16,
    pub parameter_count: u16,
}

#[derive(Debug, Clone)]
pub struct Named {
    pub name: String,
    pub kind: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub name: String,
    pub type_start: Option<u32>,
    pub type_count: u32,
}

/// The tables recore reads from one `global-metadata.dat`.
#[derive(Debug)]
pub struct Metadata {
    pub version: u32,
    pub types: Vec<TypeDefinition>,
    pub methods: Vec<MethodDefinition>,
    pub parameters: Vec<Named>,
    pub fields: Vec<Named>,
    /// Each slot of every vtable: an encoded method index, whose top three bits say whether it
    /// is a method definition (3) or a generic instance of one (6).
    pub vtable_methods: Vec<u32>,
    /// `(type index, field index within that type)` for each field a usage slot refers to.
    pub field_refs: Vec<(Option<u32>, u32)>,
    /// The name of each generic parameter.
    pub generic_parameters: Vec<String>,
    /// The first generic parameter of each generic container, and how many it has.
    pub generic_containers: Vec<(u32, u16)>,
    pub images: Vec<Image>,
    pub string_literals: Vec<String>,
    /// The constant value of each field that has one, such as an enum's members: the field's
    /// index and where its bytes start in `default_value_data`.
    pub field_default_values: Vec<(u32, usize)>,
    pub default_value_data: Vec<u8>,
}

/// One row of a section, read field by field.
struct Row<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Row<'_> {
    fn take(&mut self, width: usize) -> Result<u32> {
        let bytes = self.bytes.get(self.at..self.at + width).context("row ends early")?;
        self.at += width;
        Ok(bytes.iter().rev().fold(0, |value, &byte| value << 8 | u32::from(byte)))
    }

    fn u32(&mut self) -> Result<u32> {
        self.take(4)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(self.take(2)? as u16)
    }

    /// An index `width` bytes wide; all ones means none.
    fn index(&mut self, width: usize) -> Result<Option<u32>> {
        let value = self.take(width)?;
        Ok((value != u32::MAX >> (32 - 8 * width)).then_some(value))
    }
}

struct Reader<'a> {
    data: &'a [u8],
    version: u32,
    sections: Vec<(usize, usize, usize)>,
}

impl<'a> Reader<'a> {
    fn section(&self, table: Table) -> Result<&'a [u8]> {
        let (offset, size, _) = *self.sections.get(table.section(self.version)).context("no such section")?;
        self.data.get(offset..offset + size).context("section past the end of the file")
    }

    fn count(&self, table: Table) -> usize {
        self.sections.get(table.section(self.version)).map_or(0, |section| section.2)
    }

    /// The width of an index into `table`.
    fn width(&self, table: Table) -> usize {
        match self.count(table) {
            0..=0xff => 1,
            0x100..=0xffff => 2,
            _ => 4,
        }
    }

    /// The width of an index into `table` where version 107 narrows it and 39 does not.
    fn narrow(&self, table: Table) -> usize {
        if self.version >= 100 { self.width(table) } else { 4 }
    }

    /// The rows of `table`, each read by `read`.
    fn rows<T>(&self, table: Table, mut read: impl FnMut(&mut Row) -> Result<T>) -> Result<Vec<T>> {
        let bytes = self.section(table)?;
        let count = self.count(table);
        if count == 0 {
            return Ok(Vec::new());
        }
        let size = bytes.len() / count;
        (0..count).map(|index| read(&mut Row { bytes: &bytes[index * size..(index + 1) * size], at: 0 })).collect()
    }
}

/// The NUL-terminated string at `offset` in the string section, up to a length no name reaches,
/// so that rows of a damaged file that all point at one long run of bytes do not each copy it.
fn string(strings: &[u8], offset: u32) -> String {
    const LONGEST: usize = 1024;
    let bytes = strings.get(offset as usize..).unwrap_or_default();
    let bytes = &bytes[..bytes.len().min(LONGEST)];
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Reads the tables of a `global-metadata.dat`.
pub fn parse(data: &[u8]) -> Result<Metadata> {
    let word = |at: usize| data.get(at..at + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    ensure!(word(0) == Some(MAGIC), "not IL2CPP metadata");
    let version = word(4).context("no version")?;
    if !matches!(version, 39 | 107) {
        bail!("metadata version {version} is not read; recore reads versions 39 and 107");
    }
    let count = if version >= 100 { 32 } else { 31 };
    let sections = (0..count)
        .map(|index| {
            let at = 8 + 12 * index;
            Some((word(at)? as usize, word(at + 4)? as usize, word(at + 8)? as usize))
        })
        .collect::<Option<Vec<_>>>()
        .context("header ends early")?;
    let reader = Reader { data, version, sections };
    let strings = reader.section(Table::Strings)?;
    let read_name = |row: &mut Row| Ok::<_, anyhow::Error>(string(strings, row.u32()?));

    // A parameter is a name, a token and a type index, so its size gives the type index's width.
    let type_width = reader.section(Table::Parameters)?.len().checked_div(reader.count(Table::Parameters)).unwrap_or(12).saturating_sub(8);
    ensure!(matches!(type_width, 1 | 2 | 4), "parameters of {} bytes", type_width + 8);
    let definition_width = reader.width(Table::TypeDefinitions);
    let container_width = reader.width(Table::GenericContainers);

    let types = reader.rows(Table::TypeDefinitions, |row| {
        let name = read_name(row)?;
        let namespace = read_name(row)?;
        let (byval, declaring, parent) = (row.index(type_width)?, row.index(type_width)?, row.index(type_width)?);
        let generic_container = row.index(container_width)?;
        let flags = row.u32()?;
        let field_start = row.index(reader.narrow(Table::Fields))?;
        let method_start = row.index(reader.narrow(Table::Methods))?;
        row.index(reader.narrow(Table::Events))?;
        row.index(reader.narrow(Table::Properties))?;
        row.index(reader.narrow(Table::NestedTypes))?;
        row.index(reader.narrow(Table::Interfaces))?;
        let vtable_start = row.index(reader.narrow(Table::VtableMethods))?;
        row.index(reader.narrow(Table::InterfaceOffsets))?;
        let method_count = row.u16()?;
        let _properties = row.u16()?;
        let field_count = row.u16()?;
        let _events = row.u16()?;
        let _nested = row.u16()?;
        let vtable_count = row.u16()?;
        let _interfaces = row.u16()?;
        let _interface_offsets = row.u16()?;
        let bits = row.u32()?;
        Ok(TypeDefinition {
            name,
            namespace,
            byval,
            declaring,
            parent,
            generic_container,
            flags,
            field_start,
            method_start,
            vtable_start,
            method_count,
            field_count,
            vtable_count,
            bits,
        })
    })?;

    let methods = reader.rows(Table::Methods, |row| {
        let name = read_name(row)?;
        let declaring = row.index(definition_width)?;
        let returns = row.index(type_width)?;
        let _return_parameter_token = row.u32()?;
        let parameter_start = row.index(reader.width(Table::Parameters))?;
        let generic_container = row.index(container_width)?;
        let token = row.u32()?;
        let flags = row.u16()?;
        let _implementation_flags = row.u16()?;
        let slot = row.u16()?;
        let parameter_count = row.u16()?;
        Ok(MethodDefinition { name, declaring, returns, parameter_start, generic_container, token, flags, slot, parameter_count })
    })?;

    let parameters = reader.rows(Table::Parameters, |row| {
        let name = read_name(row)?;
        let _token = row.u32()?;
        Ok(Named { name, kind: row.index(type_width)? })
    })?;
    let fields = reader.rows(Table::Fields, |row| {
        let name = read_name(row)?;
        Ok(Named { name, kind: row.index(type_width)? })
    })?;
    let vtable_methods = reader.rows(Table::VtableMethods, |row| row.u32())?;
    let field_refs = reader.rows(Table::FieldRefs, |row| {
        let size = row.bytes.len();
        Ok((row.index(type_width)?, row.take(size.saturating_sub(type_width))?))
    })?;
    let generic_parameters = reader.rows(Table::GenericParameters, |row| {
        row.index(container_width)?;
        read_name(row)
    })?;
    // A container is its owner, its parameter count, whether a method owns it, and the index of
    // its first parameter, which ends the row.
    let generic_containers = reader.rows(Table::GenericContainers, |row| {
        let size = row.bytes.len();
        row.at = 4;
        let count = row.u16()?;
        row.at = size - reader.narrow(Table::GenericParameters).min(size);
        Ok((row.index(reader.narrow(Table::GenericParameters))?.unwrap_or(0), count))
    })?;
    let images = reader.rows(Table::Images, |row| {
        let name = read_name(row)?;
        let _assembly = row.u32()?;
        let type_start = row.index(definition_width)?;
        Ok(Image { name, type_start, type_count: row.u32()? })
    })?;

    // A literal is where its bytes start; the next one's start is where they end.
    let literal_data = reader.section(Table::StringLiteralData)?;
    let starts = reader.rows(Table::StringLiterals, |row| row.u32())?;
    let ends = starts.iter().skip(1).copied().chain([literal_data.len() as u32]);
    let string_literals = starts
        .iter()
        .zip(ends)
        .map(|(&start, end)| String::from_utf8_lossy(literal_data.get(start as usize..end as usize).unwrap_or_default()).into_owned())
        .collect();

    let field_default_values = reader.rows(Table::FieldDefaultValues, |row| {
        let field = row.index(reader.narrow(Table::Fields))?.unwrap_or(u32::MAX);
        row.index(type_width)?;
        Ok((field, row.u32()? as usize))
    })?;
    let default_value_data = reader.section(Table::FieldAndParameterDefaultValueData)?.to_vec();

    // Rows index each other; one that points past a table means the file is not as read.
    let within = |start: Option<u32>, count: u16, len: usize| start.is_none_or(|start| start as usize + usize::from(count) <= len);
    ensure!(
        types.iter().all(|def| within(def.method_start, def.method_count, methods.len()) && within(def.field_start, def.field_count, fields.len())),
        "a type's methods or fields lie past their table"
    );
    ensure!(methods.iter().all(|method| method.declaring.is_some_and(|owner| (owner as usize) < types.len())), "a method's type lies past its table");
    ensure!(field_default_values.iter().all(|&(field, _)| (field as usize) < fields.len()), "a default value's field lies past its table");

    Ok(Metadata {
        version,
        types,
        methods,
        parameters,
        fields,
        vtable_methods,
        field_refs,
        generic_parameters,
        generic_containers,
        images,
        string_literals,
        field_default_values,
        default_value_data,
    })
}

/// An unsigned number as the default value data stores one of 32 bits: one byte below 0x80,
/// two below 0x4000 and four below 0x2000_0000, big-endian under the marking top bits, or a
/// marker byte and then four bytes.
pub fn compressed_u32(data: &[u8]) -> Option<u32> {
    let first = u32::from(*data.first()?);
    let big_endian = |bytes: &[u8]| bytes.iter().fold(0, |value, &byte| value << 8 | u32::from(byte));
    Some(match first {
        0..=0x7f => first,
        0x80..=0xbf => (first & 0x3f) << 8 | u32::from(*data.get(1)?),
        0xc0..=0xdf => (first & 0x1f) << 24 | big_endian(data.get(1..4)?),
        0xf0 => u32::from_le_bytes(data.get(1..5)?.try_into().ok()?),
        0xfe => u32::MAX - 1,
        0xff => u32::MAX,
        _ => return None,
    })
}

/// A signed number of 32 bits: its magnitude shifted left past a sign bit, compressed.
pub fn compressed_i32(data: &[u8]) -> Option<i32> {
    let encoded = compressed_u32(data)?;
    if encoded == u32::MAX {
        return Some(i32::MIN);
    }
    let magnitude = (encoded >> 1) as i32;
    Some(if encoded & 1 != 0 { -magnitude - 1 } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::{compressed_i32, compressed_u32};

    /// Values a Unity 6 build stores for the members of enums whose source gives them.
    #[test]
    fn compressed_numbers_read_as_the_enums_they_come_from_declare() {
        assert_eq!(compressed_u32(&[0x40]), Some(64));
        assert_eq!(compressed_u32(&[0x80, 0x80]), Some(128));
        assert_eq!(compressed_u32(&[0x81, 0x00]), Some(256));
        assert_eq!(compressed_u32(&[0xc0, 0x00, 0x40, 0x00]), Some(1 << 14));
        assert_eq!(compressed_u32(&[0xc0, 0x01, 0x00, 0x00]), Some(1 << 16));
        assert_eq!(compressed_i32(&[0x04]), Some(2));
        assert_eq!(compressed_i32(&[0x03]), Some(-2));
    }
}
