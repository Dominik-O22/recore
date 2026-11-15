//! What a person or an agent has said about a binary: names, comments, data types and structs.
//!
//! Edits are kept in one JSON file per binary, apart from the binary and keyed by its contents,
//! so they survive a move and never apply to a file that has changed. Everything that analyzes
//! the binary reads the file and applies it, which is how an edit reaches the decompiler.

use std::collections::BTreeMap;
use std::hash::Hasher;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::report::Analysis;
use crate::structs::{FieldType, Layout, NameError, Recovered, Slot, auto_function, is_identifier};

/// Names the directory edits are kept in, instead of the user's data directory.
pub const DIR_VAR: &str = "RECORE_EDITS_DIR";

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Edits {
    /// Names given to addresses: a function entry, or data.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<u64, String>,
    /// Notes on addresses, shown wherever the address is.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub comments: BTreeMap<u64, String>,
    /// C declarations in the order they were made: structs, unions, enums and typedefs, and
    /// `extern` prototypes of named functions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declarations: Vec<String>,
    /// Names given to variables inside functions: function entry, then the variable's place as
    /// the decompiler reports it, then the name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub locals: BTreeMap<u64, BTreeMap<String, String>>,
    /// The C type of the data at an address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub types: BTreeMap<u64, String>,
    /// Structs with exact field offsets, by name: those named, and the recovered structs they
    /// point to or are pointed to by, under their recovered names until those are named too.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub structs: BTreeMap<String, Layout>,
    /// Where functions are passed a pointer to one of `structs`: function entry, then the
    /// register or stack slot. Kept apart from any name, so renames leave them be.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub holders: BTreeMap<u64, BTreeMap<Slot, String>>,
}

/// What [`Edits::name_struct`] did besides renaming: the layout of the struct named when two
/// became one, before and after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub before: Layout,
    pub after: Layout,
}

/// Where the edits of one binary are kept: a file in the edits directory named after the
/// binary's file name and the XXH3-64 of its contents. XXH3 has a published specification
/// (github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md), so the name stays the same from
/// one version of recore to the next. Working it out reads the whole binary, so a program loaded
/// once keeps it rather than reading the binary again on every save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditsFile(PathBuf);

impl EditsFile {
    /// Where the edits of the binary at `binary` are kept, in the directory [`DIR_VAR`] names or
    /// else the user's data directory.
    pub fn of(binary: &Path) -> Result<EditsFile> {
        let dir = match (std::env::var_os(DIR_VAR), std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME")) {
            (Some(dir), _, _) => PathBuf::from(dir),
            (None, Some(data_home), _) => PathBuf::from(data_home).join("recore/edits"),
            (None, None, Some(home)) => PathBuf::from(home).join(".local/share/recore/edits"),
            (None, None, None) => anyhow::bail!("no home directory to keep edits in; set {DIR_VAR}"),
        };
        EditsFile::in_dir(&dir, binary)
    }

    /// Where the edits of the binary at `binary` are kept in `dir`. Edits kept there under the
    /// key recore used before are saved under this one the first time.
    fn in_dir(dir: &Path, binary: &Path) -> Result<EditsFile> {
        let data = std::fs::read(binary).with_context(|| format!("reading {binary:?}"))?;
        let name = binary.file_name().unwrap_or_default().to_string_lossy();
        let file = EditsFile(dir.join(format!("{name}-{:016x}.json", key(&data))));
        if !file.0.exists()
            && let Some(old) = legacy_file(dir, &name, &data)
        {
            let edits = read(&old)?;
            edits.save(&file)?;
        }
        Ok(file)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The edits made so far; none if there is no file yet.
    pub fn load(&self) -> Result<Edits> {
        match read(&self.0) {
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => Ok(Edits::default()),
            result => result,
        }
    }
}

/// The key edits are kept under: XXH3-64 with seed 0.
fn key(data: &[u8]) -> u64 {
    twox_hash::XxHash3_64::oneshot(data)
}

/// The file recore kept a binary's edits in before [`key`], when it named them after
/// rustc-hash 2.1's `FxHasher`, whose values may change with any release; `None` when there is
/// none. The directory is listed first, so that a binary with no edits under its name costs no
/// second hash of its contents.
fn legacy_file(dir: &Path, name: &str, data: &[u8]) -> Option<PathBuf> {
    let prefix = format!("{name}-");
    let named = |entry: std::fs::DirEntry| entry.file_name().to_str().is_some_and(|file| file.starts_with(&prefix) && file.ends_with(".json"));
    if !std::fs::read_dir(dir).ok()?.flatten().any(named) {
        return None;
    }
    let mut hasher = rustc_hash::FxHasher::default();
    hasher.write(data);
    Some(dir.join(format!("{name}-{:016x}.json", hasher.finish()))).filter(|file| file.exists())
}

/// The edits in `file`, checked.
fn read(file: &Path) -> Result<Edits> {
    let data = std::fs::read(file).with_context(|| format!("reading {file:?}"))?;
    let edits: Edits = serde_json::from_slice(&data).with_context(|| format!("reading {file:?}"))?;
    edits.check().with_context(|| format!("reading {file:?}"))?;
    Ok(edits)
}

impl Edits {
    /// The edits made to the binary at `binary` so far; none if there is no file yet.
    pub fn load(binary: &Path) -> Result<Edits> {
        EditsFile::of(binary)?.load()
    }

    /// Writes the edits to `file`, through a temporary file so that a reader never sees half of
    /// them. The temporary file is this process's own, so two processes may write at once.
    pub fn save(&self, file: &EditsFile) -> Result<()> {
        let file = &file.0;
        std::fs::create_dir_all(file.parent().context("edits file has a directory")?)?;
        let partial = file.with_extension(format!("json.{}.partial", std::process::id()));
        std::fs::write(&partial, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&partial, file).with_context(|| format!("writing {file:?}"))
    }

    /// Checks what serde cannot see one struct at a time: names, and that every struct a field
    /// or a holder names is there.
    fn check(&self) -> Result<()> {
        for (name, layout) in &self.structs {
            anyhow::ensure!(is_identifier(name), "struct `{name}` has no C name");
            for field in layout.fields().values() {
                if let FieldType::Struct(target) = &field.ty {
                    anyhow::ensure!(self.structs.contains_key(target), "a field of struct `{name}` points to `{target}`, which is not among the structs");
                }
            }
        }
        for (function, slots) in &self.holders {
            for (slot, name) in slots {
                anyhow::ensure!(self.structs.contains_key(name), "{function:#x} {slot} holds `{name}`, which is not among the structs");
            }
        }
        Ok(())
    }

    /// Keeps a recovered struct and the ones it points to under their recovered names, and its
    /// slot as their holder, so that they outlive the session and can be named. Structs kept
    /// already stay as they are.
    pub fn adopt(&mut self, recovered: &Recovered) {
        for (name, layout) in &recovered.structs {
            self.structs.entry(name.clone()).or_insert_with(|| layout.clone());
        }
        if let Some((root, _)) = recovered.structs.first() {
            self.holders.entry(recovered.function).or_default().insert(recovered.slot.clone(), root.clone());
        }
    }

    /// Renames the kept struct `old` to `new`, and every field and holder that names it. If
    /// `new` is a struct already, the two become one: both layouts merge, or nothing changes
    /// and the error names the fields that cross.
    pub fn name_struct(&mut self, old: &str, new: &str) -> Result<Option<Joined>, NameError> {
        if !is_identifier(new) {
            return Err(NameError::NotAName(new.to_string()));
        }
        if auto_function(new).is_some() {
            return Err(NameError::AutoForm(new.to_string()));
        }
        let Some(layout) = self.structs.get(old) else { return Err(NameError::NoSuchStruct(old.to_string())) };
        if old == new {
            return Ok(None);
        }
        let joined = match self.structs.get(new) {
            Some(into) => {
                let after = into.merge(layout).map_err(|clash| NameError::Clash { joining: old.to_string(), into: new.to_string(), clash })?;
                Some(Joined { before: into.clone(), after })
            }
            None => None,
        };
        let layout = self.structs.remove(old).expect("looked up");
        self.structs.insert(new.to_string(), joined.as_ref().map_or(layout, |joined| joined.after.clone()));
        let retarget = |name: &str| if name == old { new.to_string() } else { name.to_string() };
        for layout in self.structs.values_mut() {
            *layout = layout.renamed(retarget);
        }
        for name in self.holders.values_mut().flat_map(|slots| slots.values_mut()) {
            *name = retarget(name);
        }
        Ok(joined)
    }

    /// Names the field called `field` of the kept struct `name`; an empty `new` gives it back
    /// its first name. Returns the field's offset.
    pub fn name_field(&mut self, name: &str, field: &str, new: &str) -> Result<u64, NameError> {
        let layout = self.structs.get_mut(name).ok_or_else(|| NameError::NoSuchStruct(name.to_string()))?;
        let offset = layout.field_named(field).ok_or_else(|| NameError::NoSuchField(format!("`{field}` in {name}")))?;
        layout.rename_field(offset, new)?;
        Ok(offset)
    }

    /// Gives the functions their edited names. Names on other addresses stay here; `data_names`
    /// lists them.
    pub fn apply(&self, analysis: &mut Analysis) {
        for function in analysis.functions.iter_mut().filter(|f| f.fragment_of.is_none()) {
            if let Some(name) = self.names.get(&function.addr) {
                function.name = Some(name.clone());
            }
        }
    }

    /// Names and types of addresses that are not function entries, as `(address, name, type)`.
    /// Data that has a type but no name is called `DAT_` and its address, as Ghidra calls it.
    pub fn globals(&self, analysis: &Analysis) -> Vec<(u64, String, Option<&str>)> {
        let is_function = |addr: u64| analysis.functions.binary_search_by_key(&addr, |f| f.addr).is_ok_and(|index| analysis.functions[index].fragment_of.is_none());
        let named = self.names.iter().filter(|&(&addr, _)| !is_function(addr)).map(|(&addr, name)| (addr, name.clone(), self.types.get(&addr).map(String::as_str)));
        let unnamed = self.types.iter().filter(|(addr, _)| !self.names.contains_key(addr)).map(|(&addr, kind)| (addr, format!("DAT_{addr:08x}"), Some(kind.as_str())));
        named.chain(unnamed).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::Field;

    fn layout(size: u64, fields: &[(u64, u32, FieldType)]) -> Layout {
        Layout::new(size, fields.iter().map(|(offset, size, ty)| (*offset, Field::new(*size, ty.clone()))).collect()).unwrap()
    }

    /// `S_401000_RDI`, whose field at 8 points to `S_401000_RDI_8`.
    fn recovered(function: u64) -> Recovered {
        let root = format!("S_{function:x}_RDI");
        let child = format!("{root}_8");
        Recovered {
            function,
            slot: Slot::Register("RDI".into()),
            structs: vec![(root, layout(0x20, &[(4, 4, FieldType::Int), (8, 8, FieldType::Struct(child.clone()))])), (child, layout(8, &[(4, 4, FieldType::Int)]))],
        }
    }

    #[test]
    fn naming_a_recovered_struct_keeps_its_tree_and_its_holder() {
        let mut edits = Edits::default();
        edits.adopt(&recovered(0x401000));
        assert_eq!(edits.name_struct("S_401000_RDI", "Connection"), Ok(None));
        assert_eq!(edits.name_struct("S_401000_RDI_8", "Session"), Ok(None));
        assert_eq!(edits.structs.keys().collect::<Vec<_>>(), ["Connection", "Session"]);
        assert_eq!(edits.structs["Connection"].fields()[&8].ty, FieldType::Struct("Session".into()));
        assert_eq!(edits.holders[&0x401000][&Slot::Register("RDI".into())], "Connection");
        assert_eq!(edits.name_field("Connection", "field_0x8", "session"), Ok(8));
        let text = serde_json::to_string(&edits).unwrap();
        let back: Edits = serde_json::from_str(&text).unwrap();
        back.check().unwrap();
        assert_eq!(back, edits);
    }

    #[test]
    fn a_second_struct_joins_one_of_the_same_name_or_says_where_they_cross() {
        let mut edits = Edits::default();
        edits.adopt(&recovered(0x401000));
        edits.name_struct("S_401000_RDI", "Connection").unwrap();
        edits.structs.insert("S_402000_RDI".into(), layout(0x28, &[(4, 4, FieldType::Int), (0x20, 8, FieldType::Unknown)]));
        edits.holders.entry(0x402000).or_default().insert(Slot::Register("RDI".into()), "S_402000_RDI".into());
        let joined = edits.name_struct("S_402000_RDI", "Connection").unwrap().unwrap();
        assert_eq!((joined.before.size(), joined.after.size()), (0x20, 0x28));
        assert_eq!(edits.holders[&0x402000][&Slot::Register("RDI".into())], "Connection");
        assert!(!edits.structs.contains_key("S_402000_RDI"));

        edits.structs.insert("S_403000_RDI".into(), layout(0x10, &[(6, 4, FieldType::Int)]));
        let refused = edits.name_struct("S_403000_RDI", "Connection").unwrap_err();
        assert_eq!(refused.to_string(), "cannot join Connection: S_403000_RDI has 4 bytes at +0x6, across Connection.field_0x4 (+0x4, 4 bytes)");
        assert!(edits.structs.contains_key("S_403000_RDI"));
    }

    #[test]
    fn a_struct_takes_no_name_of_the_recovered_form() {
        let mut edits = Edits::default();
        edits.adopt(&recovered(0x401000));
        assert_eq!(edits.name_struct("S_401000_RDI", "S_1_RDI"), Err(NameError::AutoForm("S_1_RDI".into())));
        assert_eq!(edits.name_struct("S_401000_RDI", "a b"), Err(NameError::NotAName("a b".into())));
    }

    /// The key is XXH3-64 as its specification defines it: `xxhsum -H3` prints 442e12e10f45c07a
    /// for these bytes. A change here orphans every user's saved edits.
    #[test]
    fn the_key_of_a_binary_is_its_xxh3() {
        assert_eq!(key(b"recore"), 0x442e_12e1_0f45_c07a);
    }

    /// Edits saved under the old key, here the one rustc-hash 2.1.3 gave the bytes `recore`,
    /// load through the new one and are saved under it.
    #[test]
    fn edits_saved_under_the_old_key_move_to_the_new_one() {
        let dir = std::env::current_exe().unwrap().with_file_name("edits-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("prog");
        std::fs::write(&binary, b"recore").unwrap();
        let old = dir.join("prog-c9ef4cc2020f04e6.json");
        std::fs::write(&old, r#"{"names":{"4198400":"main"}}"#).unwrap();

        let file = EditsFile::in_dir(&dir, &binary).unwrap();
        assert_eq!(file.path(), dir.join("prog-442e12e10f45c07a.json"));
        let edits = file.load().unwrap();
        assert_eq!(edits.names[&0x401000], "main");
        std::fs::remove_file(&old).unwrap();
        assert_eq!(EditsFile::in_dir(&dir, &binary).unwrap().load().unwrap(), edits);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn edits_that_name_a_missing_struct_are_refused_on_load() {
        let text = r#"{"structs":{"A":{"size":16,"fields":{"0":{"size":8,"type":{"struct":"B"}}}}}}"#;
        let edits: Edits = serde_json::from_str(text).unwrap();
        assert!(edits.check().unwrap_err().to_string().contains("points to `B`"));
    }
}
