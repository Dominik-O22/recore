//! What a person or an agent has said about a binary: names, comments and data types.
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
}

impl Edits {
    /// Where the edits of the binary at `path` are kept.
    pub fn file(path: &Path) -> Result<PathBuf> {
        let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
        let mut hasher = rustc_hash::FxHasher::default();
        hasher.write(&data);
        let dir = match (std::env::var_os(DIR_VAR), std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME")) {
            (Some(dir), _, _) => PathBuf::from(dir),
            (None, Some(data_home), _) => PathBuf::from(data_home).join("recore/edits"),
            (None, None, Some(home)) => PathBuf::from(home).join(".local/share/recore/edits"),
            (None, None, None) => anyhow::bail!("no home directory to keep edits in; set {DIR_VAR}"),
        };
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        Ok(dir.join(format!("{name}-{:016x}.json", hasher.finish())))
    }

    /// The edits made to the binary at `path` so far; none if there is no file yet.
    pub fn load(path: &Path) -> Result<Edits> {
        let file = Edits::file(path)?;
        match std::fs::read(&file) {
            Ok(data) => serde_json::from_slice(&data).with_context(|| format!("reading {file:?}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Edits::default()),
            Err(error) => Err(error).with_context(|| format!("reading {file:?}")),
        }
    }

    /// Writes the edits of the binary at `path`, through a temporary file so that a reader never
    /// sees half of them.
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = Edits::file(path)?;
        std::fs::create_dir_all(file.parent().context("edits file has a directory")?)?;
        let partial = file.with_extension("json.partial");
        std::fs::write(&partial, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&partial, &file).with_context(|| format!("writing {file:?}"))
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
