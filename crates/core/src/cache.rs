//! Analyses kept on disk between processes. A large binary takes seconds to analyze, and each
//! one-shot `recore-mcp` call and each decompiler process would otherwise analyze it again.

use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::Image;
use crate::report::Analysis;

/// What an analysis was made from. A kept analysis is used only when all of it is unchanged.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Key {
    /// Size and modification time of the binary, of its IL2CPP metadata if it has any, and of
    /// the program that analyzed it, which stands for recore's code.
    binary: Stamp,
    metadata: Option<Stamp>,
    program: Stamp,
}

type Stamp = (u64, u128);

fn stamp(path: &Path) -> Option<Stamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_nanos()))
}

impl Key {
    /// None for a raw image a layout file describes, made from files the layout names.
    fn of(path: &Path) -> Option<Key> {
        if crate::layout::is_layout(path) {
            return None;
        }
        let metadata = match crate::il2cpp::find(path) {
            Some(file) => Some(stamp(&file)?),
            None => None,
        };
        Some(Key { binary: stamp(path)?, metadata, program: stamp(&std::env::current_exe().ok()?)? })
    }
}

/// The analysis of `image`, loaded from `path`: the one kept from an earlier process if nothing
/// it was made from has changed, or a new one, which is then kept. Keeping is best effort: a
/// file that cannot be read or written costs only the time to analyze.
pub fn analyze(path: &Path, image: &Image) -> Analysis {
    let Some((key, file)) = Key::of(path).zip(file(path)) else {
        return crate::analyze(image);
    };
    if let Some(analysis) = read(&file, &key) {
        return analysis;
    }
    let analysis = crate::analyze(image);
    write(&file, &key, &analysis);
    analysis
}

/// Where the analysis of the binary at `path` is kept, one file per path.
fn file(path: &Path) -> Option<PathBuf> {
    let dir = match (std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME")) {
        (Some(cache), _) => PathBuf::from(cache).join("recore/analysis"),
        (None, Some(home)) => PathBuf::from(home).join(".cache/recore/analysis"),
        (None, None) => return None,
    };
    let path = std::path::absolute(path).ok()?;
    let hash = rustc_hash::FxBuildHasher.hash_one(&path);
    Some(dir.join(format!("{}-{hash:016x}", path.file_name()?.to_string_lossy())))
}

/// The file holds the key as JSON on its first line and the analysis after it in bitcode, which
/// reads several times faster than JSON. A stale file is turned down without reading the rest.
fn read(file: &Path, key: &Key) -> Option<Analysis> {
    let mut reader = BufReader::new(std::fs::File::open(file).ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    if serde_json::from_str::<Key>(&line).ok()? != *key {
        return None;
    }
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).ok()?;
    bitcode::decode(&rest).ok()
}

/// Writes through a file of this process's own, so that a reader never sees half an analysis
/// and two processes that analyzed at once each write a whole one. A file cut short by a crash
/// fails to parse and is analyzed again.
fn write(file: &Path, key: &Key, analysis: &Analysis) {
    let partial = file.with_file_name(format!("{}.partial.{}", file.file_name().expect("named").to_string_lossy(), std::process::id()));
    let written = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(file.parent().expect("kept in a directory"))?;
        let mut out = std::io::BufWriter::new(std::fs::File::create(&partial)?);
        serde_json::to_writer(&mut out, key)?;
        out.write_all(b"\n")?;
        out.write_all(&bitcode::encode(analysis))?;
        out.flush()?;
        std::fs::rename(&partial, file)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An analysis read back is the analysis written, and one made from something else is not
    /// read back.
    #[test]
    fn a_kept_analysis_is_read_back_only_under_its_own_key() {
        let binary = std::env::current_exe().unwrap();
        let image = Image::load(&binary).unwrap();
        let analysis = crate::analyze(&image);
        let dir = binary.with_file_name("cache-test");
        let file = dir.join("kept");
        let key = Key::of(&binary).unwrap();
        write(&file, &key, &analysis);
        let back = read(&file, &key).expect("read back");
        assert_eq!(serde_json::to_value(&back).unwrap(), serde_json::to_value(&analysis).unwrap());
        let changed = Key { binary: (key.binary.0 + 1, key.binary.1), ..Key::of(&binary).unwrap() };
        assert!(read(&file, &changed).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
