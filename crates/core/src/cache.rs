//! Analyses kept on disk between processes. A large binary takes seconds to analyze, and each
//! one-shot `recore-mcp` call and each decompiler process would otherwise analyze it again.

use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::Image;
use crate::report::Analysis;

/// Names the directory analyses are kept in, instead of `recore/analysis` in the user's cache
/// directory.
pub const DIR_VAR: &str = "RECORE_CACHE_DIR";

/// The most bytes of analyses kept. Past it the least recently used go, and with them those of
/// programs since rebuilt.
const LIMIT: u64 = 2 << 30;

/// A partial file this old was left by a process that died writing it.
const ABANDONED: Duration = Duration::from_secs(3600);

/// recore's directory in the user's cache directory, if there is a home to find it by.
pub fn dir() -> Option<PathBuf> {
    match (std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME")) {
        (Some(cache), _) => Some(PathBuf::from(cache).join("recore")),
        (None, Some(home)) => Some(PathBuf::from(home).join(".cache/recore")),
        (None, None) => None,
    }
}

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
    let Some((file, key)) = Key::of(path).and_then(|key| Some((file(path, &key)?, key))) else {
        return crate::analyze(image);
    };
    if let Some(analysis) = read(&file, &key) {
        return analysis;
    }
    let analysis = crate::analyze(image);
    write(&file, &key, &analysis);
    analysis
}

/// Where the analysis `key` names of the binary at `path` is kept: one file per binary and
/// program, so that two programs that analyze one binary do not take turns replacing it.
fn file(path: &Path, key: &Key) -> Option<PathBuf> {
    let dir = std::env::var_os(DIR_VAR).filter(|dir| !dir.is_empty()).map(PathBuf::from).or_else(|| Some(dir()?.join("analysis")))?;
    let path = std::path::absolute(path).ok()?;
    let hash = rustc_hash::FxBuildHasher.hash_one((&path, key.program));
    Some(dir.join(format!("{}-{hash:016x}", path.file_name()?.to_string_lossy())))
}

/// Whether an analysis of the binary at `path` is kept that [`analyze`] would use.
pub fn is_kept(path: &Path) -> bool {
    Key::of(path).is_some_and(|key| file(path, &key).is_some_and(|file| open(&file, &key).is_some()))
}

/// The file holds the key as JSON on its first line and the analysis after it in bitcode, a
/// quarter the size of JSON. A stale file is turned down without reading the rest.
fn open(file: &Path, key: &Key) -> Option<BufReader<std::fs::File>> {
    let mut reader = BufReader::new(std::fs::File::open(file).ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    (serde_json::from_str::<Key>(&line).ok()? == *key).then_some(reader)
}

/// The analysis kept in `file`, which then counts as used last.
fn read(file: &Path, key: &Key) -> Option<Analysis> {
    let mut reader = open(file, key)?;
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).ok()?;
    let analysis = bitcode::decode(&rest).ok()?;
    let _ = reader.get_ref().set_modified(SystemTime::now());
    Some(analysis)
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
    tidy(file.parent().expect("kept in a directory"), LIMIT, file);
}

/// What a file named `name` in the directory is, judged by the names [`file`] and [`write`]
/// give: `None` for one that is not recore's.
fn kind(name: &str) -> Option<Kind> {
    let is_analysis = |name: &str| name.rsplit_once('-').is_some_and(|(_, hash)| hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    match name.rsplit_once(".partial.") {
        Some((analysis, process)) if is_analysis(analysis) && !process.is_empty() && process.bytes().all(|byte| byte.is_ascii_digit()) => Some(Kind::Partial),
        _ => is_analysis(name).then_some(Kind::Analysis),
    }
}

enum Kind {
    Analysis,
    /// One being written, or left by a process that died writing it.
    Partial,
}

/// Removes partial files left in `dir` by processes that died writing them, and the least
/// recently used analyses past `limit` bytes, but never `written`, the one just kept.
fn tidy(dir: &Path, limit: u64, written: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut kept: Vec<(SystemTime, u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let (Some(kind), Ok(metadata)) = (kind(&entry.file_name().to_string_lossy()), entry.metadata()) else { continue };
        let used = metadata.modified().unwrap_or(UNIX_EPOCH);
        match kind {
            Kind::Partial if used.elapsed().is_ok_and(|age| age > ABANDONED) => {
                let _ = std::fs::remove_file(entry.path());
            }
            Kind::Partial => {}
            Kind::Analysis => kept.push((used, metadata.len(), entry.path())),
        }
    }
    kept.sort_unstable();
    let mut total: u64 = kept.iter().map(|file| file.1).sum();
    for (_, len, path) in kept {
        if total <= limit {
            break;
        }
        if path != written && std::fs::remove_file(&path).is_ok() {
            total -= len;
        }
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

    /// Past the limit the least recently used analyses go, and so do partial files left long
    /// ago. Files that are not recore's stay.
    #[test]
    fn tidying_removes_the_least_recently_used_and_abandoned_partials() {
        let dir = std::env::current_exe().unwrap().with_file_name("cache-tidy-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = SystemTime::now();
        let old = "old.so-0000000000000001";
        let files = [
            (old, 300),
            ("used.so-0000000000000002", 100),
            ("new.so-0000000000000003", 0),
            ("left.so-0000000000000004.partial.1", 2 * ABANDONED.as_secs()),
            ("writing.so-0000000000000005.partial.2", 10),
            ("notes.txt", 400),
        ];
        for (name, age) in files {
            std::fs::write(dir.join(name), [0u8; 10]).unwrap();
            std::fs::File::options().write(true).open(dir.join(name)).unwrap().set_modified(now - Duration::from_secs(age)).unwrap();
        }
        tidy(&dir, 20, &dir.join("new.so-0000000000000003"));
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["new.so-0000000000000003", "notes.txt", "used.so-0000000000000002", "writing.so-0000000000000005.partial.2"]);
        // The one just written stays, however large.
        tidy(&dir, 0, &dir.join("new.so-0000000000000003"));
        assert!(dir.join("new.so-0000000000000003").exists() && !dir.join(old).exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
