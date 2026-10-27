//! The names of the games recore's work ran on stay in the tests that need their binaries, under
//! `crates/*/tests`, which this scan does not enter. Everywhere else in the checkout, the scan
//! fails on a word of `WORDS` in a file's contents or in a file or directory name. Matching
//! ignores case, and a word counts only when no letter or digit comes just before it, so
//! identifiers such as `sort31` do not count.
//!
//! CI runs the scan with `cargo test --release --workspace`, and `./check.sh` runs it before
//! it scores the corpora.

use std::fs;
use std::path::Path;

const WORDS: [&str; 3] = ["rt3", "railroad", "tanktics"];

/// Directories the scan does not enter, at any depth: git's data, and the four names
/// .gitignore ignores at any depth (build output, Python's caches such as
/// `corpus/__pycache__`, downloads, and the output of `mise run dist`, whose README copy would
/// count as a mention).
const SKIPPED: [&str; 5] = [".git", "target", "__pycache__", "untrusted", "dist"];

/// Every byte offset in `bytes` where a word of `WORDS` stands apart, in order. A word stands
/// apart when no alphanumeric character sits just before it, so that what an identifier could
/// carry on, `sort31` beside its `rt3`, does not make a name.
fn word_starts(bytes: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    for word in WORDS.map(str::as_bytes) {
        let Some(last) = bytes.len().checked_sub(word.len()) else { continue };
        for at in 0..=last {
            if bytes[at..at + word.len()].iter().zip(word).all(|(&a, &w)| a.eq_ignore_ascii_case(&w))
                && (at == 0 || !bytes[at - 1].is_ascii_alphanumeric())
            {
                starts.push(at);
            }
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// Whether file contents tell text: without a NUL in their first block, whatever length.
fn is_text(bytes: &[u8]) -> bool {
    !bytes[..bytes.len().min(8192)].contains(&0)
}

fn walk(dir: &Path, parts: &mut Vec<String>, hits: &mut Vec<String>) {
    let here = parts.join("/");
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap_or_else(|e| panic!("{here}: {e}"))
        .map(|entry| entry.unwrap_or_else(|e| panic!("{here}: {e}")))
        .collect();
    entries.sort_unstable_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if SKIPPED.contains(&name.as_str()) {
            continue;
        }
        parts.push(name);
        // The tests are where a program's names belong, with the data and the fixtures a test
        // of `rt3.rs` carries beside them: a directory crates/<crate>/tests, exactly this
        // deep, is not entered, and so nothing under it is looked at.
        if parts.len() == 3 && parts[0] == "crates" && parts[2] == "tests" {
            parts.pop();
            continue;
        }
        let named = !word_starts(parts.last().unwrap().as_bytes()).is_empty();
        if named {
            hits.push(format!("{}: the name carries one of the words", parts.join("/")));
        } else {
            let kind = entry.file_type().unwrap_or_else(|e| panic!("{here}: {e}"));
            if kind.is_dir() {
                walk(&entry.path(), parts, hits);
            } else if kind.is_file() {
                let bytes = fs::read(entry.path()).unwrap_or_else(|e| panic!("{}: {e}", parts.join("/")));
                if is_text(&bytes) {
                    for at in word_starts(&bytes) {
                        let line = 1 + bytes[..at].iter().filter(|&&b| b == b'\n').count();
                        let ends = bytes[at..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |i| i + at);
                        let begins = bytes[..at].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
                        let mut text = String::from_utf8_lossy(&bytes[begins..ends]).trim().to_string();
                        // A file with no line breaks is one long line, so the report keeps 200
                        // bytes of it. The cut moves back to a character boundary, since lossy
                        // decoding gives 3-byte replacement characters.
                        if text.len() > 200 {
                            let mut cut = 200;
                            while !text.is_char_boundary(cut) {
                                cut -= 1;
                            }
                            text.truncate(cut);
                            text.push_str(" ...");
                        }
                        hits.push(format!("{}:{line}: {text}", parts.join("/")));
                    }
                }
            }
        }
        parts.pop();
    }
}

#[test]
fn names_stay_in_the_tests() {
    // The workspace root: above this test's crate, `crates/core`, by two levels.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).unwrap();
    let mut parts = Vec::new();
    let mut hits = Vec::new();
    walk(root, &mut parts, &mut hits);
    // The same file and line once, whatever number of the words it carries.
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "game-specific code and docs belong in tests only, under crates/*/tests. Found:\n{}",
        hits.join("\n")
    );
}

#[test]
fn a_word_inside_an_identifier_is_not_a_name() {
    assert_eq!(word_starts(b"RECORE_RT3 sort31 chart3x partsort3 Railroad"), [7, 36]);
}
