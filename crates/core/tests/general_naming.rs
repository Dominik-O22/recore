//! The names of the program the RT3 work ran on stay in the tests, where the binary they need
//! may live (`crates/*/tests`, which this scan does not enter): code and docs everywhere else
//! keep them out. Each checked-out tree carries the same source, so the scan looks for the
//! words in content and in file and directory names alike. `WORDS` is the list; matching is
//! case-insensitive, and a word counts where no alphanumeric character sits just before it,
//! which keeps identifiers such as `part3` and `sort31` out of the report.
//!
//! The scan runs with every `cargo test --release --workspace`, CI's suite, and `./check.sh`
//! runs it once more before it scores.

use std::fs;
use std::path::Path;

const WORDS: [&str; 2] = ["rt3", "railroad"];

/// Directories of these names the scan does not enter, wherever in the tree they stand: git's
/// data, build output, and the output of `mise run dist`, whose README copy would read as a
/// mention. Four of the names are from the rules of .gitignore, which have no slash in them
/// and so match at any depth — the checkout carries one of the four deeper already, the
/// `__pycache__` of the corpus scripts — and git's data is the fifth.
const UNREADABLE: [&str; 5] = [".git", "target", "__pycache__", "untrusted", "dist"];

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
        if UNREADABLE.contains(&name.as_str()) {
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
                let bytes = fs::read(&entry.path()).unwrap_or_else(|e| panic!("{}: {e}", parts.join("/")));
                if is_text(&bytes) {
                    for at in word_starts(&bytes) {
                        let line = 1 + bytes[..at].iter().filter(|&&b| b == b'\n').count();
                        let ends = bytes[at..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |i| i + at);
                        let begins = bytes[..at].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
                        let mut text = String::from_utf8_lossy(&bytes[begins..ends]).trim().to_string();
                        // A file without a line break can hold a whole binary in one line; the
                        // report keeps the words in their surroundings, not all of them. The cut
                        // stays on a character boundary: what lossy decoding made of the file
                        // has three-byte stands-in characters often enough to land mid-after
                        // 200 bytes.
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
