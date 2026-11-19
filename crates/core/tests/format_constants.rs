//! A number the ELF format defines comes from `object::elf`, never typed in. A hand-typed
//! relocation number was once wrong (`R_AARCH64_MOVW_UABS_G3` as 270, which is
//! `R_AARCH64_MOVW_SABS_G0`), and nothing but review saw it.
//!
//! The scan reads every source file under `crates/*/src` and fails on a `const` with an ELF
//! prefix whose value is a numeric literal. An alias such as
//! `const SHT_RELA: u32 = elf::SHT_RELA.0;` passes.

use std::fs;
use std::path::Path;

use regex::Regex;

fn hand_typed() -> Regex {
    Regex::new(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?const\s+((?:R|SHT|SHF|SHN|STT|STB|STV|PT|PF|EM|ET|DT)_[A-Z0-9_]+)\s*:[^=]*=\s*-?[0-9][0-9a-zA-Z_]*\s*;")
        .unwrap()
}

fn scan(dir: &Path, pattern: &Regex, root: &Path, hits: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            scan(&path, pattern, root, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).unwrap();
            for (index, line) in text.lines().enumerate() {
                if let Some(name) = pattern.captures(line).map(|c| c[1].to_string()) {
                    hits.push(format!("{}:{}: `{name}` is typed in; use object::elf::{name}", path.strip_prefix(root).unwrap().display(), index + 1));
                }
            }
        }
    }
}

#[test]
fn elf_numbers_come_from_object() {
    // The workspace root: above this test's crate, `crates/core`, by two levels.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).unwrap();
    let pattern = hand_typed();
    let mut hits = Vec::new();
    for krate in fs::read_dir(root.join("crates")).unwrap() {
        let src = krate.unwrap().path().join("src");
        if src.is_dir() {
            scan(&src, &pattern, root, &mut hits);
        }
    }
    hits.sort();
    assert!(hits.is_empty(), "a number the ELF format defines comes from object::elf. Found:\n{}", hits.join("\n"));
}

#[test]
fn a_literal_is_caught_and_an_alias_is_not() {
    let pattern = hand_typed();
    assert!(pattern.is_match("const R_AARCH64_MOVW_UABS_G3: u32 = 270;"));
    assert!(pattern.is_match("    pub(crate) const SHT_ARM_EXIDX: u32 = 0x7000_0001;"));
    assert!(!pattern.is_match("const R_AARCH64_MOVW_UABS_G3: u32 = elf::R_AARCH64_MOVW_UABS_G3.0;"));
    assert!(!pattern.is_match("const RET: u32 = 0xd65f_03c0;"));
}
