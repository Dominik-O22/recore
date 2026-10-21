//! `recore-mcp lift --config <lift.toml>`: lifts a whole program and writes it as a cargo
//! workspace, ready to build. The config names the executable, the crate of the machine the
//! lifted code runs on, and the binary that runs it; [`Config`] gives each field.
//!
//! The roots are every function the analysis finds, every word of the data sections that points
//! into code (code reached only through tables of addresses), and every code address an
//! instruction takes as an immediate that `xrefs` confirms (callbacks the analysis lists inside
//! another function). The lifted functions are split into `crates` crates `c0`..`cN` of about the
//! same size, so rustc checks them in parallel; every call between functions goes through
//! `dispatch`, so a port in the binary's `ports` replaces a lifted function for every caller.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use recore::FxHashMap;
use serde::Deserialize;
use serde_json::json;

use super::lift::{Function, X87Abi, lift};
use crate::binary::Cache;

/// A project's lift.toml. Paths are relative to the file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The executable to lift.
    exe: PathBuf,
    /// The workspace to write; its `target` directory is kept.
    out: PathBuf,
    /// How many crates the lifted functions are split into.
    crates: usize,
    /// The crate of the machine the lifted code runs on; the lifted crates `use <name>::*`.
    runtime: Crate,
    binary: Binary,
    /// Packages built at opt-level 3; the lifted crates build at 1.
    #[serde(default)]
    optimize: Vec<String>,
    x87: Option<X87>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Crate {
    name: String,
    path: PathBuf,
}

/// The binary that runs the lifted functions: `main` collects them, then the ports, and calls
/// `run` with them all.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binary {
    name: String,
    /// Its dependencies besides the lifted crates, in this order.
    deps: Vec<Crate>,
    /// The function that runs the game, given every function by address, as `host::run`.
    run: String,
    /// A `&[(u32, Lifted)]` of functions ported to Rust, as `native::PORTS`, which replace the
    /// lifted ones at the same addresses.
    ports: Option<String>,
}

/// The x87 ABI of a statically linked C runtime ([`X87Abi`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X87 {
    /// The lowest address of the C runtime.
    runtime: u64,
    #[serde(default)]
    helpers: Vec<Helper>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Helper {
    at: u64,
    /// The x87 registers it reads at its entry, ST0 in bit 0.
    takes: u8,
    /// The values it leaves on the stack less those it found.
    net: i32,
}

/// `path`, relative to `base` unless absolute, with `.` and `..` resolved without asking the
/// file system, so the workspace names a crate the same way whatever links lie on the way.
fn resolve(base: &Path, path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in base.join(path).components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Lifts the program `config` describes into its workspace, or into `out` when given, and answers
/// a summary. The full report of what could not be lifted is in the workspace's report.txt.
pub fn run(config: &Path, out: Option<&Path>) -> Result<String> {
    let text = std::fs::read_to_string(config).with_context(|| format!("reading {}", config.display()))?;
    let config_file: Config = toml::from_str(&text).with_context(|| format!("reading {}", config.display()))?;
    let base = std::path::absolute(config.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
    let exe = resolve(&base, &config_file.exe);
    let out = out.map_or_else(|| resolve(&base, &config_file.out), |o| resolve(&std::env::current_dir().unwrap_or_default(), o));
    let mut cache = Cache::default();
    let roots = roots(&mut cache, &exe)?;
    let abi = config_file.x87.as_ref().map_or_else(X87Abi::default, |x| X87Abi { runtime: x.runtime, helpers: x.helpers.iter().map(|h| (h.at, (h.takes, h.net))).collect() });
    let program = lift(cache.get(&exe)?, &roots, &abi)?;
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("report.txt"), &program.report)?;
    let count = write(&config_file, &base, &out, program.functions)?;
    let first = program.report.lines().next().unwrap_or_default().to_string();
    Ok(format!("{first} ({} roots; the failures are in {})\n{count} functions in {} crates under {}\n", roots.len(), out.join("report.txt").display(), config_file.crates, out.display()))
}

/// A section of a PE file: its address, its size in memory, the bytes the file holds, and whether
/// it is executable (IMAGE_SCN_MEM_EXECUTE).
struct Section<'a> {
    addr: u64,
    size: u64,
    bytes: &'a [u8],
    executable: bool,
}

fn sections(data: &[u8]) -> Result<Vec<Section<'_>>> {
    let u16_at = |at: usize| data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).context("a PE header");
    let u32_at = |at: usize| data.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes"))).context("a PE header");
    let pe = u32_at(0x3c)? as usize;
    let (count, optional) = (u16_at(pe + 6)? as usize, u16_at(pe + 20)? as usize);
    let base = u64::from(u32_at(pe + 24 + 28)?);
    let table = pe + 24 + optional;
    (0..count)
        .map(|i| {
            let at = table + 40 * i;
            let (size, rva, raw_size, raw) = (u32_at(at + 8)?, u32_at(at + 12)?, u32_at(at + 16)? as usize, u32_at(at + 20)? as usize);
            let flags = u32_at(at + 36)?;
            let bytes = data.get(raw.min(data.len())..(raw + raw_size).min(data.len())).unwrap_or_default();
            Ok(Section { addr: base + u64::from(rva), size: u64::from(size), bytes, executable: flags & 0x2000_0000 != 0 })
        })
        .collect()
}

/// The roots to lift: the analysis's functions, then the code addresses found in data and taken
/// by instructions that are not functions, each in address order. The lifter takes roots from
/// the end, so the order fixes the order of the output.
fn roots(cache: &mut Cache, exe: &Path) -> Result<Vec<u64>> {
    let data = std::fs::read(exe).with_context(|| format!("reading {}", exe.display()))?;
    let functions: BTreeSet<u64> = cache.get(exe)?.program.functions().map(|f| f.addr).collect();
    let sections = sections(&data)?;
    let mut extra = code_words(&sections);
    // An immediate that only looks like an address is dropped unless `xrefs` says an instruction
    // takes it.
    let path = exe.to_string_lossy().into_owned();
    for v in immediates(&sections).into_iter().filter(|v| !functions.contains(v)) {
        let answer = crate::tools::call(cache, "xrefs", json!({ "path": path, "addr": format!("{v:#x}") })).context("the xrefs tool")?;
        if answer.is_ok_and(|text| text.contains("takes its address")) {
            extra.insert(v);
        }
    }
    Ok(functions.iter().copied().chain(extra.into_iter().filter(|v| !functions.contains(v))).collect())
}

/// Whether `v` lies in an executable section.
fn in_code(sections: &[Section], v: u64) -> bool {
    sections.iter().any(|s| s.executable && (s.addr..s.addr + s.size).contains(&v))
}

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(raw[at..at + 4].try_into().expect("4 bytes")))
}

/// Every aligned word of the data sections that points into code: code reached only through
/// tables of addresses.
fn code_words(sections: &[Section]) -> BTreeSet<u64> {
    let data = sections.iter().filter(|s| !s.executable);
    data.flat_map(|s| (0..s.bytes.len().saturating_sub(3)).step_by(4).map(|at| word(s.bytes, at))).filter(|&v| in_code(sections, v)).collect()
}

/// Code addresses an instruction may take as an immediate, such as a callback one function pushes
/// and the analysis lists inside another: the immediates of PUSH imm32, MOV reg, imm32 and
/// MOV r/m32, imm32 that land in code. The scan reads every byte as a possible opcode, so some
/// are bytes that only look like one of the three.
fn immediates(sections: &[Section]) -> BTreeSet<u64> {
    let mut taken = BTreeSet::new();
    for section in sections.iter().filter(|s| s.executable) {
        let raw = section.bytes;
        for (i, &op) in raw.iter().enumerate() {
            let at = if op == 0x68 || (0xb8..=0xbf).contains(&op) {
                i + 1
            } else if op == 0xc7 && i + 2 < raw.len() {
                let modrm = raw[i + 1];
                let (mode, rm) = (modrm >> 6, modrm & 7);
                let sib = mode != 3 && rm == 4;
                let disp = match mode {
                    0 if rm == 5 || (sib && raw[i + 2] & 7 == 5) => 4,
                    1 => 1,
                    2 => 4,
                    _ => 0,
                };
                i + 2 + usize::from(sib) + disp
            } else {
                continue;
            };
            if at + 4 <= raw.len() && in_code(sections, word(raw, at)) {
                taken.insert(word(raw, at));
            }
        }
    }
    taken
}

/// The lifted functions as units to write: a body lifted for several entries, as when a jump
/// table enters a function in the middle, is written once as `b_<first>(c, start)` with a wrapper
/// `f_<entry>` per entry that keeps the entry's doc. Bodies are grouped only when their text is the
/// same but for the name, the doc and the starting pc: the same text is the same code, x87 masks
/// included, so the wrappers behave as the copies did. Units come in the order their first
/// function was lifted.
fn units(functions: Vec<Function>) -> Vec<(Vec<u64>, String)> {
    let mut groups: Vec<(String, Vec<Function>)> = Vec::new();
    let mut index: FxHashMap<String, usize> = FxHashMap::default();
    for function in functions {
        let Function { entry, doc, text } = &function;
        let (header, start) = (format!("pub fn f_{entry:x}(c: &mut Cpu) {{"), format!("let mut pc: u32 = {entry:#x};"));
        let key = if text.contains(&header) && text.contains(&start) {
            text.replacen(doc.as_str(), "", 1).replacen(&header, "pub fn BODY(c: &mut Cpu, start: u32) {", 1).replacen(&start, "let mut pc: u32 = start;", 1)
        } else {
            text.clone()
        };
        match index.get(&key) {
            Some(&i) => groups[i].1.push(function),
            None => {
                index.insert(key.clone(), groups.len());
                groups.push((key, vec![function]));
            }
        }
    }
    groups
        .into_iter()
        .map(|(key, mut members)| {
            if members.len() == 1 {
                let only = members.remove(0);
                return (vec![only.entry], only.text);
            }
            let body = members[0].entry;
            let mut code = key.replacen("pub fn BODY(", &format!("pub fn b_{body:x}("), 1);
            for Function { entry, doc, .. } in &members {
                let _ = writeln!(code, "#[allow(unused)] {doc}pub fn f_{entry:x}(c: &mut Cpu) {{ b_{body:x}(c, {entry:#x}) }}");
            }
            (members.iter().map(|m| m.entry).collect(), code)
        })
        .collect()
}

/// Writes the workspace: the lifted crates, the binary and the workspace's Cargo.toml. Answers
/// how many functions it holds.
fn write(config: &Config, base: &Path, out: &Path, functions: Vec<Function>) -> Result<usize> {
    let n = config.crates.max(1);
    let runtime = &config.runtime.name;
    let runtime_path = resolve(base, &config.runtime.path);
    let mut chunks: Vec<Vec<(Vec<u64>, String)>> = vec![Vec::new(); n];
    let mut sizes = vec![0usize; n];
    let mut units = units(functions);
    // Largest first, each to the smallest crate so far; sizes in characters.
    units.sort_by_key(|u| std::cmp::Reverse(u.1.chars().count()));
    let mut count = 0;
    for unit in units {
        let i = (0..n).min_by_key(|&i| (sizes[i], i)).expect("a crate");
        sizes[i] += unit.1.chars().count();
        count += unit.0.len();
        chunks[i].push(unit);
    }
    for entry in std::fs::read_dir(out)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let lifted = name.strip_prefix('c').is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
        if (lifted || name == config.binary.name) && entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    let call = regex::Regex::new(r"\bf_([0-9a-f]+)\(c\)").expect("a pattern");
    let module = runtime.replace('-', "_");
    for (i, chunk) in chunks.iter().enumerate() {
        let dir = out.join(format!("c{i}/src"));
        std::fs::create_dir_all(&dir)?;
        let mut code = format!("#![allow(arithmetic_overflow, unconditional_panic, unused_comparisons, overflowing_literals, non_snake_case, clippy::all)]\nuse {module}::*;\n");
        for (_, text) in chunk {
            code.push_str(&call.replace_all(text, "dispatch(c, 0x$1)"));
        }
        code.push_str("pub const FUNCTIONS: &[(u32, Lifted)] = &[\n");
        for entry in chunk.iter().flat_map(|u| &u.0) {
            writeln!(code, "    ({entry:#x}, f_{entry:x}),")?;
        }
        code.push_str("];\n");
        std::fs::write(dir.join("lib.rs"), code)?;
        std::fs::write(out.join(format!("c{i}/Cargo.toml")), format!("[package]\nname = \"c{i}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\n{runtime} = {{ path = \"{}\" }}\n", runtime_path.display()))?;
    }
    let bin = &config.binary;
    std::fs::create_dir_all(out.join(format!("{}/src", bin.name)))?;
    let mut manifest = format!("[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\n", bin.name);
    for dep in &bin.deps {
        writeln!(manifest, "{} = {{ path = \"{}\" }}", dep.name, resolve(base, &dep.path).display())?;
    }
    for i in 0..n {
        writeln!(manifest, "c{i} = {{ path = \"../c{i}\" }}")?;
    }
    std::fs::write(out.join(format!("{}/Cargo.toml", bin.name)), manifest)?;
    let mut main = String::from("fn main() {\n    let mut all = Vec::new();\n");
    for i in 0..n {
        writeln!(main, "    all.extend_from_slice(c{i}::FUNCTIONS);")?;
    }
    if let Some(ports) = &bin.ports {
        writeln!(main, "    all.extend_from_slice({ports});")?;
    }
    writeln!(main, "    {}(all);\n}}", bin.run)?;
    std::fs::write(out.join(format!("{}/src/main.rs", bin.name)), main)?;
    let members: Vec<String> = std::iter::once(bin.name.clone()).chain((0..n).map(|i| format!("c{i}"))).map(|m| format!("\"{m}\"")).collect();
    let mut workspace = format!("[workspace]\nresolver = \"3\"\nmembers = [{}]\n\n[profile.release]\nopt-level = 1\ncodegen-units = 16\ndebug = \"line-tables-only\"\noverflow-checks = false\n\n", members.join(", "));
    if !config.optimize.is_empty() {
        workspace.push_str("# The machine, host, renderer and ports are small and run on every instruction: optimize them fully.\n");
        for package in &config.optimize {
            writeln!(workspace, "[profile.release.package.{package}]\nopt-level = 3\n")?;
        }
    }
    workspace.push_str("[profile.dev]\nopt-level = 0\ndebug = \"line-tables-only\"\noverflow-checks = false\n");
    std::fs::write(out.join("Cargo.toml"), workspace)?;
    Ok(count)
}
