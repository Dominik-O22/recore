//! `recore-mcp lift --config <lift.toml>`: lifts a whole program and writes it as a cargo
//! workspace, ready to build. The config names the executable, the crate of the machine the
//! lifted code runs on, and the binary that runs it; [`Config`] gives each field.
//!
//! The roots are every function the analysis finds, every word of the data sections that points
//! into code (code reached only through tables of addresses), only the relocated ones where the
//! image keeps its relocations, and every code address the analysis finds an instruction taking
//! (callbacks it lists inside another function). The lifted functions are split into `crates`
//! crates `c0`..`cN` of about the same size, so rustc checks them in parallel; every call between
//! functions goes through `dispatch`, so a port in the binary's `ports` replaces a lifted function
//! for every caller.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use recore::{FxHashMap, Image};
use serde::Deserialize;

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
    /// The crate of the machine the lifted code runs on, `recore-machine` at crates/machine or
    /// one with its API; the lifted crates `use <name>::*`.
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
    let mut cache = Cache::new(false);
    let roots = roots(&mut cache, &exe)?;
    let abi = config_file.x87.as_ref().map_or_else(X87Abi::default, |x| X87Abi { runtime: x.runtime, helpers: x.helpers.iter().map(|h| (h.at, (h.takes, h.net))).collect() });
    let program = lift(cache.get(&exe)?, &roots, &abi)?;
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("report.txt"), &program.report)?;
    let count = write(&config_file, &base, &out, program.functions)?;
    let first = program.report.lines().next().unwrap_or_default().to_string();
    Ok(format!("{first} ({} roots; the failures are in {})\n{count} functions in {} crates under {}\n", roots.len(), out.join("report.txt").display(), config_file.crates, out.display()))
}

/// The roots to lift: the analysis's functions, then the code addresses found in data and taken
/// by instructions that are not functions, each in address order. A code address in data is a
/// word of [`data_words`] that lands in code, as the table of handlers a C runtime helper jumps
/// through; one an instruction takes is an immediate the analysis found it taking, as a callback
/// one function pushes and the analysis lists inside another. Either is dropped when it lands
/// inside an instruction of a function the analysis found. The lifter takes roots from the end,
/// so the order fixes the order of the output.
fn roots(cache: &mut Cache, exe: &Path) -> Result<Vec<u64>> {
    let program = &cache.get(exe)?.program;
    let image = &program.image;
    let functions: BTreeSet<u64> = program.functions().map(|f| f.addr).collect();
    let taken = program.analysis.data_refs.iter().filter(|r| !r.access).map(|r| r.to);
    let mut extra: BTreeSet<u64> = data_words(image).into_iter().chain(taken).filter(|&v| image.is_code(v) && !functions.contains(&v)).collect();
    // Compiled code never jumps into the middle of an instruction, so a value that lands inside a
    // function's body on no instruction the analysis decoded there is not a code address, most
    // often a short string: "SOF\0" reads as 0x464f53.
    let mut starts: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    extra.retain(|&v| {
        let owners = program.owners(v);
        owners.is_empty()
            || owners.iter().any(|&owner| {
                let instructions = starts.entry(owner).or_insert_with(|| recore::cfg::cfg(image, &program.analysis, &program.body(owner)).instructions);
                instructions.binary_search(&v).is_ok()
            })
    });
    Ok(functions.into_iter().chain(extra).collect())
}

/// The words outside code that may be addresses. An image that keeps its relocations names them:
/// its relocated words. One linked to load only at its base names none, so every aligned word
/// outside code and resources may be one, not only the image's pointer slots: those leave out
/// words that read as text, and a table of handlers can (0x46205c reads as "\ F"). A word that is
/// not an address costs a lifted function; an address missed costs a crash when it is called.
fn data_words(image: &Image) -> Vec<u64> {
    if !image.relocations_stripped {
        return image.relative_targets.iter().filter(|&&(slot, _)| !image.is_code(slot)).map(|&(_, target)| target).collect();
    }
    let data = image.sections.iter().filter(|s| !s.executable && s.name != ".rsrc");
    data.flat_map(|s| s.data.as_chunks::<4>().0.iter().map(|&word| u64::from(u32::from_le_bytes(word)))).collect()
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

#[cfg(test)]
mod tests {
    use recore::image::{Format, Machine, Section};

    use super::*;

    #[test]
    fn data_words_are_the_relocated_ones_where_the_image_keeps_relocations() {
        let section = |name: &str, addr: u64, words: &[u32], executable: bool| Section {
            name: name.into(),
            addr,
            data: words.iter().flat_map(|w| w.to_le_bytes()).collect(),
            file_offset: None,
            executable,
            writable: false,
        };
        let image = || {
            let sections = vec![
                section(".text", 0x40_1000, &[0x40_1010], true),
                section(".data", 0x40_2000, &[0x40_1020, 0x40_1030], false),
                section(".rsrc", 0x40_3000, &[0x40_1040], false),
            ];
            Image::bare("game".into(), Format::Pe, Machine::X86, 0x40_1000, sections)
        };
        // Relocated: a word of .data, and an immediate in .text, which the analysis reads instead.
        let relocated = Image { relative_targets: vec![(0x40_2004, 0x40_1030), (0x40_1000, 0x40_1010)], ..image() };
        assert_eq!(data_words(&relocated), [0x40_1030]);
        // Linked to load only at its base: every word outside code and resources.
        let fixed = Image { relocations_stripped: true, ..image() };
        assert_eq!(data_words(&fixed), [0x40_1020, 0x40_1030]);
    }

    /// A function as the lifter writes it, with `body` after its first line.
    fn lifted(entry: u64, doc: &str, body: &str) -> Function {
        let text = format!("#[allow(unused)]\n{doc}pub fn f_{entry:x}(c: &mut Cpu) {{\n    let mut pc: u32 = {entry:#x};\n{body}}}\n");
        Function { entry, doc: doc.to_string(), text }
    }

    #[test]
    fn entries_share_a_body_only_when_their_text_is_the_same() {
        let named = lifted(0x10, "#[doc = \"step\"] ", "    let [mut st0] = c.sts64();\n");
        let inner = lifted(0x20, "", "    let [mut st0] = c.sts64();\n");
        // The same code entered with an x87 stack the ABI does not describe keeps its registers
        // whole, so its text differs.
        let odd = lifted(0x30, "", "    let [mut st0] = c.sts();\n");
        let other = lifted(0x40, "", "    r0 = 1;\n");
        let (odd_text, other_text) = (odd.text.clone(), other.text.clone());
        let shared = "#[allow(unused)]\npub fn b_10(c: &mut Cpu, start: u32) {\n    let mut pc: u32 = start;\n    let [mut st0] = c.sts64();\n}\n\
            #[allow(unused)] #[doc = \"step\"] pub fn f_10(c: &mut Cpu) { b_10(c, 0x10) }\n\
            #[allow(unused)] pub fn f_20(c: &mut Cpu) { b_10(c, 0x20) }\n";
        assert_eq!(units(vec![named, odd, inner, other]), [(vec![0x10, 0x20], shared.to_string()), (vec![0x30], odd_text), (vec![0x40], other_text)]);
    }

    #[test]
    fn writes_a_workspace_of_the_lifted_crates_and_the_binary() {
        let config: Config = toml::from_str(
            r#"
            exe = "game.exe"
            out = "out/game"
            crates = 2
            optimize = ["the-machine"]
            [runtime]
            name = "the-machine"
            path = "crates/machine"
            [binary]
            name = "game"
            deps = [{ name = "host", path = "../shared/host" }]
            run = "host::run"
            ports = "host::PORTS"
            "#,
        )
        .unwrap();
        let out = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")).join(format!("recore-lift-workspace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        // What an earlier lift into more crates left, and the build it kept.
        for dir in ["c5/src", "game/src", "target/release"] {
            std::fs::create_dir_all(out.join(dir)).unwrap();
        }
        let caller = lifted(0x10, "", "    f_20(c); f_20(c); return;\n");
        let callee = lifted(0x20, "", "    return;\n");
        assert_eq!(write(&config, Path::new("/project"), &out, vec![callee, caller]).unwrap(), 2);

        let read = |path: &str| std::fs::read_to_string(out.join(path)).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["Cargo.toml", "c0", "c1", "game", "target"]);
        let workspace = read("Cargo.toml");
        assert!(workspace.contains("members = [\"game\", \"c0\", \"c1\"]"), "{workspace}");
        assert!(workspace.contains("[profile.release.package.the-machine]\nopt-level = 3\n"), "{workspace}");
        assert_eq!(read("c0/Cargo.toml"), "[package]\nname = \"c0\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nthe-machine = { path = \"/project/crates/machine\" }\n");
        assert_eq!(
            read("game/Cargo.toml"),
            "[package]\nname = \"game\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nhost = { path = \"/shared/host\" }\nc0 = { path = \"../c0\" }\nc1 = { path = \"../c1\" }\n"
        );
        assert_eq!(
            read("game/src/main.rs"),
            "fn main() {\n    let mut all = Vec::new();\n    all.extend_from_slice(c0::FUNCTIONS);\n    all.extend_from_slice(c1::FUNCTIONS);\n    all.extend_from_slice(host::PORTS);\n    host::run(all);\n}\n"
        );
        // The larger function goes to the first crate, and every call goes through `dispatch`.
        let (first, second) = (read("c0/src/lib.rs"), read("c1/src/lib.rs"));
        assert!(first.contains("use the_machine::*;\n") && first.contains("    dispatch(c, 0x20); dispatch(c, 0x20); return;\n"), "{first}");
        assert!(first.ends_with("pub const FUNCTIONS: &[(u32, Lifted)] = &[\n    (0x10, f_10),\n];\n"), "{first}");
        assert!(second.ends_with("pub const FUNCTIONS: &[(u32, Lifted)] = &[\n    (0x20, f_20),\n];\n"), "{second}");
        std::fs::remove_dir_all(&out).unwrap();
    }
}
