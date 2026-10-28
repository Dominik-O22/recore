//! Lifts tests/data/lift.exe with `recore-mcp lift`, builds the workspace it writes on
//! crates/machine with tests/lift-runner as the host, and runs each function the fixture
//! exports on generated arguments twice: lifted and natively built, and in the emulator's `run`.
//! The two must return the same EAX. The fixture covers loops, a jump table, a chain of
//! compares, branches whose arms hold loops, recursion, the stack, a global, calls through a
//! table in data, and x87 arithmetic, comparisons and conversions.

mod common;

use std::path::Path;
use std::process::Command;

use common::{Client, SERVER};
use serde_json::json;

const EXE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/lift.exe");
const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

/// The fixture's exports, with how many arguments each takes.
const FUNCTIONS: [(&str, usize); 12] = [
    ("collatz", 1), ("classify", 1), ("mix", 2), ("fib", 1), ("sum_squares", 1), ("step", 1), ("apply", 2), ("length", 2), ("scaled", 2), ("halves", 1), ("arms", 2),
    ("sparse", 1),
];

/// Arguments tried on each function.
const CASES: usize = 20;

/// Arguments that are the same on every run: small numbers half the time, any word otherwise.
fn arguments(seed: &mut u64, count: usize) -> Vec<u32> {
    (0..count)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            let word = (*seed >> 16) as u32;
            if *seed & 1 == 0 { word % 200 } else { word }
        })
        .collect()
}

/// Builds the lifted fixture once and answers its binary.
fn build(dir: &Path) -> std::path::PathBuf {
    let config = dir.join("lift.toml");
    std::fs::write(
        &config,
        format!(
            "exe = {EXE:?}\nout = \"workspace\"\ncrates = 2\n\n[runtime]\nname = \"recore-machine\"\npath = \"{MANIFEST}/../machine\"\n\n\
             [binary]\nname = \"lifted\"\ndeps = [{{ name = \"lift-runner\", path = \"{MANIFEST}/tests/lift-runner\" }}]\nrun = \"lift_runner::run\"\n"
        ),
    )
    .unwrap();
    let lifted = Command::new(SERVER).args(["lift", "--config"]).arg(&config).output().unwrap();
    let summary = String::from_utf8_lossy(&lifted.stdout);
    assert!(lifted.status.success() && summary.contains("; 0 failed"), "{summary}{}", String::from_utf8_lossy(&lifted.stderr));
    // The versions recore builds with, so the build needs no registry.
    std::fs::copy(Path::new(MANIFEST).join("../../Cargo.lock"), dir.join("workspace/Cargo.lock")).unwrap();
    let built = Command::new(env!("CARGO"))
        .args(["build", "--release", "--quiet", "--manifest-path"])
        .arg(dir.join("workspace/Cargo.toml"))
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
    dir.join("target/release/lifted")
}

#[test]
fn lifted_functions_return_what_the_emulator_does() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("lift");
    std::fs::create_dir_all(&dir).unwrap();
    let lifted = build(&dir);
    let mut client = Client::start();
    let symbols = client.tool("symbols", json!({ "path": EXE })).unwrap();
    let mut seed = 0x2545_f491_4f6c_dd1d;
    let mut differ = Vec::new();
    for (name, arity) in FUNCTIONS {
        let addr = symbols.lines().find(|line| line.ends_with(&format!("function: {name}"))).and_then(|line| line.split(' ').next()).unwrap_or_else(|| panic!("{name} in {symbols}"));
        for _ in 0..CASES {
            let args = arguments(&mut seed, arity);
            let emulated = client.tool("run", json!({ "path": EXE, "function": addr, "args": args })).unwrap();
            let expected = emulated.split("returned EAX = ").nth(1).and_then(|rest| rest.split(' ').next()).unwrap_or_else(|| panic!("{name}{args:?}: {emulated}"));
            let run = Command::new(&lifted).arg(EXE).arg(addr).args(args.iter().map(|a| format!("{a:#x}"))).output().unwrap();
            let got = String::from_utf8_lossy(&run.stdout).trim().to_string();
            if got != expected {
                differ.push(format!("{name}{args:x?}: lifted {got}, emulated {expected} {}", String::from_utf8_lossy(&run.stderr)));
            }
        }
    }
    assert!(differ.is_empty(), "{} of {} runs differ:\n{}", differ.len(), FUNCTIONS.len() * CASES, differ.join("\n"));
}

#[test]
fn coverage_lists_the_functions_a_run_entered() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("lift-coverage");
    std::fs::create_dir_all(&dir).unwrap();
    let lifted = build(&dir);
    let symbols = Client::start().tool("symbols", json!({ "path": EXE })).unwrap();
    let addr = |name: &str| symbols.lines().find(|line| line.ends_with(&format!("function: {name}"))).and_then(|line| line.split(' ').next()).unwrap().to_string();
    let file = dir.join("coverage.txt");
    let run = Command::new(&lifted).arg(EXE).arg(addr("fib")).arg("0x5").env("LIFT_COVERAGE", &file).output().unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let coverage = std::fs::read_to_string(&file).unwrap();
    assert!(coverage.starts_with("functions ") && coverage.contains(&format!("{} lifted", addr("fib"))), "{coverage}");
    assert!(!coverage.contains(&format!("{} lifted", addr("collatz"))), "{coverage}");
}
