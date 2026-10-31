//! What the instruction budget does not see, held against a build of the base: how long an agent
//! waits on a large binary with the kernel and every core in it, and the most memory that takes.
//! Both sides run in turn, so that what else the machine is doing falls on both, and a base built
//! at the same time needs no number kept for this machine.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use recore::program::Program;

use crate::suites::{evict, measured, name, sample, sibling};

/// The largest binaries of the set, which show this best and take most of the time.
const BINARIES: usize = 3;
/// Rounds per binary.
const ROUNDS: usize = 5;
/// Functions a `decompile` asks for at once. One call ends before what a session pays for going
/// back to the kernel for memory shows.
const FUNCTIONS: usize = 30;
/// How far either may grow, in percent, before the run fails: more than each moves on its own.
const TIME: f64 = 10.0;
const MEMORY: f64 = 10.0;
const CALLS: [&str; 2] = ["summary", "decompile"];

/// What a call took in each round.
#[derive(Clone, Default)]
struct Runs {
    ms: Vec<f64>,
    bytes: Vec<u64>,
}

impl Runs {
    /// The fastest: the machine only ever adds to a time.
    fn ms(&self) -> f64 {
        self.ms.iter().copied().fold(f64::MAX, f64::min)
    }

    /// The middle: a run can hold well over or under the others with the same code.
    fn bytes(&self) -> u64 {
        let mut bytes = self.bytes.clone();
        bytes.sort_unstable();
        bytes[bytes.len() / 2]
    }
}

/// What the program and the processes it started have allocated at the moment, in bytes. Pages of
/// mapped files are left out: how many a process has depends on what the one before left cached.
fn held(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let own = status.lines().find_map(|line| line.strip_prefix("RssAnon:")).and_then(|value| value.trim().strip_suffix("kB")?.trim().parse::<u64>().ok());
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).into_iter().flatten().flatten();
    let children: Vec<u32> = tasks.flat_map(|task| std::fs::read_to_string(task.path().join("children")).unwrap_or_default().split_whitespace().filter_map(|child| child.parse().ok()).collect::<Vec<u32>>()).collect();
    own.unwrap_or(0) * 1024 + children.into_iter().map(held).sum::<u64>()
}

/// Measures a call of `tool` from a cold start: `summary` with no analysis kept, then `decompile`
/// of `functions` with the one that left.
fn call(tool: &Path, cache: &Path, binary: &Path, functions: &[u64], what: &str) -> Result<(f64, u64)> {
    if what == "summary" {
        let _ = std::fs::remove_dir_all(cache);
    }
    let kept = std::fs::read_dir(cache).into_iter().flatten().flatten().map(|entry| entry.path());
    for path in [tool.to_path_buf(), binary.to_path_buf()].into_iter().chain(recore::il2cpp::find(binary)).chain(kept) {
        evict(&path);
    }
    let mut command = Command::new(tool);
    command.env(recore::cache::DIR_VAR, cache).arg(what).arg(binary);
    if what == "decompile" {
        command.args(functions.iter().map(|function| format!("{function:#x}")));
    }
    measured(&mut command, held)
}

/// Measures the largest of `binaries` with `base`, a `recore-mcp`, and with this build's. Fails
/// where this one is past a limit, unless `accept`: for a change worth what it costs, which its
/// description says.
pub fn run(binaries: &[PathBuf], base: &Path, accept: bool) -> Result<()> {
    let tools = [std::path::absolute(base)?, sibling("recore-mcp")?];
    let scratch = std::path::absolute("target/bench/cost")?;
    let mut largest: Vec<&PathBuf> = binaries.iter().filter(|binary| binary.exists()).collect();
    largest.sort_by_key(|binary| std::cmp::Reverse(binary.metadata().map_or(0, |metadata| metadata.len())));
    largest.truncate(BINARIES);
    println!("{:<34} {:<10} {:>10} {:>10} {:>8} {:>10} {:>10} {:>8}", "binary", "call", "base ms", "ms", "change", "base MiB", "MiB", "change");
    let mut over = Vec::new();
    for binary in largest {
        let functions = sample(&Program::load(binary)?, FUNCTIONS);
        let mut runs = vec![vec![Runs::default(); CALLS.len()]; 2];
        for round in 0..ROUNDS {
            for side in [round % 2, 1 - round % 2] {
                for (index, what) in CALLS.into_iter().enumerate() {
                    let (ms, bytes) = call(&tools[side], &scratch.join(side.to_string()), binary, &functions, what)?;
                    runs[side][index].ms.push(ms);
                    runs[side][index].bytes.push(bytes);
                }
            }
        }
        for (index, what) in CALLS.into_iter().enumerate() {
            let (before, now) = (&runs[0][index], &runs[1][index]);
            let (time, memory) = ((now.ms() / before.ms() - 1.0) * 100.0, (now.bytes() as f64 / before.bytes() as f64 - 1.0) * 100.0);
            let mib = |bytes: u64| bytes as f64 / (1 << 20) as f64;
            let row = format!("{:<34} {what:<10} {:>10.0} {:>10.0} {time:>+7.1}% {:>10.0} {:>10.0} {memory:>+7.1}%", name(binary).rsplit('/').next().unwrap_or_default(), before.ms(), now.ms(), mib(before.bytes()), mib(now.bytes()));
            println!("{row}");
            if time > TIME || memory > MEMORY {
                over.push(row);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    if !over.is_empty() && !accept {
        bail!("time past {TIME}% or memory past {MEMORY}% over the base, which `--accept` lets by if the change is worth it:\n{}", over.join("\n"));
    }
    Ok(())
}
