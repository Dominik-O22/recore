//! A limit on the instructions recore executes that only tightens: `recore-bench ratchet`.
//!
//! `bench/budget.json` holds, for each binary of the set, the instructions of what an agent
//! waits for; [`Work`] lists them. All but `diff` run `recore-mcp`, the program agents run, so
//! that its tools and its decompiler process are counted with what they call. A run fails when a
//! count grew past its budget by more than [`SLACK`] percent, and lowers the budget where a
//! count shrank by as much, so the next change is held to the faster code. Counted instructions
//! do not move with the machine's load, but they do with the compiler and with the processor,
//! where a library picks its code by what the processor has: a budget is kept on one machine.
//! They add up the work of every process and leave out the kernel, so they do not see time spent
//! in page faults or on the disk, or how work is shared among threads, which `recore-bench run`
//! times. Nor do they see the largest few functions of a binary or tools other than the ones
//! [`count`] calls. Each binary is counted in a process of its own, because in one process the
//! allocator's state after the binaries before it moved a count by up to 2%.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use recore::program::Program;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::work::Counter;

/// How far a count may move, in percent of its budget, and still be the same.
const SLACK: u128 = 1;

/// Functions decompiled per binary. `bench/functions.json` keeps which, so that a change to what
/// the analysis finds does not swap them for others and move the count by itself.
const FUNCTIONS: usize = 24;

/// `trace` goes through the chosen functions until this many had both a parameter and a value to
/// follow: it takes the longest of the tools on some of them, and few small ones have both. Which
/// these are is not kept, so a change to what the decompiler recovers can swap them.
const TRACED: usize = 3;

/// What a function may take. One that takes longer is a failed call: `choose` leaves it out, and
/// in a count it fails the run. A decompiler process replaced on the way to a call that then
/// succeeds shows only as growth.
const TIMEOUT: Duration = Duration::from_secs(60);

const NOT_ALLOWED: &str = "the kernel lets this process count no instructions; /proc/sys/kernel/perf_event_paranoid must be 2 or less";

/// Instructions executed for one binary, in the order they are printed.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
struct Work {
    /// `summary` with nothing kept: the first call on a binary, which analyzes it.
    analysis: u64,
    /// `summary` again in a new process: what each command run on its own starts with.
    again: u64,
    /// A new server's first `decompile`, of the smallest of the binary's chosen functions: the
    /// binary read back and a decompiler process set up.
    setup: u64,
    /// `decompile` of the rest of the chosen functions, one call each.
    decompile: u64,
    /// `functions`, `strings`, `imports`, `classes`, `symbols` and `unnamed`, and `function`,
    /// `xrefs`, `disassemble`, `addr` and `bytes` of each chosen function.
    lookups: u64,
    /// `structs` and `pcode` of each chosen function, and `trace` as [`TRACED`] says. Apart from
    /// `lookups` because its cost is in the decompiler, which would hide a slower lookup.
    dataflow: u64,
    /// Comparing the binary with itself, in this process: `recore-mcp diff` refuses that.
    diff: u64,
}

impl Work {
    fn counts(&mut self) -> [(&'static str, &mut u64); 7] {
        [
            ("analysis", &mut self.analysis),
            ("again", &mut self.again),
            ("setup", &mut self.setup),
            ("decompile", &mut self.decompile),
            ("lookups", &mut self.lookups),
            ("dataflow", &mut self.dataflow),
            ("diff", &mut self.diff),
        ]
    }
}

/// What `recore-bench count` prints: the counts, and the functions behind `decompile`.
#[derive(Serialize, Deserialize)]
struct Counted {
    work: Work,
    functions: Vec<u64>,
}

/// One run's check of each binary's counts against the budget.
struct Ratchet {
    budget: BTreeMap<String, Work>,
    accept: bool,
    /// Each count that grew past its budget, described.
    over: Vec<String>,
    lowered: usize,
    added: usize,
}

impl Ratchet {
    fn new(budget: BTreeMap<String, Work>, accept: bool) -> Ratchet {
        Ratchet { budget, accept, over: Vec::new(), lowered: 0, added: 0 }
    }

    /// Holds what the binary `name` counted to its budget, which a binary new to it gets at
    /// that count, and returns the row that shows how the counts moved.
    fn hold(&mut self, name: &str, mut now: Work) -> String {
        let limit = self.budget.entry(name.to_string()).or_insert_with(|| {
            self.added += 1;
            now
        });
        let mut shown = Vec::new();
        for ((what, limit), (_, now)) in limit.counts().into_iter().zip(now.counts()) {
            let now = *now;
            let change = now as f64 / (*limit).max(1) as f64 - 1.0;
            shown.push(format!("{:>10.1} {:>+6.1}%", now as f64 / 1e6, change * 100.0));
            // In whole numbers, which put a count exactly `SLACK` off still inside it.
            let (percent, budget) = (u128::from(now) * 100, u128::from((*limit).max(1)));
            if percent > budget * (100 + SLACK) {
                self.over.push(format!("{name}: {what} {:.1}M -> {:.1}M ({:+.1}%)", *limit as f64 / 1e6, now as f64 / 1e6, change * 100.0));
                if self.accept {
                    *limit = now;
                }
            } else if percent < budget * (100 - SLACK) {
                *limit = now;
                self.lowered += 1;
            }
        }
        format!("{:<46} {}", name, shown.join(" "))
    }

    /// The budget to write back and how it moved, or the error that names each count that grew
    /// past it, unless the run accepts them.
    fn finish(self) -> Result<(BTreeMap<String, Work>, String)> {
        if !self.over.is_empty() && !self.accept {
            bail!("instructions grew past the budget, which `--accept` raises if the change is worth it:\n{}", self.over.join("\n"));
        }
        let raised = if self.accept { self.over.len() } else { 0 };
        Ok((self.budget, format!("{raised} raised, {} lowered, {} added", self.lowered, self.added)))
    }
}

/// Reads the JSON at `path`, or an empty map if there is no such file.
fn read_map<T: serde::de::DeserializeOwned>(path: &Path) -> Result<BTreeMap<String, T>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Measures the binaries against the budget at `path`, and writes the budget back with what
/// shrank lowered and what is new added. With `accept`, what grew is raised to what it is now
/// and nothing fails: for a change that is worth what it costs, which its description says.
pub fn run(binaries: &[PathBuf], path: &Path, accept: bool) -> Result<()> {
    let mut ratchet = Ratchet::new(read_map(path)?, accept);
    let functions_path = path.with_file_name("functions.json");
    let mut functions: BTreeMap<String, Vec<u64>> = read_map(&functions_path)?;
    // A store can hold some corpora and not others, but one that holds none of the set is a
    // wrong path, which must not pass for a check.
    let (present, missing): (Vec<&PathBuf>, Vec<&PathBuf>) = binaries.iter().partition(|binary| binary.exists());
    if present.is_empty() {
        bail!("none of the {} binaries of the set is in {}", binaries.len(), crate::corpora().display());
    }
    let header: Vec<String> = Work { analysis: 0, again: 0, setup: 0, decompile: 0, lookups: 0, dataflow: 0, diff: 0 }.counts().map(|(what, _)| format!("{:>18}", format!("{what} M"))).into();
    println!("{:<46} {}", "binary", header.join(" "));
    for binary in present {
        let name = crate::suites::name(binary);
        let chosen = functions.get(&name).into_iter().flatten().map(u64::to_string);
        let counted = Command::new(std::env::current_exe()?).arg("count").arg(binary).args(chosen).output()?;
        if !counted.status.success() {
            bail!("counting {}: {}", binary.display(), String::from_utf8_lossy(&counted.stderr).trim());
        }
        let counted: Counted = serde_json::from_slice(&counted.stdout).with_context(|| format!("counting {}", binary.display()))?;
        println!("{}", ratchet.hold(&name, counted.work));
        functions.insert(name, counted.functions);
    }
    let (budget, moved) = ratchet.finish()?;
    std::fs::write(path, serde_json::to_string_pretty(&budget)? + "\n").with_context(|| format!("writing {}", path.display()))?;
    std::fs::write(&functions_path, serde_json::to_string_pretty(&functions)? + "\n").with_context(|| format!("writing {}", functions_path.display()))?;
    println!("{moved} in {}", path.display());
    if !missing.is_empty() {
        println!("{} binaries of the set are not in {} and were not counted", missing.len(), crate::corpora().display());
    }
    Ok(())
}

/// A `recore-mcp` server with one client, as an agent has it.
struct Server {
    child: Child,
    stdin: ChildStdin,
    replies: BufReader<ChildStdout>,
    binary: String,
}

impl Server {
    fn start(mut command: Command, binary: &Path) -> Result<Server> {
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().context("starting recore-mcp")?;
        let (stdin, stdout) = (child.stdin.take().context("no stdin")?, child.stdout.take().context("no stdout")?);
        Ok(Server { child, stdin, replies: BufReader::new(stdout), binary: binary.display().to_string() })
    }

    /// Calls a tool on the binary. An error from it is an error here: a call that failed did
    /// not do the work its count stands for, and a lower count would pass for a faster program.
    fn call(&mut self, tool: &str, mut arguments: Value) -> Result<()> {
        arguments["path"] = json!(self.binary);
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": tool, "arguments": arguments } });
        // In one write: a line in pieces is read in as many pieces as the scheduler makes of it.
        self.stdin.write_all(format!("{request}\n").as_bytes())?;
        let mut line = String::new();
        ensure!(self.replies.read_line(&mut line)? > 0, "recore-mcp ended during `{tool}`");
        let reply: Value = serde_json::from_str(&line).with_context(|| format!("the reply to `{tool}`"))?;
        ensure!(reply["result"]["isError"] == false, "`{tool}` {arguments}: {line}");
        Ok(())
    }

    fn decompile(&mut self, function: u64) -> Result<()> {
        self.call("decompile", json!({ "functions": [format!("{function:#x}")], "timeout": TIMEOUT.as_secs() }))
    }

    fn look_up(&mut self, function: u64) -> Result<()> {
        let function = format!("{function:#x}");
        self.call("function", json!({ "addr": function }))?;
        self.call("xrefs", json!({ "addr": function }))?;
        self.call("disassemble", json!({ "function": function }))?;
        self.call("addr", json!({ "addr": function }))?;
        self.call("bytes", json!({ "addr": function }))
    }

    fn data_flow(&mut self, function: u64) -> Result<()> {
        let function = format!("{function:#x}");
        self.call("structs", json!({ "function": function, "timeout": TIMEOUT.as_secs() }))?;
        self.call("pcode", json!({ "function": function, "timeout": TIMEOUT.as_secs() }))
    }

    /// Follows the function's first parameter and its return value, and says whether it has
    /// both. Saying that it lacks one is an answer, where any other error is a failed call.
    fn trace(&mut self, function: u64) -> Result<bool> {
        let function = format!("{function:#x}");
        let mut has = |arguments: Value, none: &str| match self.call("trace", arguments) {
            Ok(()) => Ok(true),
            Err(error) if error.to_string().contains(none) => Ok(false),
            Err(error) => Err(error),
        };
        Ok(has(json!({ "function": function, "param": 1, "timeout": TIMEOUT.as_secs() }), "has no parameter 1")? & has(json!({ "function": function, "returns": true, "timeout": TIMEOUT.as_secs() }), "returns no value")?)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The binary's functions at even steps through their sizes, smallest first, as the set takes
/// binaries, leaving out those with no code and those a tool of [`count`]'s fails on. The largest
/// few, which take most of the time and so would hide the rest, fall past the last step.
fn choose(program: &Program, mut server: Server) -> Vec<u64> {
    let mut by_size: Vec<(u64, u64)> = program.sizes().into_iter().filter(|&(_, size)| size > 0).map(|(entry, size)| (size, entry)).collect();
    by_size.sort_unstable();
    let step = by_size.len().div_ceil(FUNCTIONS).max(1);
    by_size.into_iter().step_by(step).map(|(_, entry)| entry).filter(|&entry| server.decompile(entry).and_then(|()| server.look_up(entry)).and_then(|()| server.data_flow(entry)).and_then(|()| server.trace(entry)).is_ok()).collect()
}

/// Counts [`Work`] for `binary`, decompiling `functions`, or functions it chooses if there are
/// none, and prints it as JSON for [`run`]. What `recore-mcp` keeps goes to a directory emptied
/// before counting: the first call has nothing kept, and no edits a run left behind apply.
pub fn count(binary: &Path, functions: Vec<u64>) -> Result<()> {
    let program = Program::load(binary)?;
    let tool = crate::suites::sibling("recore-mcp")?;
    let kept = std::path::absolute("target/bench/count")?;
    let recore_mcp = || {
        let mut command = Command::new(&tool);
        // Rayon's work on one thread, so that the count does not depend on how it was split.
        command.env(recore::cache::DIR_VAR, &kept).env(recore::edits::DIR_VAR, &kept).env("RAYON_NUM_THREADS", "1").env_remove(recore_decomp::types::DEBUG_VAR);
        command
    };
    let functions = if functions.is_empty() { choose(&program, Server::start(recore_mcp(), binary)?) } else { functions };
    let (first, rest) = functions.split_first().with_context(|| format!("no function of {} to decompile", binary.display()))?;
    let _ = std::fs::remove_dir_all(&kept);
    std::fs::create_dir_all(&kept)?;

    let counter = Counter::new().context(NOT_ALLOWED)?;
    counter.start();
    let read = || counter.read().context("reading the instruction counter");
    let summary = || -> Result<u64> {
        let before = read()?;
        let mut command = recore_mcp();
        let status = command.arg("summary").arg(binary).stdout(Stdio::null()).status()?;
        ensure!(status.success(), "{command:?} failed");
        Ok(read()? - before)
    };
    let analysis = summary()?;
    let again = summary()?;

    let start = read()?;
    let mut server = Server::start(recore_mcp(), binary)?;
    server.decompile(*first)?;
    let set_up = read()?;
    for &function in rest {
        server.decompile(function)?;
    }
    let decompiled = read()?;
    for tool in ["functions", "strings", "imports", "classes", "symbols", "unnamed"] {
        server.call(tool, json!({}))?;
    }
    for &function in &functions {
        server.look_up(function)?;
    }
    let looked_up = read()?;
    for &function in &functions {
        server.data_flow(function)?;
    }
    let mut traced = 0;
    for &function in &functions {
        if traced < TRACED {
            traced += usize::from(server.trace(function)?);
        }
    }
    let flowed = read()?;
    drop(server);
    let _ = std::fs::remove_dir_all(&kept);

    let (_, diff) = crate::work::instructions(|| recore::diff::diff(&program, &program));
    let work = Work { analysis, again, setup: set_up - start, decompile: decompiled - set_up, lookups: looked_up - decompiled, dataflow: flowed - looked_up, diff: diff.context(NOT_ALLOWED)? };
    println!("{}", serde_json::to_string(&Counted { work, functions })?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Work = Work { analysis: 1_000_000_000, again: 1_000_000_000, setup: 1_000_000_000, decompile: 1_000_000_000, lookups: 1_000_000_000, dataflow: 1_000_000_000, diff: 1_000_000_000 };

    /// Holds one count of the binary `a`, whose budget is [`LIMIT`], and finishes.
    fn finish_with(analysis: u64, accept: bool) -> Result<(BTreeMap<String, Work>, String)> {
        let mut ratchet = Ratchet::new(BTreeMap::from([("a".to_string(), LIMIT)]), accept);
        ratchet.hold("a", Work { analysis, ..LIMIT });
        ratchet.finish()
    }

    #[test]
    fn every_count_is_held_to_its_budget() {
        for index in 0..7 {
            let mut now = LIMIT;
            let (what, count) = now.counts().into_iter().nth(index).expect("a count");
            *count = 1_020_000_000;
            let mut ratchet = Ratchet::new(BTreeMap::from([("a".to_string(), LIMIT)]), false);
            ratchet.hold("a", now);
            let error = ratchet.finish().unwrap_err().to_string();
            assert!(error.contains(&format!("a: {what} ")), "{error}");
        }
    }

    #[test]
    fn a_count_that_grew_more_than_one_percent_fails_the_run_and_is_named() {
        let error = finish_with(1_010_100_000, false).unwrap_err().to_string();
        assert!(error.contains("a: analysis 1000.0M -> 1010.1M (+1.0%)"), "{error}");
    }

    #[test]
    fn accepting_a_count_that_grew_raises_its_budget_to_it() {
        let (budget, moved) = finish_with(1_010_100_000, true).unwrap();
        assert_eq!((budget["a"].analysis, moved.as_str()), (1_010_100_000, "1 raised, 0 lowered, 0 added"));
    }

    #[test]
    fn a_count_that_shrank_more_than_one_percent_lowers_its_budget() {
        let (budget, moved) = finish_with(989_900_000, false).unwrap();
        assert_eq!((budget["a"], moved.as_str()), (Work { analysis: 989_900_000, ..LIMIT }, "0 raised, 1 lowered, 0 added"));
    }

    #[test]
    fn a_count_within_one_percent_either_way_leaves_its_budget() {
        for analysis in [990_000_000, 1_000_000_000, 1_010_000_000] {
            let (budget, moved) = finish_with(analysis, false).unwrap();
            assert_eq!((budget["a"], moved.as_str()), (LIMIT, "0 raised, 0 lowered, 0 added"), "{analysis}");
        }
    }

    #[test]
    fn a_binary_new_to_the_budget_is_added_at_what_it_counted() {
        let mut ratchet = Ratchet::new(BTreeMap::new(), false);
        ratchet.hold("b", Work { analysis: 5, ..LIMIT });
        let (budget, moved) = ratchet.finish().unwrap();
        assert_eq!((budget["b"], moved.as_str()), (Work { analysis: 5, ..LIMIT }, "0 raised, 0 lowered, 1 added"));
    }
}
