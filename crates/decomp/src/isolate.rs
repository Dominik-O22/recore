//! Decompiling in a child process, so that a crash or an endless function costs one function.
//!
//! The engine cannot be cancelled and a C++ fault kills its process. A [`Worker`] is a child
//! process holding one [`Session`]; the parent sends it one address at a time and enforces a
//! wall-clock limit. The child side is [`serve`], which the program reaches through a
//! subcommand of its own executable.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use recore::image::{Format, Machine};
use recore::report::{Analysis, CallTarget};
use serde::{Deserialize, Serialize};

use crate::{Facts, Session, Style};

/// Where switch targets come from.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JumpTables {
    /// recore's for PE images, which keep tables among the code; the engine's own otherwise.
    #[default]
    Auto,
    Recore,
    Engine,
}

/// What a worker is told to do.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Options {
    pub style: Style,
    /// Send the C text back, not only its length.
    pub emit_c: bool,
    pub jump_tables: JumpTables,
    /// Address-space limit in GiB. Past it the engine's allocations fail and the function is
    /// reported as an error, instead of the machine going into swap.
    pub memory_gb: u64,
    /// Decompile the functions a function calls before the function itself, so that its calls
    /// pass at least the parameters those were found to take. Only done for 32-bit x86, where a
    /// call shows what it pushes but not which registers the callee reads. Elsewhere it costs
    /// time and recovers parameters worse.
    pub callees_first: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options { style: Style::Decompile, emit_c: true, jump_tables: JumpTables::Auto, memory_gb: 4, callees_first: true }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    /// The engine reported a failure for this function and carried on.
    Error,
    /// The function ran past the wall-clock limit and its worker was killed.
    Timeout,
    /// The worker died while decompiling this function.
    Crash,
}

/// The outcome for one function.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionRecord {
    pub addr: u64,
    pub status: Status,
    /// The engine's error, or how the worker died.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Time inside the decompiler; for a timeout or crash, the time until it was noticed.
    pub ms: f64,
    pub params: usize,
    /// Where each parameter lives: a register name or `stack:<offset>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<String>,
    pub returns_value: bool,
    pub c_len: usize,
}

impl FunctionRecord {
    /// A record for a function that produced no result.
    pub fn failed(addr: u64, status: Status, message: String, ms: f64) -> FunctionRecord {
        FunctionRecord { addr, status, message: Some(message), ms, params: 0, storage: Vec::new(), returns_value: false, c_len: 0 }
    }
}

/// One line of a worker's stdout.
#[derive(Serialize, Deserialize)]
enum Event {
    /// The binary is loaded and the session is set up.
    Ready,
    Done { record: FunctionRecord, c_text: Option<String> },
    /// The functions a function calls whose parameters the session does not hold yet.
    Callees(Vec<u64>),
}

/// One line of a worker's stdin: a letter and a hex address.
#[derive(Clone, Copy)]
enum Request {
    /// `d`: decompile the function.
    Decompile(u64),
    /// `p`: decompile it for its parameters only, which the session keeps for its callers.
    Parameters(u64),
    /// `c`: list its callees not decompiled yet.
    Callees(u64),
}

impl Request {
    fn line(self) -> String {
        match self {
            Request::Decompile(addr) => format!("d {addr:x}"),
            Request::Parameters(addr) => format!("p {addr:x}"),
            Request::Callees(addr) => format!("c {addr:x}"),
        }
    }

    fn parse(line: &str) -> Result<Request> {
        let (kind, addr) = line.split_once(' ').context("request without an address")?;
        let addr = u64::from_str_radix(addr, 16)?;
        match kind {
            "d" => Ok(Request::Decompile(addr)),
            "p" => Ok(Request::Parameters(addr)),
            "c" => Ok(Request::Callees(addr)),
            _ => anyhow::bail!("unknown request {kind}"),
        }
    }
}

/// Callees with more code than this, in bytes, are not decompiled ahead of their callers. The few
/// large functions take most of the time, and leaving them out costs no measurable accuracy.
const CALLEE_LIMIT: u64 = 4096;

/// The child side: loads `binary`, then answers each request on stdin with one line on stdout,
/// until stdin closes. `options` is the JSON that [`Worker::new`] passed along.
pub fn serve(binary: &Path, options: &str) -> Result<()> {
    let options: Options = serde_json::from_str(options)?;
    let bytes = options.memory_gb << 30;
    // Failing to set the limit only loses the protection.
    unsafe { libc::setrlimit(libc::RLIMIT_AS, &libc::rlimit { rlim_cur: bytes, rlim_max: bytes }) };

    let image = recore::Image::load(binary)?;
    // The engine reads its language files while the analysis runs.
    let (session, analysis) = std::thread::scope(|scope| {
        let session = scope.spawn(|| Session::load(&image));
        let analysis = recore::analyze(&image);
        (session.join().expect("loading does not panic"), analysis)
    });
    let mut session = session?;
    session.add_imports(&image, &analysis)?;
    let facts = Facts::derive(&image, &analysis);
    session.add_functions(&facts)?;
    session.add_strings(&analysis)?;
    session.add_classes(&analysis)?;
    if options.jump_tables == JumpTables::Recore || (options.jump_tables == JumpTables::Auto && image.format == Format::Pe) {
        session.override_jump_tables(&analysis, &facts)?;
    }

    session.set_style(options.style)?;
    let callees_first = options.callees_first && image.machine == Machine::X86;
    session.keep_prototypes(callees_first);
    let callees = if callees_first { callees(&analysis) } else { HashMap::new() };
    // Functions decompiled so far, whose parameters the session holds if it could recover them.
    let mut known: HashSet<u64> = HashSet::new();
    // Bytes of code per function, fragments included.
    let mut sizes: HashMap<u64, u64> = HashMap::new();
    for function in &analysis.functions {
        *sizes.entry(function.fragment_of.unwrap_or(function.addr)).or_default() += function.ranges.iter().map(|range| range.1 - range.0).sum::<u64>();
    }
    // Results of functions decompiled ahead of a caller that are as good as asked for.
    let mut ready: HashMap<u64, Event> = HashMap::new();

    let mut out = std::io::stdout().lock();
    let mut send = |event: &Event| -> Result<()> {
        serde_json::to_writer(&mut out, event)?;
        out.write_all(b"\n")?;
        Ok(out.flush()?)
    };
    send(&Event::Ready)?;
    for line in std::io::stdin().lock().lines() {
        let request = Request::parse(&line?)?;
        let unknown = |addr: u64| {
            let mut pending: Vec<u64> = callees.get(&addr).into_iter().flatten().copied().filter(|callee| !known.contains(callee) && sizes.get(callee).is_some_and(|&size| size <= CALLEE_LIMIT)).collect();
            pending.sort_unstable();
            pending.dedup();
            pending
        };
        let addr = match request {
            Request::Callees(addr) => {
                // A function ready to be handed over has nothing left to wait for.
                send(&Event::Callees(if ready.contains_key(&addr) { Vec::new() } else { unknown(addr) }))?;
                continue;
            }
            Request::Decompile(addr) | Request::Parameters(addr) => addr,
        };
        if let (Request::Decompile(_), Some(event)) = (request, ready.remove(&addr)) {
            send(&event)?;
            continue;
        }
        // Decompiled for a caller's sake with every callee of its own known, a function comes
        // out as it would when asked for, so the result is kept for then.
        let keep = matches!(request, Request::Parameters(_)) && unknown(addr).is_empty();
        let start = Instant::now();
        let result = session.decompile(addr);
        known.insert(addr);
        let ms = start.elapsed().as_secs_f64() * 1e3;
        let event = match result {
            Ok(function) => Event::Done {
                record: FunctionRecord {
                    addr,
                    status: Status::Ok,
                    message: None,
                    ms,
                    params: function.param_count(),
                    storage: function.params.iter().map(|p| p.storage.clone()).collect(),
                    returns_value: function.returns_value,
                    c_len: function.c_text.len(),
                },
                c_text: (options.emit_c && (keep || matches!(request, Request::Decompile(_)))).then_some(function.c_text),
            },
            Err(error) => Event::Done { record: FunctionRecord::failed(addr, Status::Error, error.to_string(), ms), c_text: None },
        };
        if keep {
            // The caller only waits for this to finish.
            send(&Event::Callees(Vec::new()))?;
            ready.insert(addr, event);
        } else {
            send(&event)?;
        }
    }
    Ok(())
}

/// The functions each function calls or tail-calls, by entry point.
fn callees(analysis: &Analysis) -> HashMap<u64, Vec<u64>> {
    let mut extents: Vec<(u64, u64, u64)> =
        analysis.functions.iter().flat_map(|f| f.ranges.iter().map(move |&(start, end)| (start, end, f.fragment_of.unwrap_or(f.addr)))).collect();
    extents.sort_unstable();
    let mut callees: HashMap<u64, Vec<u64>> = HashMap::new();
    for call in &analysis.calls {
        let CallTarget::Function(target) = call.target else { continue };
        let index = extents.partition_point(|extent| extent.0 <= call.at);
        if let Some(&(_, end, owner)) = index.checked_sub(1).map(|i| &extents[i])
            && call.at < end
            && owner != target
        {
            callees.entry(owner).or_default().push(target);
        }
    }
    callees
}

/// A worker gets this long to load its binary and declare every function.
const SETUP_LIMIT: Duration = Duration::from_secs(300);

/// A running child and the pipes to it. Dropping it kills the child.
struct Process {
    child: Child,
    stdin: ChildStdin,
    events: Receiver<Event>,
    stderr: Option<JoinHandle<String>>,
    /// The child has reported that its session is set up.
    ready: bool,
}

/// How a request went wrong, with the child gone.
struct Failure {
    status: Status,
    message: String,
}

impl Process {
    fn start(mut command: Command) -> Result<Process> {
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("spawning worker")?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let (sender, events) = mpsc::channel();
        // Reading and draining each get a thread, so the caller only ever waits on a channel
        // with a timeout and a full pipe never blocks the child.
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let Ok(event) = serde_json::from_str(&line) else { break };
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        let drain = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        Ok(Process { child, stdin, events, stderr: Some(drain), ready: false })
    }

    /// Waits for the child to finish setting up.
    fn wait_ready(&mut self) -> Result<(), Failure> {
        if self.ready {
            return Ok(());
        }
        match self.events.recv_timeout(SETUP_LIMIT) {
            Ok(Event::Ready) => {
                self.ready = true;
                Ok(())
            }
            Ok(_) => Err(Failure { status: Status::Crash, message: "worker answered before it was asked".into() }),
            Err(error) => {
                let how = self.end(error == RecvTimeoutError::Timeout);
                Err(Failure { status: Status::Crash, message: format!("worker stopped during setup: {how}") })
            }
        }
    }

    /// Sends one request and waits up to `timeout` for the answer. Setup still under way does
    /// not count towards `timeout`.
    fn ask(&mut self, request: Request, timeout: Duration) -> Result<Event, Failure> {
        self.wait_ready()?;
        // A failed write means the child is gone, which the receive below reports.
        let _ = writeln!(self.stdin, "{}", request.line()).and_then(|()| self.stdin.flush());
        match self.events.recv_timeout(timeout) {
            Ok(Event::Ready) | Err(RecvTimeoutError::Disconnected) => Err(Failure { status: Status::Crash, message: self.end(false) }),
            Ok(event) => Ok(event),
            // The child is still busy; dropping this process kills it.
            Err(RecvTimeoutError::Timeout) => Err(Failure { status: Status::Timeout, message: format!("no result after {timeout:.0?}") }),
        }
    }

    /// Kills the child if it is still running and describes how it ended.
    fn end(&mut self, kill: bool) -> String {
        if kill {
            let _ = self.child.kill();
        }
        let how = match self.child.wait() {
            Ok(status) => status.signal().map_or_else(|| format!("exited with {status}"), |signal| format!("killed by signal {signal}")),
            Err(error) => error.to_string(),
        };
        // The end of stderr usually names the cause: an assertion, a panic, an abort message.
        let stderr = self.stderr.take().and_then(|drain| drain.join().ok()).unwrap_or_default();
        let tail: String = stderr.trim().chars().rev().take(300).collect::<Vec<_>>().into_iter().rev().collect();
        if tail.is_empty() { how } else { format!("{how}: {tail}") }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A child process with a warm session for one binary. A child that dies or stalls is replaced
/// by a new one, so a failure costs the one function and the parameters kept so far.
pub struct Worker {
    command: Box<dyn Fn() -> Command + Send>,
    options: Options,
    process: Option<Process>,
    /// Callees that took a child down. They are no longer decompiled ahead of their callers.
    avoid: HashSet<u64>,
}

impl Worker {
    /// Starts a child without waiting for it, so that it sets up while the caller does other
    /// work. `command` must build a program that ends up calling [`serve`] with the two arguments
    /// appended here: the binary's path and the options as JSON.
    pub fn new(command: impl Fn() -> Command + Send + 'static, binary: &Path, options: &Options) -> Worker {
        let (binary, json) = (binary.to_path_buf(), serde_json::to_string(options).expect("plain data"));
        let command = move || {
            let mut command = command();
            command.arg(&binary).arg(&json);
            command
        };
        let process = Process::start(command()).ok();
        Worker { command: Box::new(command), options: options.clone(), process, avoid: HashSet::new() }
    }

    /// Decompiles one function. If the child dies or exceeds `timeout`, the record says so.
    /// With [`Options::callees_first`] the function's callees are decompiled before it, each
    /// within `timeout` of its own.
    pub fn decompile(&mut self, addr: u64, timeout: Duration) -> (FunctionRecord, Option<String>) {
        let mut ahead = 0;
        if self.options.callees_first
            && let Ok(Event::Callees(callees)) = self.ask(Request::Callees(addr), timeout)
        {
            for callee in callees {
                if self.avoid.contains(&callee) {
                    continue;
                }
                match self.ask(Request::Parameters(callee), timeout) {
                    Ok(_) => ahead += 1,
                    // The new child starts without the parameters of the callees before this one.
                    Err(_) => {
                        self.avoid.insert(callee);
                        ahead = 0;
                    }
                }
            }
        }
        let start = Instant::now();
        let mut result = self.ask(Request::Decompile(addr), timeout);
        if result.is_err() && ahead > 0 {
            // Known parameters at its calls can send a function astray that decompiles well
            // without them. The new child knows none.
            result = self.ask(Request::Decompile(addr), timeout);
        }
        match result {
            Ok(Event::Done { record, c_text }) => (record, c_text),
            Ok(_) => (FunctionRecord::failed(addr, Status::Crash, "worker answered something else".into(), 0.0), None),
            Err(failure) => (FunctionRecord::failed(addr, failure.status, failure.message, start.elapsed().as_secs_f64() * 1e3), None),
        }
    }

    /// Waits until a child is set up, so that what is timed next is the decompiler alone.
    pub fn ready(&mut self) -> bool {
        let ready = self.process().and_then(Process::wait_ready).is_ok();
        if !ready {
            self.process = None;
        }
        ready
    }

    /// The child, started now if the last one is gone. A child can also have died while idle,
    /// which is not the doing of the function asked for next.
    fn process(&mut self) -> Result<&mut Process, Failure> {
        if self.process.as_mut().is_none_or(|process| !matches!(process.child.try_wait(), Ok(None))) {
            let started = Process::start((self.command)());
            self.process = Some(started.map_err(|error| Failure { status: Status::Error, message: format!("{error:#}") })?);
        }
        Ok(self.process.as_mut().expect("started above"))
    }

    /// Asks the child, starting one if the last one is gone.
    fn ask(&mut self, request: Request, timeout: Duration) -> Result<Event, Failure> {
        let result = self.process()?.ask(request, timeout);
        if result.is_err() {
            self.process = None;
        }
        result
    }
}
