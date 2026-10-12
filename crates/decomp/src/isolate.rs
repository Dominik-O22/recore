//! Decompiling in a child process, so that a crash or an endless function costs one function.
//!
//! The engine cannot be cancelled and a C++ fault kills its process. A [`Worker`] is a child
//! process holding one [`Session`]; the parent sends it one address at a time and enforces a
//! wall-clock limit. The child side is [`serve`], which the program reaches through a
//! subcommand of its own executable.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use recore::image::Format;
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
}

impl Default for Options {
    fn default() -> Options {
        Options { style: Style::Decompile, emit_c: true, jump_tables: JumpTables::Auto, memory_gb: 4 }
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
}

/// The child side: loads `binary`, then answers each hex address on stdin with one line on
/// stdout, until stdin closes. `options` is the JSON that [`Worker::spawn`] passed along.
pub fn serve(binary: &Path, options: &str) -> Result<()> {
    let options: Options = serde_json::from_str(options)?;
    let bytes = options.memory_gb << 30;
    // Failing to set the limit only loses the protection.
    unsafe { libc::setrlimit(libc::RLIMIT_AS, &libc::rlimit { rlim_cur: bytes, rlim_max: bytes }) };

    let image = recore::Image::load(binary)?;
    let analysis = recore::analyze(&image);
    let facts = Facts::derive(&image, &analysis);
    let mut session = Session::from_image(&image, &analysis)?;
    session.add_functions(&facts)?;
    session.add_strings(&analysis)?;
    if options.jump_tables == JumpTables::Recore || (options.jump_tables == JumpTables::Auto && image.format == Format::Pe) {
        session.override_jump_tables(&analysis, &facts)?;
    }
    session.set_style(options.style)?;

    let mut out = std::io::stdout().lock();
    let mut send = |event: &Event| -> Result<()> {
        serde_json::to_writer(&mut out, event)?;
        out.write_all(b"\n")?;
        Ok(out.flush()?)
    };
    send(&Event::Ready)?;
    for line in std::io::stdin().lock().lines() {
        let addr = u64::from_str_radix(&line?, 16)?;
        let start = Instant::now();
        let result = session.decompile(addr);
        let ms = start.elapsed().as_secs_f64() * 1e3;
        send(&match result {
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
                c_text: options.emit_c.then_some(function.c_text),
            },
            Err(error) => Event::Done { record: FunctionRecord::failed(addr, Status::Error, error.to_string(), ms), c_text: None },
        })?;
    }
    Ok(())
}

/// A worker gets this long to load its binary and declare every function.
const SETUP_LIMIT: Duration = Duration::from_secs(300);

/// A child process with a warm session for one binary.
pub struct Worker {
    child: Child,
    stdin: ChildStdin,
    events: Receiver<Event>,
    stderr: Option<JoinHandle<String>>,
    /// The child has reported that its session is set up.
    ready: bool,
}

impl Worker {
    /// Starts a worker and waits until its session is set up. `command` must run a program that
    /// ends up calling [`serve`] with the two arguments appended here: the binary's path and
    /// the options as JSON.
    pub fn spawn(command: Command, binary: &Path, options: &Options) -> Result<Worker> {
        let mut worker = Worker::start(command, binary, options)?;
        worker.wait_ready().map_err(|message| anyhow::anyhow!("worker stopped during setup: {message}"))?;
        Ok(worker)
    }

    /// Starts a worker without waiting for it, so that it sets up while the caller does other
    /// work. The first [`Worker::decompile`] waits for whatever setup is left.
    pub fn start(mut command: Command, binary: &Path, options: &Options) -> Result<Worker> {
        command.arg(binary).arg(serde_json::to_string(options)?);
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
        Ok(Worker { child, stdin, events, stderr: Some(drain), ready: false })
    }

    /// Waits for the child to finish setting up. On failure the child is gone and the error
    /// says how it ended.
    fn wait_ready(&mut self) -> Result<(), String> {
        if self.ready {
            return Ok(());
        }
        match self.events.recv_timeout(SETUP_LIMIT) {
            Ok(Event::Ready) => {
                self.ready = true;
                Ok(())
            }
            Ok(Event::Done { .. }) => Err("worker answered before it was asked".into()),
            Err(error) => Err(self.end(error == RecvTimeoutError::Timeout)),
        }
    }

    /// Whether the child is still running. A worker kept between requests can die while idle,
    /// and asking it for a function would then blame that function.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Decompiles one function. If the worker dies or exceeds `timeout`, the record says so
    /// and the worker is gone: `Err` hands back that record, and the caller starts a new worker
    /// for whatever comes next. Setup still under way does not count towards `timeout`.
    pub fn decompile(&mut self, addr: u64, timeout: Duration) -> Result<(FunctionRecord, Option<String>), FunctionRecord> {
        let start = Instant::now();
        let failed = |status, message, start: Instant| FunctionRecord::failed(addr, status, message, start.elapsed().as_secs_f64() * 1e3);
        if let Err(message) = self.wait_ready() {
            return Err(failed(Status::Crash, format!("worker stopped during setup: {message}"), start));
        }
        let start = Instant::now();
        // A failed write means the child is gone, which the receive below reports.
        let _ = writeln!(self.stdin, "{addr:x}").and_then(|()| self.stdin.flush());
        match self.events.recv_timeout(timeout) {
            Ok(Event::Done { record, c_text }) => Ok((record, c_text)),
            Ok(Event::Ready) | Err(RecvTimeoutError::Disconnected) => Err(failed(Status::Crash, self.end(false), start)),
            // The child is still busy; dropping this worker kills it.
            Err(RecvTimeoutError::Timeout) => Err(failed(Status::Timeout, format!("no result after {timeout:.0?}"), start)),
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

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
