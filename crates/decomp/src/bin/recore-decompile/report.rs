//! The files a corpus run writes, and the lines a child process sends to its parent.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    /// The engine reported a failure for this function and carried on.
    Error,
    /// The function ran past the wall-clock limit and its child process was killed.
    Timeout,
    /// The child process died while decompiling this function.
    Crash,
}

/// The outcome for one function.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionRecord {
    pub addr: u64,
    pub status: Status,
    /// The engine's error, or how the child process died.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Time inside the decompiler; for a timeout, the limit.
    pub ms: f64,
    pub params: usize,
    pub returns_value: bool,
    pub c_len: usize,
}

impl FunctionRecord {
    /// A record for a function that produced no result.
    pub fn failed(addr: u64, status: Status, message: String, ms: f64) -> FunctionRecord {
        FunctionRecord { addr, status, message: Some(message), ms, params: 0, returns_value: false, c_len: 0 }
    }
}

/// `<out-dir>/<name>.json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct BinaryReport {
    pub name: String,
    /// Entries recore attributes to another function as cold fragments; not decompiled alone.
    pub fragments_skipped: usize,
    /// Sorted by address.
    pub functions: Vec<FunctionRecord>,
}

/// One line of a child's stdout.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// Sent before a function is handed to the engine, so the parent knows what was in flight
    /// if the child dies or stalls.
    Start(u64),
    Done {
        record: FunctionRecord,
        /// Present only with `--emit-c`.
        c_text: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Slow {
    pub binary: String,
    pub addr: u64,
    pub ms: f64,
    pub status: Status,
}

/// `<out-dir>/summary.json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct Summary {
    pub binaries: usize,
    pub functions: usize,
    /// Cold fragments recore found, which are decompiled only as part of their owners.
    pub fragments_skipped: usize,
    pub ok: usize,
    pub error: usize,
    pub timeout: usize,
    pub crash: usize,
    pub jobs: usize,
    pub wall_seconds: f64,
    /// Sum of the per-function times.
    pub function_seconds: f64,
    pub median_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub slowest: Vec<Slow>,
}
