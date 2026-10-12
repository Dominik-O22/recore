//! The files a corpus run writes.

use recore_decomp::isolate::{FunctionRecord, Status};
use serde::{Deserialize, Serialize};

/// `<out-dir>/<name>.json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct BinaryReport {
    pub name: String,
    /// Entries recore attributes to another function as cold fragments; not decompiled alone.
    pub fragments_skipped: usize,
    /// Sorted by address.
    pub functions: Vec<FunctionRecord>,
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
