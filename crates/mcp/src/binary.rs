//! Binaries kept loaded between requests, with the lookups the tools share.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use recore::Image;
use recore::program::Program;
use recore_decomp::isolate::{FunctionRecord, Options, Status, Worker};

/// Binaries kept at once. Each holds its analysis and a decompiler process.
const KEPT: usize = 8;

/// An analyzed binary and its decompiler process.
pub struct Binary {
    path: PathBuf,
    /// Modification time and size of the file when it was loaded.
    stamp: (SystemTime, u64),
    pub program: Program,
    /// Time spent loading and analyzing.
    pub analysis_ms: f64,
    /// Started when the binary is loaded, so it sets up while the first queries are answered.
    worker: Option<Worker>,
}

fn start_worker(path: &Path) -> Result<Worker> {
    let mut command = Command::new(std::env::current_exe()?);
    command.arg(crate::WORKER_ARG);
    Worker::start(command, path, &Options::default())
}

impl Binary {
    fn load(path: &Path, stamp: (SystemTime, u64)) -> Result<Binary> {
        let start = Instant::now();
        // The child repeats the analysis for itself, at the same time as this process.
        let worker = start_worker(path).ok();
        let image = Image::load(path)?;
        let analysis = recore::analyze(&image);
        let analysis_ms = start.elapsed().as_secs_f64() * 1e3;

        let program = Program::new(image, analysis);
        Ok(Binary { path: path.to_path_buf(), stamp, program, analysis_ms, worker })
    }

    /// Decompiles the function at `addr` in the child process. A crash or a function that runs
    /// past `timeout` costs that child and is reported in the record; the next one is started
    /// at once.
    pub fn decompile(&mut self, addr: u64, timeout: Duration) -> (FunctionRecord, Option<String>) {
        // A child can have died while idle; that is not this function's doing.
        if self.worker.as_mut().is_none_or(|worker| !worker.is_alive()) {
            match start_worker(&self.path) {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => return (FunctionRecord::failed(addr, Status::Error, format!("{error:#}"), 0.0), None),
            }
        }
        match self.worker.as_mut().expect("started above").decompile(addr, timeout) {
            Ok(result) => result,
            Err(record) => {
                self.worker = start_worker(&self.path).ok();
                (record, None)
            }
        }
    }
}

/// The binaries a session has touched, most recently used first.
#[derive(Default)]
pub struct Cache {
    binaries: Vec<Binary>,
}

impl Cache {
    /// The binary at `path`, analyzed now unless it was before and the file has not changed.
    pub fn get(&mut self, path: &Path) -> Result<&mut Binary> {
        let metadata = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        let stamp = (metadata.modified()?, metadata.len());
        let binary = match self.binaries.iter().position(|binary| binary.path == path) {
            Some(index) if self.binaries[index].stamp == stamp => self.binaries.remove(index),
            stale => {
                // Dropping a binary ends its decompiler process.
                stale.map(|index| self.binaries.remove(index));
                Binary::load(path, stamp).with_context(|| format!("cannot load {}", path.display()))?
            }
        };
        self.binaries.insert(0, binary);
        self.binaries.truncate(KEPT);
        Ok(&mut self.binaries[0])
    }
}
