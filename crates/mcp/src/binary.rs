//! Binaries kept loaded between requests, with the lookups the tools share.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use recore::Image;
use recore::edits::Edits;
use recore::program::Program;
use recore_decomp::isolate::{FunctionRecord, Options, Worker};
use recore_decomp::{Flow, Instruction, Local};

/// How long the decompiler process gets for a request that is not a decompilation.
pub const QUICK: Duration = Duration::from_secs(30);

/// Binaries kept at once. Each holds its analysis and a decompiler process.
const KEPT: usize = 8;

/// An analyzed binary and its decompiler process.
pub struct Binary {
    path: PathBuf,
    /// Modification time and size of the file when it was loaded.
    stamp: (SystemTime, u64),
    pub program: Program,
    /// The names, comments and types given to this binary, as saved.
    pub edits: Edits,
    /// The name the analysis gave each of `program.analysis.functions`, before edits.
    found_names: Vec<Option<String>>,
    /// Time spent loading and analyzing.
    pub analysis_ms: f64,
    /// Started when the binary is loaded, so it sets up while the first queries are answered.
    worker: Worker,
}

fn start_worker(path: &Path) -> Worker {
    let command = || {
        // Without the path of this program no child starts, and each decompilation reports that.
        let mut command = Command::new(std::env::current_exe().unwrap_or_default());
        command.arg(crate::WORKER_ARG);
        command
    };
    Worker::new(command, path, &Options::default())
}

impl Binary {
    fn load(path: &Path, stamp: (SystemTime, u64)) -> Result<Binary> {
        let start = Instant::now();
        // The child repeats the analysis for itself, at the same time as this process.
        let worker = start_worker(path);
        let image = Image::load(path)?;
        let mut analysis = recore::analyze(&image);
        let analysis_ms = start.elapsed().as_secs_f64() * 1e3;

        let edits = Edits::load(path)?;
        let found_names = analysis.functions.iter().map(|function| function.name.clone()).collect();
        edits.apply(&mut analysis);
        let program = Program::new(image, analysis);
        Ok(Binary { path: path.to_path_buf(), stamp, program, edits, found_names, analysis_ms, worker })
    }

    /// Changes the binary's edits and saves them. The decompiler process is replaced by one that
    /// starts from the new edits, so the next decompilation waits for it to set up again.
    pub fn edit(&mut self, change: impl FnOnce(&mut Edits)) -> Result<()> {
        let mut edits = self.edits.clone();
        change(&mut edits);
        edits.save(&self.path)?;
        self.edits = edits;
        for (function, found) in self.program.analysis.functions.iter_mut().zip(&self.found_names) {
            function.name.clone_from(found);
        }
        self.edits.apply(&mut self.program.analysis);
        self.worker.restart();
        Ok(())
    }

    /// Where this binary's edits are saved.
    pub fn edits_file(&self) -> Result<PathBuf> {
        Edits::file(&self.path)
    }

    /// Disassembles `[start, end)`: see [`Worker::listing`].
    pub fn listing(&mut self, start: u64, end: u64, pcode: bool) -> Result<Vec<Instruction>> {
        self.worker.listing(start, end, pcode, QUICK).map_err(anyhow::Error::msg)
    }

    /// The data flow of the function at `addr`, which costs one decompilation.
    pub fn flow(&mut self, addr: u64, timeout: Duration) -> Result<Flow> {
        self.worker.flow(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The variables of the function at `addr`, which costs one decompilation.
    pub fn locals(&mut self, addr: u64, timeout: Duration) -> Result<Vec<Local>> {
        self.worker.locals(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// Checks a C declaration against the decompiler without saving it.
    pub fn check_declaration(&mut self, declaration: &str) -> Result<()> {
        self.worker.declare(declaration, QUICK).map_err(anyhow::Error::msg)
    }

    /// Describes a data type the decompiler knows.
    pub fn type_layout(&mut self, name: &str) -> Result<String> {
        self.worker.type_layout(name, QUICK).map_err(anyhow::Error::msg)
    }

    /// Decompiles the function at `addr` in the child process. A crash or a function that runs
    /// past `timeout` costs that child and is reported in the record.
    pub fn decompile(&mut self, addr: u64, timeout: Duration) -> (FunctionRecord, Option<String>) {
        self.worker.decompile(addr, timeout)
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
