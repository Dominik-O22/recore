//! Binaries kept loaded between requests, with the lookups the tools share.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use recore::Image;
use recore::edits::Edits;
use recore::program::Program;
use recore_decomp::isolate::{FunctionRecord, Options, Worker};
use recore::structs::Recovered;
use recore_decomp::{Flow, Instruction, Local, StructReport};

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
    /// Started when the binary is loaded, so it sets up while the first queries are answered,
    /// or by the first request, for a tool run from the shell that may make none.
    worker: Worker,
}

/// The decompiler process for the binary at `path`, started now or by its first request.
fn worker(path: &Path, start: bool) -> Worker {
    let command = || {
        // Without the path of this program no child starts, and each decompilation reports that.
        let mut command = Command::new(std::env::current_exe().unwrap_or_default());
        command.arg(crate::WORKER_ARG);
        command
    };
    if start { Worker::new(command, path, &Options::default()) } else { Worker::idle(command, path, &Options::default()) }
}

impl Binary {
    fn load(path: &Path, stamp: (SystemTime, u64), start_worker: bool) -> Result<Binary> {
        let start = Instant::now();
        // A child started now reads the analysis kept on disk at the same time as this process.
        // Without one it is started once this process has kept its own, so the binary is
        // analyzed once.
        let kept = recore::cache::is_kept(path);
        let early = (start_worker && kept).then(|| worker(path, true));
        // Analysis frees most of what it builds, some of it to allocate again at once: 10 ms
        // gives back the rest and leaves analysis as fast as without.
        let give_back = (!kept).then(|| recore_decomp::GiveBackFreed::after(10));
        let image = Image::load(path)?;
        let mut analysis = recore::cache::analyze(path, &image);
        drop(give_back);
        let worker = early.unwrap_or_else(|| worker(path, start_worker));
        let analysis_ms = start.elapsed().as_secs_f64() * 1e3;

        let edits = Edits::load(path)?;
        let found_names = analysis.functions.iter().map(|function| function.name.clone()).collect();
        edits.apply(&mut analysis);
        let program = Program::new(image, analysis);
        // What loading freed would otherwise be held while queries are answered.
        recore_decomp::give_back_freed_memory();
        Ok(Binary { path: path.to_path_buf(), stamp, program, edits, found_names, analysis_ms, worker })
    }

    /// Changes the binary's edits and saves them. The decompiler process takes names, comments
    /// and named structs as it runs. A declaration, a type, a name taken away or a struct whose
    /// layout grows replaces it with one that starts from the new edits, so the next
    /// decompilation waits for it to set up again.
    pub fn edit(&mut self, change: impl FnOnce(&mut Edits)) -> Result<()> {
        let mut edits = self.edits.clone();
        change(&mut edits);
        edits.save(&self.path)?;
        self.edits = edits;
        for (function, found) in self.program.analysis.functions.iter_mut().zip(&self.found_names) {
            function.name.clone_from(found);
        }
        self.edits.apply(&mut self.program.analysis);
        self.worker.update(&self.edits, QUICK);
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

    /// `[start, end)` lifted to raw p-code for the emulator: see [`recore_decomp::Session::lift`].
    pub fn lift(&mut self, start: u64, end: u64) -> Result<Vec<Instruction>> {
        self.worker.lift(start, end, QUICK).map_err(anyhow::Error::msg)
    }

    /// The space, offset and size of a register: see [`recore_decomp::Session::register`].
    pub fn register(&mut self, name: &str) -> Result<(String, u64, u32)> {
        self.worker.register(name, QUICK).map_err(anyhow::Error::msg)
    }

    /// The data flow of the function at `addr`, which costs one decompilation.
    pub fn flow(&mut self, addr: u64, timeout: Duration) -> Result<Flow> {
        self.worker.flow(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The C of the function at `addr` with the address of its instruction before each line.
    pub fn addressed(&mut self, addr: u64, timeout: Duration) -> Result<String> {
        self.worker.addressed(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The variables of the function at `addr`, which costs one decompilation.
    pub fn locals(&mut self, addr: u64, timeout: Duration) -> Result<Vec<Local>> {
        self.worker.locals(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The struct the decompiler recovered under the name `name` and those it points to. Its
    /// function is decompiled first if the decompiler process has not.
    pub fn recovered(&mut self, name: &str) -> Result<Recovered> {
        self.worker.recovered(name, QUICK).map_err(anyhow::Error::msg)
    }

    /// What struct recovery made of the objects the function at `addr` reaches through its
    /// pointers, which costs one decompilation.
    pub fn structs(&mut self, addr: u64, timeout: Duration) -> Result<StructReport> {
        self.worker.structs(addr, timeout).map_err(anyhow::Error::msg)
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
pub struct Cache {
    binaries: Vec<Binary>,
    /// Whether each binary's decompiler process starts as the binary loads: in a server, and for
    /// a tool run from the shell whose answer comes from it. Otherwise the first request
    /// starts it.
    start_workers: bool,
}

impl Cache {
    pub fn new(start_workers: bool) -> Cache {
        Cache { binaries: Vec::new(), start_workers }
    }

    /// The binary at `path`, analyzed now unless it was before and the file has not changed.
    pub fn get(&mut self, path: &Path) -> Result<&mut Binary> {
        let metadata = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        let stamp = (metadata.modified()?, metadata.len());
        let binary = match self.binaries.iter().position(|binary| binary.path == path) {
            Some(index) if self.binaries[index].stamp == stamp => self.binaries.remove(index),
            stale => {
                // Dropping a binary ends its decompiler process.
                stale.map(|index| self.binaries.remove(index));
                Binary::load(path, stamp, self.start_workers).with_context(|| format!("cannot load {}", path.display()))?
            }
        };
        self.binaries.insert(0, binary);
        self.binaries.truncate(KEPT);
        Ok(&mut self.binaries[0])
    }

    /// Two binaries at once, for a tool that compares them.
    pub fn pair(&mut self, first: &Path, second: &Path) -> Result<(&mut Binary, &mut Binary)> {
        anyhow::ensure!(first != second, "{} is given twice", first.display());
        self.get(first)?;
        self.get(second)?;
        let (second, first) = self.binaries.split_at_mut(1);
        Ok((&mut first[0], &mut second[0]))
    }
}
