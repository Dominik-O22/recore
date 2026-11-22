//! Binaries kept loaded between requests, with the lookups the tools share.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use recore::Image;
use recore::edits::{Edits, EditsFile, Stamp};
use recore::program::Program;
use recore_decomp::isolate::{FunctionRecord, Options, Worker, returning_callers};
use recore::structs::Recovered;
use recore_decomp::{Flow, Instruction, Local, StructReport};

/// How long the decompiler process gets for a request that is not a decompilation.
pub const QUICK: Duration = Duration::from_secs(30);

/// Binaries kept at once. Each holds its analysis and a decompiler process.
const KEPT: usize = 8;

/// An analyzed binary and its decompiler process.
pub struct Binary {
    /// The device and inode of the binary's file, so that two spellings of it find one binary,
    /// and the file name it was given, which names its edits file.
    key: (u64, u64, OsString),
    /// Modification time and size of the file when it was loaded.
    stamp: (SystemTime, u64),
    pub program: Program,
    /// The names, comments and types given to this binary, as saved when last read.
    pub edits: Edits,
    /// Where `edits` are saved.
    edits_file: EditsFile,
    /// The stamp of the file `edits` were read from, or `None` if there was none.
    edits_stamp: Option<Stamp>,
    /// The name the analysis gave each of `program.analysis.functions`, before edits.
    found_names: Vec<Option<String>>,
    /// Time spent loading and analyzing.
    pub analysis_ms: f64,
    /// Started when the binary is loaded, so it sets up while the first queries are answered,
    /// or by the first request, for a tool run from the shell that may make none.
    worker: Worker,
    /// The objects of a kernel image that hold functions, and the struct each is, read from its
    /// BTF when first asked for.
    objects: std::cell::OnceCell<recore_decomp::btf::Objects>,
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
    fn load(path: &Path, key: (u64, u64, OsString), stamp: (SystemTime, u64), start_worker: bool) -> Result<Binary> {
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

        let edits_file = EditsFile::of(path)?;
        let edits_stamp = edits_file.stamp();
        let edits = edits_file.load()?;
        let found_names = analysis.functions.iter().map(|function| function.name.clone()).collect();
        edits.apply(&mut analysis);
        let program = Program::new(image, analysis);
        // What loading freed would otherwise be held while queries are answered.
        recore_decomp::give_back_freed_memory();
        Ok(Binary { key, stamp, program, edits, edits_file, edits_stamp, found_names, analysis_ms, worker, objects: std::cell::OnceCell::new() })
    }

    /// Changes the binary's edits as saved now, which may hold edits another process saved since
    /// they were read, and saves them. Nothing is saved if `change` fails.
    pub fn edit<T>(&mut self, change: impl FnOnce(&mut Edits) -> Result<T>) -> Result<T> {
        let (edits, stamp, out) = self.edits_file.update(change)?;
        self.edits_stamp = Some(stamp);
        self.take(edits);
        Ok(out)
    }

    /// Reads the edits again if another process saved them since they were read.
    fn refresh(&mut self) -> Result<()> {
        let stamp = self.edits_file.stamp();
        if stamp != self.edits_stamp {
            let edits = self.edits_file.load()?;
            self.edits_stamp = stamp;
            self.take(edits);
        }
        Ok(())
    }

    /// Makes `edits` the binary's edits. The decompiler process takes names, comments and named
    /// structs as it runs. A declaration, a type, a name taken away or a struct whose layout
    /// grows replaces it with one that starts from the new edits, so the next decompilation
    /// waits for it to set up again.
    fn take(&mut self, edits: Edits) {
        if edits == self.edits {
            return;
        }
        self.edits = edits;
        for (function, found) in self.program.analysis.functions.iter_mut().zip(&self.found_names) {
            function.name.clone_from(found);
        }
        self.edits.apply(&mut self.program.analysis);
        self.worker.update(&self.edits, QUICK);
    }

    /// The objects of a kernel image that hold functions, each with the struct its functions'
    /// prototypes say it is: see [`recore_decomp::btf::objects`]. None for any other image.
    pub fn objects(&self) -> &recore_decomp::btf::Objects {
        let image = &self.program.image;
        self.objects.get_or_init(|| recore_decomp::btf::types(image).map(|types| recore_decomp::btf::objects(image, &types)).unwrap_or_default())
    }

    /// Where this binary's edits are saved.
    pub fn edits_file(&self) -> &Path {
        self.edits_file.path()
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

    /// Gives the decompiler process the calls to the function at `addr`, from this binary's
    /// index of them, before it decompiles the function: see [`Worker::callers`].
    fn give_callers(&mut self, addr: u64) {
        let program = &self.program;
        self.worker.callers(addr, || returning_callers(program, addr));
    }

    /// The data flow of the function at `addr`, which costs one decompilation.
    pub fn flow(&mut self, addr: u64, timeout: Duration) -> Result<Flow> {
        self.give_callers(addr);
        self.worker.flow(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The C of the function at `addr` with the address of its instruction before each line.
    pub fn addressed(&mut self, addr: u64, timeout: Duration) -> Result<String> {
        self.give_callers(addr);
        self.worker.addressed(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The variables of the function at `addr`, which costs one decompilation.
    pub fn locals(&mut self, addr: u64, timeout: Duration) -> Result<Vec<Local>> {
        self.give_callers(addr);
        self.worker.locals(addr, timeout).map_err(anyhow::Error::msg)
    }

    /// The struct the decompiler recovered under the name `name` and those it points to. Its
    /// function is decompiled first if the decompiler process has not.
    pub fn recovered(&mut self, name: &str) -> Result<Recovered> {
        if let Some(function) = recore::structs::auto_function(name) {
            self.give_callers(function);
        }
        self.worker.recovered(name, QUICK).map_err(anyhow::Error::msg)
    }

    /// What struct recovery made of the objects the function at `addr` reaches through its
    /// pointers, which costs one decompilation.
    pub fn structs(&mut self, addr: u64, timeout: Duration) -> Result<StructReport> {
        self.give_callers(addr);
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
        self.give_callers(addr);
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

    /// The binary at `path`, analyzed now unless it was before and the file has not changed,
    /// with the edits saved last.
    pub fn get(&mut self, path: &Path) -> Result<&mut Binary> {
        let metadata = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        // A FIFO would never end, /dev/zero would fill memory, and /dev/stdin is the protocol.
        anyhow::ensure!(metadata.is_file(), "{} is not a regular file", path.display());
        let key = (metadata.dev(), metadata.ino(), path.file_name().unwrap_or_default().to_os_string());
        let stamp = (metadata.modified()?, metadata.len());
        let binary = match self.binaries.iter().position(|binary| binary.key == key) {
            Some(index) if self.binaries[index].stamp == stamp => self.binaries.remove(index),
            stale => {
                // Dropping a binary ends its decompiler process.
                stale.map(|index| self.binaries.remove(index));
                Binary::load(path, key, stamp, self.start_workers).with_context(|| format!("cannot load {}", path.display()))?
            }
        };
        self.binaries.insert(0, binary);
        self.binaries.truncate(KEPT);
        let binary = &mut self.binaries[0];
        binary.refresh()?;
        Ok(binary)
    }

    /// Two binaries at once, for a tool that compares them.
    pub fn pair(&mut self, first: &Path, second: &Path) -> Result<(&mut Binary, &mut Binary)> {
        let first_key = self.get(first)?.key.clone();
        anyhow::ensure!(self.get(second)?.key != first_key, "{} is given twice", first.display());
        let (second, first) = self.binaries.split_at_mut(1);
        Ok((&mut first[0], &mut second[0]))
    }
}

impl recore_lift::Source for Binary {
    fn program(&self) -> &Program {
        &self.program
    }

    fn edits(&self) -> &Edits {
        &self.edits
    }

    fn lift(&mut self, start: u64, end: u64) -> Result<Vec<Instruction>> {
        Binary::lift(self, start, end)
    }

    fn register(&mut self, name: &str) -> Result<(String, u64, u32)> {
        Binary::register(self, name)
    }
}
