//! Binaries kept loaded between requests, with the lookups the tools share.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use recore::Image;
use recore::report::{Analysis, AnalyzedFunction, CallSite, CallTarget, DataRef, StringLiteral};
use recore_decomp::isolate::{FunctionRecord, Options, Status, Worker};

/// Binaries kept at once. Each holds its analysis and a decompiler process.
const KEPT: usize = 8;

/// Part of a function's body.
struct Extent {
    start: u64,
    end: u64,
    /// Entry of the function it belongs to.
    owner: u64,
}

/// An analyzed binary and its decompiler process.
pub struct Binary {
    path: PathBuf,
    /// Modification time and size of the file when it was loaded.
    stamp: (SystemTime, u64),
    pub image: Image,
    pub analysis: Analysis,
    /// Time spent loading and analyzing.
    pub analysis_ms: f64,
    /// Every range of every function, sorted by start. Ranges of different functions can
    /// overlap, because functions share exits.
    extents: Vec<Extent>,
    /// For each extent, the furthest end among it and those before it.
    reach: Vec<u64>,
    /// Data address to the indices in `Analysis::data_refs` that refer to it.
    refs_to: HashMap<u64, Vec<usize>>,
    /// Function entry or import slot to the indices in `Analysis::calls` that go there.
    calls_to: HashMap<u64, Vec<usize>>,
    /// Started when the binary is loaded, so it sets up while the first queries are answered.
    worker: Option<Worker>,
}

/// The address a call or tail call goes to: a function entry or an import slot.
fn target_addr(target: CallTarget) -> u64 {
    match target {
        CallTarget::Function(addr) | CallTarget::Import(addr) => addr,
    }
}

/// Whether `text` contains `pattern`, ignoring case. No pattern matches everything.
pub fn matches(text: &str, pattern: Option<&str>) -> bool {
    pattern.is_none_or(|p| text.to_lowercase().contains(&p.to_lowercase()))
}

/// Reads an address in hex, with or without `0x`. Also takes the names the decompiler prints
/// for unnamed functions, `func_0x401000` and Ghidra's `FUN_00401000`.
pub fn parse_addr(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = ["func_0x", "FUN_", "0x", "0X"].iter().find_map(|prefix| text.strip_prefix(prefix)).unwrap_or(text);
    u64::from_str_radix(digits, 16).ok()
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

        // A fragment is a piece of its owner, whether or not the owner's ranges list it.
        let mut extents: Vec<(u64, u64, u64)> = analysis
            .functions
            .iter()
            .flat_map(|f| f.ranges.iter().map(move |&(start, end)| (start, end, f.fragment_of.unwrap_or(f.addr))))
            .collect();
        extents.sort_unstable();
        extents.dedup();
        let extents: Vec<Extent> = extents.into_iter().map(|(start, end, owner)| Extent { start, end, owner }).collect();
        let reach = extents
            .iter()
            .scan(0, |furthest, extent| {
                *furthest = extent.end.max(*furthest);
                Some(*furthest)
            })
            .collect();

        let mut refs_to: HashMap<u64, Vec<usize>> = HashMap::new();
        for (index, reference) in analysis.data_refs.iter().enumerate() {
            refs_to.entry(reference.to).or_default().push(index);
        }
        let mut calls_to: HashMap<u64, Vec<usize>> = HashMap::new();
        for (index, call) in analysis.calls.iter().enumerate() {
            calls_to.entry(target_addr(call.target)).or_default().push(index);
        }
        Ok(Binary { path: path.to_path_buf(), stamp, image, analysis, analysis_ms, extents, reach, refs_to, calls_to, worker })
    }

    /// The function entered at `entry`, if it is one in its own right and not a fragment.
    pub fn function(&self, entry: u64) -> Option<&AnalyzedFunction> {
        let functions = &self.analysis.functions;
        let index = functions.binary_search_by_key(&entry, |f| f.addr).ok()?;
        Some(&functions[index]).filter(|f| f.fragment_of.is_none())
    }

    /// Functions in their own right, sorted by address.
    pub fn functions(&self) -> impl Iterator<Item = &AnalyzedFunction> {
        self.analysis.functions.iter().filter(|f| f.fragment_of.is_none())
    }

    /// Entries of the functions whose body contains `addr`, sorted. More than one when the
    /// address is in an exit that functions share.
    pub fn owners(&self, addr: u64) -> Vec<u64> {
        let mut index = self.extents.partition_point(|extent| extent.start <= addr);
        let mut owners = Vec::new();
        while index > 0 && self.reach[index - 1] > addr {
            index -= 1;
            if self.extents[index].end > addr {
                owners.push(self.extents[index].owner);
            }
        }
        owners.sort_unstable();
        owners.dedup();
        owners
    }

    /// The body of the function at `entry` as `[start, end)` ranges, sorted: its own ranges and
    /// those of its fragments.
    pub fn body(&self, entry: u64) -> Vec<(u64, u64)> {
        self.extents.iter().filter(|extent| extent.owner == entry).map(|extent| (extent.start, extent.end)).collect()
    }

    /// Bytes of code per function entry.
    pub fn sizes(&self) -> HashMap<u64, u64> {
        let mut sizes = HashMap::new();
        for extent in &self.extents {
            *sizes.entry(extent.owner).or_default() += extent.end - extent.start;
        }
        sizes
    }

    /// A function as `address` or `address(name)`.
    pub fn label(&self, entry: u64) -> String {
        match self.function(entry).and_then(|f| f.name.as_ref()) {
            Some(name) => format!("{entry:#x}({name})"),
            None => format!("{entry:#x}"),
        }
    }

    /// The functions containing an instruction, as labels; `?` if none does.
    pub fn site_label(&self, site: u64) -> String {
        let owners = self.owners(site);
        if owners.is_empty() { "?".into() } else { owners.iter().map(|&entry| self.label(entry)).collect::<Vec<_>>().join(" ") }
    }

    /// Distinct functions containing the given instruction addresses.
    pub fn users(&self, sites: impl Iterator<Item = u64>) -> BTreeSet<u64> {
        sites.flat_map(|site| self.owners(site)).collect()
    }

    pub fn import_name(&self, slot: u64) -> Option<&str> {
        self.analysis.imports.iter().find(|i| i.slot == slot).map(|i| i.name.as_str()).or_else(|| self.image.import_slots.get(&slot).map(String::as_str))
    }

    pub fn string_at(&self, addr: u64) -> Option<&StringLiteral> {
        let strings = &self.analysis.strings;
        strings.binary_search_by_key(&addr, |s| s.addr).ok().map(|index| &strings[index])
    }

    /// Calls and tail calls that go to the function or import slot at `target`.
    pub fn calls_to(&self, target: u64) -> impl Iterator<Item = &CallSite> {
        self.calls_to.get(&target).into_iter().flatten().map(|&index| &self.analysis.calls[index])
    }

    /// Instructions that refer to the data at `addr`.
    pub fn refs_to(&self, addr: u64) -> impl Iterator<Item = &DataRef> {
        self.refs_to.get(&addr).into_iter().flatten().map(|&index| &self.analysis.data_refs[index])
    }

    /// Calls made from `[start, end)`.
    pub fn calls_in(&self, start: u64, end: u64) -> impl Iterator<Item = &CallSite> {
        let calls = &self.analysis.calls;
        calls[calls.partition_point(|call| call.at < start)..].iter().take_while(move |call| call.at < end)
    }

    /// Data references made from `[start, end)`.
    pub fn refs_in(&self, start: u64, end: u64) -> impl Iterator<Item = &DataRef> {
        let refs = &self.analysis.data_refs;
        refs[refs.partition_point(|reference| reference.from < start)..].iter().take_while(move |reference| reference.from < end)
    }

    /// The entry of the function that `addr` is in. In a shared exit, the function that starts
    /// there if one does, else the first that has it.
    pub fn function_at(&self, addr: u64) -> Result<u64> {
        let owners = self.owners(addr);
        owners.iter().copied().find(|&entry| entry == addr).or_else(|| owners.first().copied()).with_context(|| format!("no function contains {addr:#x}"))
    }

    /// The entry of the function called `name`: an exact match, or else the only function whose
    /// name contains it.
    pub fn function_named(&self, name: &str) -> Result<u64> {
        let named = || self.functions().filter_map(|f| Some((f.addr, f.name.as_deref()?)));
        if let Some((entry, _)) = named().find(|&(_, candidate)| candidate == name) {
            return Ok(entry);
        }
        let partial: Vec<(u64, &str)> = named().filter(|(_, candidate)| matches(candidate, Some(name))).collect();
        match partial.as_slice() {
            [(entry, _)] => Ok(*entry),
            [] => bail!("no function is named `{name}`; the `functions` tool lists the names this binary carries"),
            several => {
                let shown: Vec<String> = several.iter().take(10).map(|&(entry, _)| self.label(entry)).collect();
                bail!("`{name}` matches {} functions: {}{}", several.len(), shown.join(" "), if several.len() > 10 { " ..." } else { "" })
            }
        }
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
