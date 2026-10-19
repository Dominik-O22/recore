//! The memory of a live process, for `run` to start from in place of the file's.
//!
//! A snapshot is a directory. Its `snapshot.tsv` has one row per line, its fields separated
//! by tabs, and addresses in hex without `0x`:
//!
//! - `region START END PERMISSIONS NAME`: the bytes from START up to END, as a line of
//!   `/proc/<pid>/maps` gives them. Its bytes are the file `START.bin` beside `snapshot.tsv`,
//!   with START spelled exactly as the row spells it: a row of `00400000` names
//!   `00400000.bin`, and a row of `400000` names `400000.bin`. A file shorter than its region
//!   holds the start of it, for a region that could be read only in part. PERMISSIONS and NAME are for people;
//!   `run` does not read them, and NAME may be empty.
//! - `teb ADDRESS`: the thread environment block of a Windows thread, which `FS` points to
//!   in 32-bit code. The first one listed is the thread a run is on, unless the caller sets
//!   `FS_OFFSET`.
//!
//! Regions may come in any order and must not overlap. A snapshot is read a page at a time
//! as a run first touches the page, so a large one costs only the pages a run reaches.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

/// The file a snapshot's rows are in.
const MANIFEST: &str = "snapshot.tsv";

pub struct Snapshot {
    /// Sorted by address.
    regions: Vec<Region>,
    pub tebs: Vec<u64>,
}

struct Region {
    start: u64,
    end: u64,
    /// The bytes from `start`, which may stop before `end`.
    file: File,
    held: u64,
    path: PathBuf,
}

fn hex(field: &str) -> Result<u64> {
    u64::from_str_radix(field, 16).with_context(|| format!("`{field}` is not an address in hex"))
}

impl Snapshot {
    pub fn open(dir: &Path) -> Result<Snapshot> {
        let manifest = dir.join(MANIFEST);
        let text = std::fs::read_to_string(&manifest).with_context(|| format!("reading {}", manifest.display()))?;
        let mut regions = Vec::new();
        let mut tebs = Vec::new();
        for (number, line) in text.lines().enumerate().filter(|(_, line)| !line.is_empty()) {
            let fields: Vec<&str> = line.split('\t').collect();
            let row = || format!("{} line {}", manifest.display(), number + 1);
            match fields.as_slice() {
                ["region", start_text, end, _permissions, _name] => {
                    let (start, end) = (hex(start_text).with_context(row)?, hex(end).with_context(row)?);
                    ensure!(start < end, "{}: the region ends before it starts", row());
                    let path = dir.join(format!("{start_text}.bin"));
                    let file = File::open(&path).with_context(|| format!("{}: opening {}, which the row's START names as it is spelled", row(), path.display()))?;
                    let held = file.metadata()?.len();
                    ensure!(held <= end - start, "{}: {} holds {held} bytes, more than the region's {}", row(), path.display(), end - start);
                    regions.push(Region { start, end, file, held, path });
                }
                ["teb", addr] => tebs.push(hex(addr).with_context(row)?),
                _ => bail!("{}: expected `region START END PERMISSIONS NAME` or `teb ADDRESS`, separated by tabs", row()),
            }
        }
        regions.sort_by_key(|region| region.start);
        if let Some(pair) = regions.windows(2).find(|pair| pair[0].end > pair[1].start) {
            bail!("{}: the regions at {:x} and {:x} overlap", manifest.display(), pair[0].start, pair[1].start);
        }
        Ok(Snapshot { regions, tebs })
    }

    /// `[start, end)` of every region, held or not, which the run keeps its own memory out of.
    pub fn ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.regions.iter().map(|region| (region.start, region.end))
    }

    /// Copies what the snapshot holds of the bytes from `addr` into `bytes`, and marks them in
    /// `known`.
    pub fn fill(&self, addr: u64, bytes: &mut [u8], known: &mut [bool]) {
        let end = addr + bytes.len() as u64;
        let first = self.regions.partition_point(|region| region.end <= addr);
        for region in self.regions[first..].iter().take_while(|region| region.start < end) {
            let (from, to) = (region.start.max(addr), (region.start + region.held).min(end));
            if from >= to {
                continue;
            }
            let into = (from - addr) as usize..(to - addr) as usize;
            // A file the snapshot opened and measured fails to read only if it changed since.
            let mut file = &region.file;
            file.seek(SeekFrom::Start(from - region.start))
                .and_then(|_| file.read_exact(&mut bytes[into.clone()]))
                .unwrap_or_else(|error| panic!("reading {}: {error}", region.path.display()));
            known[into].fill(true);
        }
    }
}
