//! Finds what the layout of a banked image leaves open, by trying it.
//!
//! Three things can be open. The ranges every bank shares are found by comparing the regions
//! byte for byte. The trampolines are the scheme, of those recore knows, whose bytes are there.
//! And which region is which bank is a matching: every pairing of a region with a bank is
//! scored on where the trampolines that name the bank land in the region's bytes, see
//! [`crate::score`], and the assignment with the largest sum is taken. How far the next best
//! assignment falls short, region by region, says how sure each placement is.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;

use crate::image::{Compiler, Image, Section};
use crate::layout::{BankingLayout, Layout, SCHEMES, Trampoline};
use crate::program::Program;
use crate::score::{Score, landing, score};

/// Bits by which an assignment must beat the next best for a region to count as placed: odds
/// of a thousand to one.
const DECISIVE: f64 = 10.0;

/// What a sweep found, best first.
pub struct Sweep {
    /// `[start, end)` of the 16-bit addresses every bank shares.
    pub common: Vec<(u64, u64)>,
    /// How many regions were compared to find them, unless the layout gave them.
    pub compared: Option<usize>,
    pub candidates: Vec<Candidate>,
    /// The schemes whose trampolines the image does not have.
    pub absent: Vec<String>,
    /// How the analyses of the first two candidates differ.
    pub difference: Option<String>,
    pub timings: Vec<(&'static str, Duration)>,
    layout: Layout,
    /// The layout's file, which its regions' files are named from.
    path: PathBuf,
}

/// One way to complete the layout: a trampoline scheme and a bank for each open region.
pub struct Candidate {
    pub scheme: String,
    /// Trampolines the scheme finds.
    pub trampolines: usize,
    /// The open regions in the order of the layout.
    pub placements: Vec<Placement>,
    /// The score of the whole image under this candidate, on the targets that cross.
    pub score: Score,
    banking: BankingLayout,
    pieces: Vec<Piece>,
}

/// Where one open region goes, and what says so.
pub struct Placement {
    /// The region's place among the regions of the layout, counted from zero.
    pub region: usize,
    pub offset: u64,
    /// None when there are more regions than banks and this one is left over.
    pub bank: Option<u64>,
    /// What the trampolines that name the bank say of the region's bytes.
    pub evidence: Option<Score>,
    /// The bank that fits this region's bytes best after its own, and the bits it scores.
    pub rival: Option<(u64, f64)>,
    /// Bits by which the best assignment that gives this region another bank falls short, and
    /// that bank: infinite when no other bank is to be had, and unknown for a candidate that
    /// is not the best of its scheme.
    pub margin: Option<f64>,
    pub otherwise: Option<u64>,
}

impl Placement {
    /// The evidence of the region's own bytes for its bank over the next best bank.
    fn own_lead(&self) -> f64 {
        self.evidence.map_or(0.0, |evidence| evidence.bits()) - self.rival.map_or(0.0, |(_, bits)| bits)
    }

    /// In a few words, how the region came by its bank.
    pub fn verdict(&self) -> String {
        let targets = self.evidence.map_or(0, |evidence| evidence.follows_end.total);
        let bank = |bank: Option<u64>| bank.map_or("no bank".to_string(), |bank| format!("bank {bank}"));
        match self.bank {
            None => "not placed: no trampoline reaches a bank that is left for it".into(),
            Some(_) if self.margin.is_some_and(|margin| margin < DECISIVE) => format!("open: {} fits within {:.1} bits, with {targets} trampolines into this one", bank(self.otherwise), self.margin.unwrap_or_default()),
            Some(_) if self.own_lead() < DECISIVE => format!("by elimination: {targets} trampolines do not tell it from {}, which another region holds", bank(self.rival.map(|rival| rival.0))),
            Some(_) => "placed".into(),
        }
    }
}

/// A stretch of a region of the layout and the address it loads at.
struct Piece {
    region: usize,
    /// Bytes into the region.
    skip: u64,
    length: u64,
    address: u64,
}

/// A layout with its bytes, and what is known of its banks before any are assigned.
struct Draft<'a> {
    layout: &'a Layout,
    bytes: &'a [Vec<u8>],
    /// The regions whose bank is open, as indices into the layout's.
    open: Vec<usize>,
    common: Vec<(u64, u64)>,
}

impl Draft<'_> {
    /// `[start, end)` of the 16-bit addresses the bytes of `region` have.
    fn span(&self, region: usize) -> (u64, u64) {
        let region = &self.layout.region[region];
        (region.address, region.address + region.length)
    }

    /// The pieces the layout loads when each of `placed`, an open region, is the bank beside
    /// it. The common ranges load once, from the region `shared`.
    fn pieces(&self, placed: &[(usize, u64)], shared: Option<usize>) -> Vec<Piece> {
        let is_open = |region: usize| self.layout.region[region].bank.is_some();
        let mut pieces: Vec<Piece> = (0..self.layout.region.len()).filter(|&region| !is_open(region)).map(|region| Piece { region, skip: 0, length: self.layout.region[region].length, address: self.layout.region[region].address }).collect();
        let bank_of = |region: usize| placed.iter().find(|placed| placed.0 == region).map(|placed| placed.1);
        for &region in &self.open {
            let (start, end) = self.span(region);
            let mut cuts: Vec<u64> = self.common.iter().flat_map(|&(from, to)| [from, to]).filter(|&cut| start < cut && cut < end).chain([start, end]).collect();
            cuts.sort_unstable();
            cuts.dedup();
            for (from, to) in cuts.iter().zip(&cuts[1..]) {
                let is_common = self.common.iter().any(|&(start, end)| start <= *from && *from < end);
                let address = match (is_common, bank_of(region)) {
                    (true, _) if shared == Some(region) => *from,
                    (false, Some(bank)) => bank << 16 | from,
                    _ => continue,
                };
                match pieces.last_mut().filter(|last| last.region == region && last.address + last.length == address && last.skip + last.length == from - start) {
                    Some(last) => last.length += to - from,
                    None => pieces.push(Piece { region, skip: from - start, length: to - from, address }),
                }
            }
        }
        pieces
    }

    fn sections(&self, pieces: &[Piece]) -> Vec<Section> {
        pieces.iter().map(|piece| self.layout.region[piece.region].section(piece.skip, piece.address, &self.bytes[piece.region][piece.skip as usize..(piece.skip + piece.length) as usize])).collect()
    }

    fn image(&self, pieces: &[Piece], banking: &BankingLayout) -> Result<Image> {
        self.layout.image("sweep".into(), self.sections(pieces), Some(banking))
    }

    /// The best ways to place the open regions under the trampolines of `banking`, and the
    /// time spent scoring pairs and assigning. None when the image has no such trampolines.
    fn place(&self, scheme: &str, banking: BankingLayout) -> Result<Option<(Vec<Candidate>, [Duration; 2])>> {
        // Where a trampoline goes does not depend on where its caller is loaded, so any
        // placement shows them all: here each open region in a bank no trampoline can name.
        let apart: Vec<(usize, u64)> = self.open.iter().zip(0x100..).map(|(&region, bank)| (region, bank)).collect();
        let first = self.open.first().copied();
        let provisional = self.image(&self.pieces(&apart, first), &banking)?;
        let reached = || provisional.banking.trampolines.values().chain(provisional.banking.calls.values()).copied();
        let trampolines = reached().count();
        if trampolines == 0 {
            return Ok(None);
        }
        // The functions trampolines reach in each bank that no region of the layout holds yet.
        let mut targets: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for target in reached().filter(|&target| provisional.section_at(target).is_none() && !(target >> 16 == 0 && provisional.banking.is_common(target as u16))) {
            targets.entry(target >> 16).or_default().insert(target);
        }
        let banks: Vec<u64> = targets.keys().copied().collect();

        let start = Instant::now();
        let pairs: Vec<(usize, usize)> = (0..self.open.len()).flat_map(|region| (0..banks.len()).map(move |bank| (region, bank))).collect();
        let scores: Vec<Score> = pairs
            .par_iter()
            .map(|&(region, bank)| Ok(landing(&self.image(&self.pieces(&[(self.open[region], banks[bank])], first), &banking)?, &targets[&banks[bank]])))
            .collect::<Result<_>>()?;
        let evidence = |region: usize, bank: usize| scores[region * banks.len() + bank];
        let scored = start.elapsed();

        // A square of gains: a region without a bank and a bank without a region gain nothing.
        let start = Instant::now();
        let size = self.open.len().max(banks.len());
        let mut gain = vec![vec![0.0; size]; size];
        for &(region, bank) in &pairs {
            gain[region][bank] = evidence(region, bank).bits();
        }
        let total = |assigned: &[usize]| assigned.iter().enumerate().map(|(row, &column)| gain[row][column]).sum::<f64>();
        let best = assign(&gain);
        // The best assignment that gives each region in turn something else.
        let others: Vec<(f64, Vec<usize>)> = (0..self.open.len())
            .map(|region| {
                let mut without = gain.clone();
                without[region][best[region]] = FORBIDDEN;
                let other = assign(&without);
                (if other[region] == best[region] { f64::INFINITY } else { total(&best) - total(&other) }, other)
            })
            .collect();
        let assigned = start.elapsed();

        let candidate = |assignment: &[usize], measured: bool| -> Result<Candidate> {
            let bank = |region: usize| banks.get(assignment[region]).copied();
            let placed: Vec<(usize, u64)> = (0..self.open.len()).filter_map(|region| Some((self.open[region], bank(region)?))).collect();
            // The region that is bank 0 is loaded whole, the way a layout written by hand has it.
            let shared = placed.iter().find(|placed| placed.1 == 0).map(|placed| placed.0).or(first);
            let pieces = self.pieces(&placed, shared);
            let image = self.image(&pieces, &banking)?;
            let placements = (0..self.open.len())
                .map(|region| Placement {
                    region: self.open[region],
                    offset: self.layout.region[self.open[region]].offset,
                    bank: bank(region),
                    evidence: bank(region).map(|_| evidence(region, assignment[region])),
                    rival: (0..banks.len()).filter(|&other| other != assignment[region]).map(|other| (banks[other], evidence(region, other).bits())).max_by(|a, b| a.1.total_cmp(&b.1)),
                    margin: measured.then_some(others[region].0),
                    otherwise: banks.get(others[region].1[region]).copied().filter(|_| measured),
                })
                .collect();
            Ok(Candidate { scheme: scheme.to_string(), trampolines, placements, score: score(&image).crossing(), banking: banking.clone(), pieces })
        };
        let mut candidates = vec![candidate(&best, true)?];
        // The next best assignment over all is the nearest of those.
        if let Some((_, other)) = others.iter().filter(|(margin, _)| margin.is_finite()).min_by(|a, b| a.0.total_cmp(&b.0)) {
            candidates.push(candidate(other, false)?);
        }
        Ok(Some((candidates, [scored, assigned])))
    }
}

/// A gain no assignment takes while it has another choice.
const FORBIDDEN: f64 = -1e12;

/// For each row of the square `gain`, the column it gets when each column goes to one row and
/// the gains of the pairs sum to the most: the Hungarian method, on costs that are the gains
/// negated.
fn assign(gain: &[Vec<f64>]) -> Vec<usize> {
    let size = gain.len();
    // Rows and columns count from one; column 0 holds the row being placed.
    let (mut row_potential, mut column_potential) = (vec![0.0; size + 1], vec![0.0; size + 1]);
    let (mut row_of, mut came_from) = (vec![0; size + 1], vec![0; size + 1]);
    for row in 1..=size {
        row_of[0] = row;
        let mut column = 0;
        let mut slack = vec![f64::INFINITY; size + 1];
        let mut used = vec![false; size + 1];
        while row_of[column] != 0 {
            used[column] = true;
            let (current, mut least, mut next) = (row_of[column], f64::INFINITY, 0);
            for other in (1..=size).filter(|&other| !used[other]) {
                let reduced = -gain[current - 1][other - 1] - row_potential[current] - column_potential[other];
                if reduced < slack[other] {
                    (slack[other], came_from[other]) = (reduced, column);
                }
                if slack[other] < least {
                    (least, next) = (slack[other], other);
                }
            }
            for other in 0..=size {
                if used[other] {
                    row_potential[row_of[other]] += least;
                    column_potential[other] -= least;
                } else {
                    slack[other] -= least;
                }
            }
            column = next;
        }
        while column != 0 {
            row_of[column] = row_of[came_from[column]];
            column = came_from[column];
        }
    }
    let mut columns = vec![0; size];
    (1..=size).for_each(|column| columns[row_of[column] - 1] = column - 1);
    columns
}

/// Bytes that the open regions must share at one end for it to count as common. Banks that
/// begin with the same few instructions by coincidence share less. Banks that begin with a
/// longer run of the same code that is theirs alone are taken to share it, wrongly.
const SHARED_AT_LEAST: u64 = 32;

/// `[start, end)` of the 16-bit addresses at which the regions `open`, given as the address
/// each starts at and its bytes, hold the same: what lies below the first address where two
/// differ or only some have bytes, and what lies above the last. A range with no bytes in it
/// is left out; `loaded` says whether any other region of the layout has bytes in one.
fn shared(open: &[(u64, &[u8])], loaded: impl Fn(u64, u64) -> bool) -> Result<Vec<(u64, u64)>> {
    let byte = |&(start, data): &(u64, &[u8]), addr: u64| addr.checked_sub(start).and_then(|offset| data.get(offset as usize)).copied();
    let differs = |addr: u64| open.iter().any(|region| byte(region, addr) != byte(&open[0], addr));
    let (Some(first), Some(last)) = ((0..0x1_0000).find(|&addr| differs(addr)), (0..0x1_0000).rev().find(|&addr| differs(addr))) else {
        bail!("the {} regions whose bank is open hold the same bytes, so comparing them does not show what the banks share: give `common` in the layout", open.len())
    };
    // What the regions hold the same below `first` and above `last`.
    let (lowest, highest) = (open.iter().map(|region| region.0).min().unwrap_or(0), open.iter().map(|&(start, data)| start + data.len() as u64).max().unwrap_or(0));
    let below = if first - lowest.min(first) < SHARED_AT_LEAST { lowest.min(first) } else { first };
    let above = if highest.max(last + 1) - (last + 1) < SHARED_AT_LEAST { highest.max(last + 1) } else { last + 1 };
    let held = |from: u64, to: u64| lowest < to && from < highest;
    Ok([(0, below), (above, 0x1_0000)].into_iter().filter(|&(from, to)| from < to && (held(from, to) || loaded(from, to))).collect())
}

/// Finds what the layout at `path` leaves open.
pub fn sweep(path: &Path) -> Result<Sweep> {
    let start = Instant::now();
    let mut layout = Layout::read(path)?;
    let bytes = layout.bytes(path)?;
    let given = layout.banking.take().unwrap_or_default();
    let open: Vec<usize> = (0..layout.region.len()).filter(|&region| layout.region[region].bank.is_some()).collect();
    for region in open.iter().map(|&region| &layout.region[region]) {
        ensure!(region.address + region.length <= 0x1_0000, "the region at offset {:#x} is open, so its `address` is the 16-bit address it starts at, and it runs past 0x10000", region.offset);
    }
    let mut timings = vec![("read", start.elapsed())];

    let start = Instant::now();
    let (common, compared) = if given.common.is_empty() {
        let regions: Vec<(u64, &[u8])> = open.iter().map(|&region| (layout.region[region].address, bytes[region].as_slice())).collect();
        let loaded = |from: u64, to: u64| layout.region.iter().any(|region| region.bank.is_none() && region.address < to && from < region.address + region.length);
        (shared(&regions, loaded)?, Some(open.len()))
    } else {
        (given.common.iter().map(|&(start, end)| (u64::from(start), u64::from(end))).collect(), None)
    };
    timings.push(("compare regions", start.elapsed()));

    let draft = Draft { layout: &layout, bytes: &bytes, open, common: common.clone() };
    let narrow = |common: &[(u64, u64)]| common.iter().map(|&(start, end)| (start as u16, end as u32)).collect();
    let schemes: Vec<(String, BankingLayout)> = if given.trampoline.is_empty() {
        let read = |text: &str| -> Result<Trampoline> { toml::from_str(text).context("reading a trampoline scheme") };
        SCHEMES.iter().map(|&(name, text)| Ok((name.to_string(), BankingLayout { common: narrow(&common), trampoline: vec![read(text)?] }))).collect::<Result<_>>()?
    } else {
        vec![("the layout's trampolines".to_string(), BankingLayout { common: narrow(&common), trampoline: given.trampoline })]
    };
    let (mut candidates, mut absent) = (Vec::new(), Vec::new());
    let mut spent = [Duration::ZERO; 3];
    for (name, banking) in schemes {
        let start = Instant::now();
        match draft.place(&name, banking)? {
            Some((found, [scored, assigned])) => {
                candidates.extend(found);
                spent = [spent[0] + scored, spent[1] + assigned, spent[2] + start.elapsed() - scored - assigned];
            }
            None => absent.push(name),
        }
    }
    timings.extend([("score each region as each bank", spent[0]), ("assign", spent[1]), ("find trampolines, score the candidates", spent[2])]);
    candidates.sort_by(|a, b| b.score.bits().total_cmp(&a.score.bits()));

    let start = Instant::now();
    let analyzed = |candidate: &Candidate| -> Result<Program> {
        let image = draft.image(&candidate.pieces, &candidate.banking)?;
        let analysis = crate::analyze(&image);
        Ok(Program::new(image, analysis))
    };
    let difference = match candidates.as_slice() {
        [first, second, ..] => Some(differences(first, &analyzed(first)?, second, &analyzed(second)?)),
        _ => None,
    };
    timings.push(("analyze and compare the first two", start.elapsed()));
    Ok(Sweep { common, compared, candidates, absent, difference, timings, layout, path: path.to_path_buf() })
}

/// How the second candidate differs from the first: in its layout, and in what analysis finds.
fn differences(first: &Candidate, best: &Program, second: &Candidate, next: &Program) -> String {
    let bank = |bank: Option<u64>| bank.map_or("no bank".to_string(), |bank| format!("bank {bank}"));
    let mut moved: Vec<String> = first.placements.iter().zip(&second.placements).filter(|(a, b)| a.bank != b.bank).map(|(a, b)| format!("region {} is {} in place of {}", a.region, bank(b.bank), bank(a.bank))).collect();
    if first.scheme != second.scheme {
        moved.insert(0, format!("its trampolines are {}", second.scheme));
    }
    // Addresses carry the bank, so a function is the same one only where both load its bytes.
    let entries = |program: &Program| -> BTreeSet<u64> { program.functions().map(|function| function.addr).collect() };
    let (ours, theirs) = (entries(best), entries(next));
    format!(
        "{}; {} functions start at the same address in both, {} only in the first and {} only in the second; {} calls against {}",
        moved.join(", "),
        ours.intersection(&theirs).count(),
        ours.difference(&theirs).count(),
        theirs.difference(&ours).count(),
        best.analysis.calls.len(),
        next.analysis.calls.len(),
    )
}

impl Sweep {
    /// The layout of the best candidate, to be written to the file `out`: complete, so that it
    /// loads as an image. None when the sweep found no candidate.
    pub fn layout(&self, out: &Path) -> Result<Option<String>> {
        let Some(best) = self.candidates.first() else { return Ok(None) };
        let directory = |path: &Path| path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")).canonicalize();
        let beside = directory(out).ok().zip(directory(&self.path).ok()).is_some_and(|(out, layout)| out == layout);
        // A file is named from the layout's place, which this layout may not share.
        let file = |file: &Path| -> Result<String> { Ok(serde_json::to_string(&if beside { file.to_path_buf() } else { self.path.with_file_name(file).canonicalize()? })?) };
        let mut text = String::new();
        writeln!(text, "machine = {}", serde_json::to_string(&self.layout.machine)?)?;
        writeln!(text, "entry = [{}]", self.layout.entry.iter().map(|entry| format!("{entry:#06x}")).collect::<Vec<_>>().join(", "))?;
        if let Some(names) = &self.layout.names {
            writeln!(text, "names = {}", file(names)?)?;
        }
        match self.layout.compiler {
            Some(Compiler::Keil) => writeln!(text, "compiler = \"keil\"")?,
            Some(Compiler::Sdcc) => writeln!(text, "compiler = \"sdcc\"")?,
            None => {}
        }
        writeln!(text)?;
        for placement in best.placements.iter().filter(|placement| placement.bank.is_none()) {
            writeln!(text, "# The region at offset {:#x} is left out: {}.", placement.offset, placement.verdict())?;
        }
        for piece in &best.pieces {
            let region = &self.layout.region[piece.region];
            writeln!(text, "[[region]]\nfile = {}", file(&region.file)?)?;
            writeln!(text, "offset = {:#x}\nlength = {:#x}\naddress = {:#08x}", region.offset + piece.skip, piece.length, piece.address)?;
            for (key, value) in [("executable", region.executable), ("writable", region.writable)] {
                if value {
                    writeln!(text, "{key} = true")?;
                }
            }
            if let Some(name) = &region.name {
                writeln!(text, "name = {}", serde_json::to_string(name)?)?;
            }
            writeln!(text)?;
        }
        writeln!(text, "[banking]\ncommon = [{}]", self.common.iter().map(|(start, end)| format!("[{start:#06x}, {end:#x}]")).collect::<Vec<_>>().join(", "))?;
        for trampoline in &best.banking.trampoline {
            write!(text, "\n[[banking.trampoline]]\n# {}\n{trampoline}", best.scheme)?;
        }
        Ok(Some(text))
    }
}

impl fmt::Display for Sweep {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ranges = self.common.iter().map(|(start, end)| format!("{start:#06x}-{end:#x}")).collect::<Vec<_>>().join(" ");
        match self.compared {
            Some(regions) => writeln!(f, "common to every bank: {ranges}, where the {regions} open regions hold the same bytes")?,
            None => writeln!(f, "common to every bank: {ranges}, as the layout says")?,
        }
        for scheme in &self.absent {
            writeln!(f, "{scheme}: the image has no such trampolines")?;
        }
        if self.candidates.is_empty() {
            writeln!(f, "no trampolines found, so nothing says which region is which bank")?;
        }
        for (rank, candidate) in self.candidates.iter().enumerate() {
            let banks: Vec<String> = candidate.placements.iter().map(|placement| placement.bank.map_or("?".into(), |bank| bank.to_string())).collect();
            writeln!(f, "\n{}. {}, {} trampolines; regions in file order are banks {}", rank + 1, candidate.scheme, candidate.trampolines, banks.join(" "))?;
            write!(f, "{}", candidate.score)?;
            if rank > 0 {
                continue;
            }
            writeln!(f, "  region   offset  bank  trampolines  follow an end  called there   bits  next best bank    margin")?;
            for placement in &candidate.placements {
                let bank = placement.bank.map_or("?".into(), |bank| bank.to_string());
                let (targets, follow, called, bits) = placement.evidence.map_or((0, 0, 0, 0.0), |evidence| (evidence.follows_end.total, evidence.follows_end.good, evidence.called_locally.good, evidence.bits()));
                let rival = placement.rival.map_or("none".into(), |(bank, bits)| format!("{bank} at {bits:.0}"));
                writeln!(f, "  {:>6} {:>#8x} {bank:>5} {targets:>12} {follow:>14} {called:>13} {bits:>6.0}  {rival:>14} {:>9.0}  {}", placement.region, placement.offset, placement.margin.unwrap_or(f64::NAN), placement.verdict())?;
            }
        }
        if let Some(difference) = &self.difference {
            writeln!(f, "\nthe second differs from the first: {difference}")?;
        }
        let total: Duration = self.timings.iter().map(|timing| timing.1).sum();
        let phases: Vec<String> = self.timings.iter().map(|(phase, time)| format!("{phase} {:.0} ms", time.as_secs_f64() * 1e3)).collect();
        writeln!(f, "\nswept in {:.0} ms: {}", total.as_secs_f64() * 1e3, phases.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_assignment_is_the_best_as_a_whole_and_not_row_by_row() {
        // The first row likes the first column most, and must leave it to the second.
        assert_eq!(assign(&[vec![10.0, 9.0], vec![9.0, 1.0]]), [1, 0]);
        assert_eq!(assign(&[vec![5.0, 1.0, 0.0], vec![4.0, 3.0, 0.0], vec![0.0, 0.0, 0.0]]), [0, 1, 2]);
    }

    #[test]
    fn banks_share_the_ranges_where_all_hold_the_same_bytes() {
        let mut first = vec![0x11; 0x1_0000];
        let mut second = first.clone();
        first[0x4000..0xF000].fill(0x22);
        second[0x4000..0xF000].fill(0x33);
        // The banks have the same byte somewhere in between as well.
        second[0x8000] = 0x22;
        assert_eq!(shared(&[(0, &first), (0, &second)], |_, _| false).unwrap(), [(0, 0x4000), (0xF000, 0x1_0000)]);
    }

    #[test]
    fn banks_that_only_begin_alike_share_nothing_of_their_own() {
        // Both start at 0x8000 with the same two bytes. Another region holds the code below.
        let (first, second) = ([0xC0, 0xE0, 0x01, 0x02], [0xC0, 0xE0, 0x03]);
        let below = |from: u64, to: u64| from < 0x100 && to > 0;
        assert_eq!(shared(&[(0x8000, &first), (0x8000, &second)], below).unwrap(), [(0, 0x8000)]);
        assert!(shared(&[(0x8000, &first), (0x8000, &first)], below).is_err());
    }
}
