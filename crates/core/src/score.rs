//! How well the layout of a raw image fits its code, measured without knowing the answer.
//!
//! A layout says where bytes load: which region is which bank, what every bank shares, how one
//! bank reaches another. What it decides is where a transfer that leaves its region lands: a
//! call through a trampoline, a call from a bank into the common code. Under the right layout
//! such a target is the start of a function. Under a wrong one it is an address like any other.
//!
//! So the score follows control flow from the entry points, without guessing at code nothing
//! reaches, and puts three questions to each target that crosses. Each is a [`Component`]: how
//! many targets pass, and how often an address picked blindly from the same sections would.
//! The evidence is the distance between the two, in bits.
//!
//! Code that stays inside a region reads the same whichever bank the region is. It does not
//! where the region loads at another address and its calls name theirs outright, as an 8051's
//! do, so the first question is put to the calls inside a region as well.

use std::collections::BTreeSet;
use std::fmt;

use crate::arch::{Arch, Flow};
use crate::image::{Image, Machine, Section};
use crate::x86::X86;
use crate::{FxHashMap, FxHashSet};

/// One question put to every target, and how the answers compare with chance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Component {
    /// Targets that pass.
    pub good: usize,
    pub total: usize,
    /// The share of all addresses in the targets' sections that pass.
    pub chance: f64,
}

/// A rate is never taken to be nearer to certain than this, so that one count of zero does not
/// outweigh everything else. Picked by hand: the validation of `corpus/validate_layout_score.py`
/// and the sweeps of the corpus come out the same at 1e-3 and at 1e-5.
const FLOOR: f64 = 1e-4;

/// A component whose perfect outcome is worth fewer bits than this cannot tell layouts apart.
const WORTH_TELLING: f64 = 3.0;

impl Component {
    pub fn rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.good as f64 / self.total as f64 }
    }

    /// The evidence that the targets are not addresses picked blindly: how many bits it takes
    /// to describe the outcome with the chance rate beyond what it takes with the rate seen.
    /// Negative when the targets pass less often than chance.
    pub fn bits(&self) -> f64 {
        let (rate, chance) = (self.rate(), self.chance.clamp(FLOOR, 1.0 - FLOOR));
        let term = |seen: f64, expected: f64| if seen == 0.0 { 0.0 } else { seen * (seen / expected).log2() };
        let divergence = term(rate, chance) + term(1.0 - rate, 1.0 - chance);
        self.total as f64 * if rate >= chance { divergence } else { -divergence }
    }

    /// Why the component says nothing about this image, if it does not: there is nothing to
    /// ask, or nearly every address passes.
    pub fn blind(&self) -> Option<String> {
        let worth = self.total as f64 * -self.chance.clamp(FLOOR, 1.0).log2();
        match self.total {
            0 => Some("no target crosses the layout".into()),
            _ if worth < WORTH_TELLING => Some(format!("cannot tell: {} targets, and {:.1}% of all addresses pass", self.total, 100.0 * self.chance)),
            _ => None,
        }
    }
}

/// What the targets that cross the layout of an image say about it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    /// The target follows an instruction that execution does not run past: a return or a jump.
    pub follows_end: Component,
    /// A call from the target's own section goes there too: a second, independent source for
    /// the same function start.
    pub called_locally: Component,
    /// The target is not in the middle of an instruction that control flow reaches.
    pub on_instruction: Component,
    /// The target of a call that stays in its section follows such an instruction too. This
    /// tells the address a section loads at, where calls name their target outright, and not
    /// which bank it is.
    pub local_follows_end: Component,
}

impl Score {
    pub fn components(&self) -> [(&'static str, &Component); 4] {
        [
            ("follow a return or jump", &self.follows_end),
            ("called in their own region", &self.called_locally),
            ("on an instruction", &self.on_instruction),
            ("local calls follow an end", &self.local_follows_end),
        ]
    }

    /// The score on the targets that cross alone, which is what tells one bank from another:
    /// the calls inside a region land the same whichever bank it is, and only add to the score
    /// of whatever reaches more of them.
    pub fn crossing(self) -> Score {
        Score { local_follows_end: Component { good: 0, total: 0, chance: 0.0 }, ..self }
    }

    /// The evidence of all components. They overlap, so this ranks layouts and is not the odds
    /// of one.
    pub fn bits(&self) -> f64 {
        self.components().iter().map(|(_, component)| component.bits()).sum()
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.components().iter().all(|(_, component)| component.total == 0) {
            return writeln!(f, "0 bits: no target crosses the layout, and no call stays in a region");
        }
        writeln!(f, "{:.0} bits", self.bits())?;
        // Left out where it was not asked, see [`Score::crossing`].
        let asked = |component: &Component| component.total > 0 || *component != self.local_follows_end;
        for (name, component) in self.components().into_iter().filter(|(_, component)| asked(component)) {
            let Component { good, total, chance } = *component;
            write!(f, "  {name:<27} {good:>6} of {total:<6} {:>5.1}%, {:>4.1}% by chance: ", 100.0 * component.rate(), 100.0 * chance)?;
            match component.blind() {
                Some(reason) => writeln!(f, "{reason}")?,
                None => writeln!(f, "{:+.0} bits", component.bits())?,
            }
        }
        Ok(())
    }
}

/// Scores the layout of `image` on every target that crosses it: the functions its trampolines
/// reach, and the targets of jumps and calls from one section to another.
pub fn score(image: &Image) -> Score {
    by_machine(image, None)
}

/// Scores `targets` alone, as the only places execution is known to enter `image`.
pub fn landing(image: &Image, targets: &BTreeSet<u64>) -> Score {
    by_machine(image, Some(targets)).crossing()
}

fn by_machine(image: &Image, targets: Option<&BTreeSet<u64>>) -> Score {
    match image.machine {
        Machine::X86_64 if image.data_in_code => score_with::<X86<64, true>>(image, targets),
        Machine::X86_64 => score_with::<X86<64, false>>(image, targets),
        Machine::X86 if image.data_in_code => score_with::<X86<32, true>>(image, targets),
        Machine::X86 => score_with::<X86<32, false>>(image, targets),
        Machine::Aarch64 => score_with::<crate::arm64::Arm64>(image, targets),
        Machine::I8051 => score_with::<crate::i8051::I8051>(image, targets),
    }
}

fn score_with<A: Arch>(image: &Image, targets: Option<&BTreeSet<u64>>) -> Score {
    let known = || image.exports.iter().copied().chain([image.entry]);
    let walk = match targets {
        Some(targets) => Walk::new::<A>(image, targets.iter().copied()),
        None => Walk::new::<A>(image, known()),
    };
    let crossing: BTreeSet<u64> = walk.crossing.iter().copied().chain(image.banking.trampolines.values().copied()).chain(image.banking.calls.values().copied()).collect();
    walk.judge::<A>(targets.unwrap_or(&crossing))
}

/// The byte begins an instruction that control flow reaches.
const START: u8 = 1;
/// The byte is a later byte of such an instruction.
const INSIDE: u8 = 2;
/// The byte follows an instruction that execution does not run past.
const AFTER_END: u8 = 4;

/// The instructions control flow reaches from a set of addresses, and where it leaves a section.
struct Walk<'a> {
    image: &'a Image,
    /// For each section of the image, a set of the flags above for each of its bytes.
    marks: Vec<Vec<u8>>,
    /// Targets of calls that stay in their section.
    local_calls: FxHashSet<u64>,
    /// Targets of jumps, branches and calls that leave their section.
    crossing: FxHashSet<u64>,
}

impl<'a> Walk<'a> {
    fn new<A: Arch>(image: &'a Image, seeds: impl Iterator<Item = u64>) -> Walk<'a> {
        let mut walk = Walk { image, marks: image.sections.iter().map(|section| vec![0; section.data.len()]).collect(), local_calls: FxHashSet::default(), crossing: FxHashSet::default() };
        let mut pending: Vec<u64> = seeds.collect();
        while let Some(start) = pending.pop() {
            let Some((index, section)) = walk.code_at(start) else { continue };
            let mut state = A::State::default();
            for decoded in A::decode(&section.data[(start - section.addr) as usize..], start) {
                let at = (decoded.addr - section.addr) as usize;
                let Some(insn) = decoded.insn.filter(|_| walk.marks[index][at] & START == 0) else { break };
                walk.marks[index][at] |= START;
                walk.marks[index][at + 1..at + usize::from(decoded.len)].iter_mut().for_each(|mark| *mark |= INSIDE);
                let flow = A::flow(&insn, &state, image);
                A::step(&mut state, &insn);
                if let Some(Flow::Call(target) | Flow::Branch(target) | Flow::Jump(target)) = flow {
                    if !section.contains(target) {
                        walk.crossing.insert(target);
                    } else if matches!(flow, Some(Flow::Call(_))) {
                        walk.local_calls.insert(target);
                    }
                    pending.push(target);
                }
                if ends(flow) {
                    break;
                }
            }
        }
        walk
    }

    /// The executable section `addr` is in, and its index.
    fn code_at(&self, addr: u64) -> Option<(usize, &'a Section)> {
        let index = self.image.sections.partition_point(|section| section.addr <= addr).checked_sub(1)?;
        let section = &self.image.sections[index];
        (section.executable && section.contains(addr)).then_some((index, section))
    }

    /// Puts the questions to `targets`, and to the sections they lie in for the chance.
    fn judge<A: Arch>(mut self, targets: &BTreeSet<u64>) -> Score {
        let places: Vec<(u64, Option<(usize, &Section)>)> = targets.iter().map(|&target| (target, self.code_at(target))).collect();
        let sections: FxHashMap<usize, &Section> = places.iter().filter_map(|&(_, place)| place).collect();
        // The first byte of a section follows whatever ends the one before it.
        for (&index, section) in &sections {
            self.marks[index][0] |= AFTER_END;
            for offset in 0..section.data.len() {
                let Some(decoded) = A::decode(&section.data[offset..], section.addr + offset as u64).next() else { continue };
                let after = offset + usize::from(decoded.len);
                if decoded.insn.is_some_and(|insn| ends(A::flow(&insn, &A::State::default(), self.image))) && after < section.data.len() {
                    self.marks[index][after] |= AFTER_END;
                }
            }
        }
        let bytes: usize = sections.values().map(|section| section.data.len()).sum();
        let marked = |flag: u8| sections.keys().flat_map(|&index| &self.marks[index]).filter(|&&mark| mark & flag != 0).count();
        let holds = |flag: u8| places.iter().filter(|(target, place)| place.is_some_and(|(index, section)| self.marks[index][(target - section.addr) as usize] & flag != 0)).count();
        let total = places.len();
        let share = |count: usize, of: usize| if of == 0 { 0.0 } else { count as f64 / of as f64 };

        let local: Vec<(usize, usize)> = self.local_calls.iter().filter_map(|&target| self.code_at(target).filter(|(index, _)| sections.contains_key(index)).map(|(index, section)| (index, (target - section.addr) as usize))).collect();
        let local_calls = local.len();
        let (starts, inside) = (marked(START), marked(INSIDE));
        Score {
            follows_end: Component { good: holds(AFTER_END), total, chance: share(marked(AFTER_END), bytes) },
            called_locally: Component { good: places.iter().filter(|(target, _)| self.local_calls.contains(target)).count(), total, chance: share(local_calls, bytes) },
            // A target outside the code is on no instruction. Chance is over the bytes flow reached.
            on_instruction: Component { good: places.iter().filter(|(_, place)| place.is_some()).count() - holds(INSIDE), total, chance: share(starts, starts + inside) },
            local_follows_end: Component { good: local.iter().filter(|&&(index, at)| self.marks[index][at] & AFTER_END != 0).count(), total: local_calls, chance: share(marked(AFTER_END), bytes) },
        }
    }
}

/// Whether execution does not go on to the instruction after one with this effect.
fn ends(flow: Option<Flow>) -> bool {
    matches!(flow, Some(Flow::Jump(_) | Flow::JumpIndirect(_) | Flow::Return | Flow::Halt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;

    /// An 8051 image entered at 0 with `caller` there and `callee` in a section of its own.
    fn image(caller: &[u8], callee_at: u64, callee: &[u8]) -> Image {
        let layout: Layout = toml::from_str("machine = \"8051\"\nentry = [0]\nregion = []").unwrap();
        let section = |addr, data: &[u8]| Section { name: String::new(), addr, data: data.to_vec(), file_offset: None, executable: true, writable: false };
        layout.image(String::new(), vec![section(0, caller), section(callee_at, callee)], None).unwrap()
    }

    #[test]
    fn evidence_is_the_distance_from_chance_in_bits() {
        let component = |good| Component { good, total: 10, chance: 0.5 };
        assert_eq!(component(10).bits(), 10.0);
        assert_eq!(component(5).bits(), 0.0);
        assert_eq!(component(0).bits(), -10.0);
        assert_eq!(Component { good: 0, total: 0, chance: 0.5 }.blind().as_deref(), Some("no target crosses the layout"));
    }

    #[test]
    fn a_call_into_a_region_loaded_where_it_belongs_lands_on_a_function() {
        // LCALL 0x8003; RET.
        let caller = [0x12, 0x80, 0x03, 0x22];
        // NOP; NOP; RET, then at 0x8003 the function called: CLR A; LCALL 0x8000; RET.
        let callee = [0x00, 0x00, 0x22, 0xE4, 0x12, 0x80, 0x00, 0x22];
        let right = score(&image(&caller, 0x8000, &callee));
        assert_eq!((right.follows_end.good, right.on_instruction.good, right.follows_end.total), (1, 1, 1));
        // The function's own call names 0x8000 outright, which is a function only loaded there.
        assert_eq!((right.local_follows_end.good, right.local_follows_end.total), (1, 1));
        assert_eq!(right.crossing().local_follows_end.total, 0);

        // Two bytes too low, the call lands on the operand of the function's own call.
        let wrong = score(&image(&caller, 0x7FFE, &callee));
        assert_eq!((wrong.follows_end.good, wrong.follows_end.total), (0, 1));
        assert!(right.bits() > wrong.bits());
    }

    #[test]
    fn a_layout_nothing_crosses_says_so() {
        // RET, and in the other section RET.
        let found = score(&image(&[0x22], 0x8000, &[0x22]));
        assert_eq!(found.to_string(), "0 bits: no target crosses the layout, and no call stays in a region\n");
    }

    #[test]
    fn a_target_inside_an_instruction_that_runs_is_not_on_one() {
        // LCALL 0x8000; LCALL 0x8001; RET, into MOV A, #0; RET.
        let found = score(&image(&[0x12, 0x80, 0x00, 0x12, 0x80, 0x01, 0x22], 0x8000, &[0x74, 0x00, 0x22]));
        assert_eq!((found.on_instruction.good, found.on_instruction.total), (1, 2));
    }

    #[test]
    fn a_target_called_from_its_own_region_too_is_found_twice() {
        // LCALL 0x8001; RET, and in the other section RET; RET; LCALL 0x8001; RET.
        let found = score(&image(&[0x12, 0x80, 0x01, 0x22], 0x8000, &[0x22, 0x22, 0x12, 0x80, 0x01, 0x22]));
        assert_eq!(found.called_locally.good, 0);
        // The same with a jump to the code that makes the second call.
        let found = score(&image(&[0x12, 0x80, 0x01, 0x02, 0x80, 0x02], 0x8000, &[0x22, 0x22, 0x12, 0x80, 0x01, 0x22]));
        assert_eq!((found.called_locally.good, found.called_locally.total), (1, 2));
    }
}
