//! What each function of an 8051 program does with the registers.
//!
//! A calling convention says a call may change every register and takes its arguments in a
//! few of them. Much 8051 code is not held to one: a compiler's library routines and the
//! pieces of code a linker shares between functions are called with values in whatever
//! registers the code around the call had them in, leave the others alone, and hand back
//! values in several. And a function passes a register it was given on to a function it calls
//! without reading it. So what a function takes, changes and gives back is worked out here
//! from the instructions, for the whole program at once.

use rustc_hash::FxHashMap;

use super::{I8051, Insn, Transfer};
use crate::arch::{Arch, Flow};
use crate::image::Image;
use crate::report::{Analysis, CallTarget};

/// A set of the registers code passes values in: `R0` to `R7` of the first register bank,
/// `ACC`, `B`, the two halves of `DPTR` and the carry flag.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Registers(u16);

const NAMES: [&str; 13] = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "ACC", "B", "DPL", "DPH", "CY"];
const BANK: u16 = 0xFF;
const ACC: u16 = 1 << 8;
const B: u16 = 1 << 9;
const DPTR: u16 = 3 << 10;
const CY: u16 = 1 << 12;
const ALL: u16 = (1 << NAMES.len()) - 1;

impl Registers {
    pub const ALL: Registers = Registers(ALL);

    /// The registers of the set by name, `DPTR` for its two halves together.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        let halves = self.0 & DPTR == DPTR;
        let single = NAMES.iter().enumerate().filter(move |&(bit, _)| self.0 >> bit & 1 != 0 && !(halves && 1 << bit & DPTR != 0)).map(|(_, &name)| name);
        single.chain(halves.then_some("DPTR"))
    }

    pub fn has(self, name: &str) -> bool {
        self.names().any(|register| register == name)
    }

    /// The registers that are not of the set.
    pub fn others(self) -> Registers {
        Registers(!self.0 & ALL)
    }
}

/// The register at a direct address, if it is one of these.
fn direct(address: u8) -> u16 {
    match address {
        0x00..=0x07 => 1 << address,
        0xE0 => ACC,
        0xF0 => B,
        0x82 => 1 << 10,
        0x83 => 1 << 11,
        // The status word holds the carry flag and says which register bank is in use.
        0xD0 => CY | BANK,
        _ => 0,
    }
}

/// The register a bit address is a bit of.
fn bit(address: u8) -> u16 {
    match address {
        0xD7 => CY,
        // The two bits that pick the register bank.
        0xD3 | 0xD4 => BANK,
        0xE0..=0xE7 => ACC,
        0xF0..=0xF7 => B,
        _ => 0,
    }
}

/// What one instruction writes. A store through `R0` or `R1` is taken to go to memory that is
/// no register.
fn written(insn: Insn) -> u16 {
    let [opcode, first, second] = insn.bytes;
    let register = 1 << (opcode & 7);
    let (row, column) = (opcode >> 4, opcode & 0x0F);
    match opcode {
        // RR, RL, SWAP, CPL, CLR and MOV A; INC and DEC A; MOVC and MOVX to A.
        0x03 | 0x23 | 0xC4 | 0xF4 | 0xE4 | 0x74 | 0x04 | 0x14 | 0x83 | 0x93 | 0xE0 | 0xE2 | 0xE3 => ACC,
        // RRC, RLC and DA.
        0x13 | 0x33 | 0xD4 => ACC | CY,
        // MUL and DIV.
        0x84 | 0xA4 => ACC | B | CY,
        // MOV DPTR and INC DPTR.
        0x90 | 0xA3 => DPTR,
        // ORL, ANL and MOV into carry, CPL, CLR and SETB carry.
        0x72 | 0x82 | 0xA0 | 0xB0 | 0xA2 | 0xB3 | 0xC3 | 0xD3 => CY,
        // JBC, MOV bit, CPL bit, CLR bit and SETB bit.
        0x10 | 0x92 | 0xB2 | 0xC2 | 0xD2 => bit(first),
        // ORL, ANL and XRL of a direct address, with A or a constant; POP.
        0x42 | 0x43 | 0x52 | 0x53 | 0x62 | 0x63 | 0xD0 => direct(first),
        // INC, DEC, MOV to a direct address from a constant, A, `@Ri` or `Rn`; DJNZ on one.
        0x05 | 0x15 | 0x75 | 0xF5 | 0x86..=0x8F | 0xD5 => direct(first),
        // MOV direct, direct names where it goes last.
        0x85 => direct(second),
        0xC5 => ACC | direct(first),
        // CJNE sets the carry flag.
        0xB4..=0xBF => CY,
        // XCH and XCHD of A with `@Ri`, XCH with `Rn`, DJNZ on `Rn`.
        0xC6 | 0xC7 | 0xD6 | 0xD7 => ACC,
        0xC8..=0xCF => ACC | register,
        0xD8..=0xDF => register,
        // ADD, ADDC and SUBB of A; ORL, ANL, XRL and MOV into A.
        _ if matches!(row, 0x2 | 0x3 | 0x9) && column >= 4 => ACC | CY,
        _ if matches!(row, 0x4 | 0x5 | 0x6 | 0xE) && column >= 4 => ACC,
        // INC, DEC and MOV into `Rn`, from a constant, a direct address or A.
        _ if matches!(row, 0x0 | 0x1 | 0x7 | 0xA | 0xF) && column >= 8 => register,
        _ => 0,
    }
}

/// What one instruction reads. `PUSH` reads nothing: it puts a register by to bring it back.
fn read(insn: Insn) -> u16 {
    let [opcode, first, _] = insn.bytes;
    let (row, column) = (opcode >> 4, opcode & 0x0F);
    // The operand the low half of the opcode names: a direct address, `@Ri` or `Rn`.
    let operand = match column {
        0x5 => direct(first),
        0x6 | 0x7 => 1 << (opcode & 1),
        0x8..=0xF => 1 << (opcode & 7),
        _ => 0,
    };
    match opcode {
        // RR, RL, SWAP, CPL, INC and DEC of A; JZ and JNZ; MOVC from after the instruction.
        0x03 | 0x23 | 0xC4 | 0xF4 | 0x04 | 0x14 | 0x60 | 0x70 | 0x83 => ACC,
        // RRC, RLC and DA.
        0x13 | 0x33 | 0xD4 => ACC | CY,
        0x84 | 0xA4 => ACC | B,
        // JMP and MOVC through A and DPTR, MOVX to DPTR.
        0x73 | 0x93 | 0xF0 => ACC | DPTR,
        // INC DPTR, MOVX from DPTR.
        0xA3 | 0xE0 => DPTR,
        // JC, JNC, CPL C and MOV bit, C.
        0x40 | 0x50 | 0xB3 | 0x92 => CY,
        // ORL and ANL into carry.
        0x72 | 0x82 | 0xA0 | 0xB0 => CY | bit(first),
        // JBC, JB, JNB, MOV C, bit and CPL bit.
        0x10 | 0x20 | 0x30 | 0xA2 | 0xB2 => bit(first),
        // ORL, ANL and XRL of a direct address: with A, or with a constant.
        0x42 | 0x52 | 0x62 => ACC | direct(first),
        0x43 | 0x53 | 0x63 => direct(first),
        // MOV direct, direct names what it reads first; DJNZ on a direct address.
        0x85 | 0xD5 => direct(first),
        // MOV to a direct address from `@Ri` or `Rn`.
        0x86..=0x8F => operand,
        // MOV `@Ri`, direct reads both; MOV `Rn`, direct the address.
        0xA6 | 0xA7 => operand | direct(first),
        0xA8..=0xAF => direct(first),
        // CJNE of A with a constant or a direct address, and of `@Ri` or `Rn`.
        0xB4 => ACC,
        0xB5 => ACC | direct(first),
        0xB6..=0xBF => operand,
        // XCH and XCHD of A, DJNZ on `Rn`.
        0xC5..=0xCF | 0xD6 | 0xD7 => ACC | operand,
        0xD8..=0xDF => operand,
        // MOVX between A and `@Ri`.
        0xE2 | 0xE3 => 1 << (opcode & 1),
        0xF2 | 0xF3 => ACC | 1 << (opcode & 1),
        // MOV from A to a direct address, `@Ri` or `Rn`.
        0xF5 | 0xF8..=0xFF => ACC,
        0xF6 | 0xF7 => ACC | operand,
        // INC and DEC of an operand; MOV `@Ri`, constant.
        _ if matches!(row, 0x0 | 0x1) && column >= 5 => operand,
        0x76 | 0x77 => operand,
        // ADD, ORL, ANL and XRL of A with a constant or an operand; ADDC and SUBB with carry.
        _ if matches!(row, 0x2 | 0x4 | 0x5 | 0x6) && column >= 4 => ACC | operand,
        _ if matches!(row, 0x3 | 0x9) && column >= 4 => ACC | CY | operand,
        // MOV A from an operand.
        _ if row == 0xE && column >= 5 => operand,
        _ => 0,
    }
}

/// What a function does with the registers.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Use {
    /// Registers it reads, itself or in what it calls, before anything writes them: what it
    /// is passed.
    pub taken: Registers,
    /// Registers it may change, itself or in what it calls.
    pub changed: Registers,
    /// Registers it changes that some code calling it reads afterwards: what it hands back.
    /// `None` for a function no call of which is known.
    pub given: Option<Registers>,
    /// Registers it has set by the time it returns, whichever way it ran: written by an
    /// instruction of its own, or set by a function it called, and not handed to a call
    /// since. A value a function returns is in one of these.
    pub set: Registers,
}

/// A function another one calls: by its address, or one the analysis does not know.
type Callee = Option<u64>;

/// One instruction of a function.
#[derive(Default)]
struct Step {
    reads: u16,
    writes: u16,
    /// The instructions of the function that may run next, by index.
    next: Vec<u32>,
    /// A call, after which the next instruction runs, with the registers the code on the way
    /// to the callee writes: those reach the callee with nothing of the caller's in them.
    call: Option<(Callee, u16)>,
    leaves: Leaves,
}

/// How an instruction leaves its function, if it does.
#[derive(Default, Clone, Copy)]
enum Leaves {
    #[default]
    No,
    Return,
    /// A jump to another function, which returns to this one's caller.
    Jump(Callee),
    /// To where the analysis does not follow.
    Unknown,
}

/// What the code a trampoline entry runs writes before the function is reached, as far as it
/// can be read: the entry, and the stub it jumps to.
fn stub_writes(image: &Image, entry: u64) -> u16 {
    let mut writes = 0;
    let mut at = entry;
    for _ in 0..2 {
        let Some(bytes) = image.bytes_from(at) else { break };
        let mut jump = None;
        for insn in super::decode(&bytes[..bytes.len().min(32)], at).filter_map(|decoded| decoded.insn) {
            writes |= written(insn);
            if let Some((Transfer::Jump, target)) = insn.transfer() {
                jump = Some(image.banking.reach(insn.addr, target));
                break;
            }
            if matches!(insn.opcode(), 0x22 | 0x73) {
                break;
            }
        }
        let Some(target) = jump else { break };
        at = target;
    }
    writes
}

/// The instructions of each function, the one it starts at first, by the function's address.
fn steps(image: &Image, analysis: &Analysis) -> FxHashMap<u64, Vec<Step>> {
    let state = super::State::default();
    let call = |at: u64| analysis.calls.binary_search_by_key(&at, |call| call.at).ok().map(|index| &analysis.calls[index]);
    let table = |jump: u64| analysis.jump_tables.iter().find(|table| table.jump == jump).map(|table| &table.targets);
    // A piece of a function that lies apart from it is the function's.
    let owner_of: FxHashMap<u64, u64> = analysis.functions.iter().map(|function| (function.addr, function.fragment_of.unwrap_or(function.addr))).collect();
    let callee = |target: u64| owner_of.get(&target).copied();
    let mut bodies: FxHashMap<u64, Vec<(u64, u64)>> = FxHashMap::default();
    for function in &analysis.functions {
        bodies.entry(owner_of[&function.addr]).or_default().extend(&function.ranges);
    }
    let mut all = FxHashMap::default();
    for (&owner, body) in &bodies {
        let mut insns: Vec<(Insn, u64)> = Vec::new();
        let mut body = body.clone();
        body.sort_unstable_by_key(|&(start, end)| (!(start..end).contains(&owner), start));
        for &(start, end) in &body {
            let Some(bytes) = image.bytes_from(start) else { continue };
            insns.extend(super::decode(&bytes[..bytes.len().min((end - start) as usize)], start).filter_map(|decoded| Some((decoded.insn?, decoded.next_addr()))));
        }
        let index: FxHashMap<u64, u32> = insns.iter().enumerate().map(|(index, (insn, _))| (insn.addr, index as u32)).collect();
        let mut function = Vec::with_capacity(insns.len());
        for &(insn, after) in &insns {
            let mut step = Step { reads: read(insn), writes: written(insn), ..Step::default() };
            // Code that runs off the end of the function runs on into the next.
            let go_on = |step: &mut Step| match index.get(&after) {
                Some(&next) => step.next.push(next),
                None => step.leaves = Leaves::Jump(callee(after)),
            };
            let known = call(insn.addr);
            let target = known.and_then(|call| if let CallTarget::Function(target) = call.target { Some(target) } else { None });
            // Code on the way to another bank writes registers of its own.
            let through = match insn.transfer() {
                _ if image.banking.calls.contains_key(&insn.addr) => ALL,
                Some((Transfer::Call | Transfer::Jump, raw)) if image.banking.trampolines.contains_key(&image.banking.reach(insn.addr, raw)) => stub_writes(image, image.banking.reach(insn.addr, raw)),
                _ => 0,
            };
            match I8051::flow(&insn, &state, image) {
                Some(Flow::Return) => step.leaves = Leaves::Return,
                Some(Flow::Halt) => step.leaves = Leaves::Unknown,
                Some(Flow::Call(_) | Flow::CallIndirect(_)) if known.is_some_and(|call| call.noreturn) => step.leaves = Leaves::Unknown,
                Some(Flow::Call(direct)) => {
                    step.call = Some((target.or(Some(direct)).and_then(callee), through));
                    go_on(&mut step);
                }
                Some(Flow::CallIndirect(_)) => {
                    step.call = Some((target.and_then(callee), ALL));
                    go_on(&mut step);
                }
                Some(Flow::Jump(inside)) if !known.is_some_and(|call| call.tail) && index.contains_key(&inside) => step.next.push(index[&inside]),
                Some(Flow::Jump(outside)) => {
                    step.writes |= through;
                    step.leaves = Leaves::Jump(target.or(Some(outside)).and_then(callee));
                }
                Some(Flow::Branch(to)) => {
                    match index.get(&to).filter(|_| !known.is_some_and(|call| call.tail)) {
                        Some(&inside) => step.next.push(inside),
                        None => step.leaves = Leaves::Jump(target.or(Some(to)).and_then(callee)),
                    }
                    if let Some(&next) = index.get(&after) {
                        step.next.push(next);
                    }
                }
                Some(Flow::JumpIndirect(_)) => match table(insn.addr) {
                    Some(targets) => {
                        // A call to a routine that reads the table after it and jumps on.
                        if let Some((Transfer::Call, routine)) = insn.transfer() {
                            step.call = Some((callee(image.banking.reach(insn.addr, routine)), 0));
                        }
                        step.next.extend(targets.iter().filter_map(|target| index.get(target)));
                    }
                    None => step.leaves = Leaves::Unknown,
                },
                None => go_on(&mut step),
            }
            function.push(step);
        }
        all.insert(owner, function);
    }
    all
}

/// The registers live before each instruction of a function: read on some path from there
/// before anything writes them. `after` says what is live where the function is left.
fn live(steps: &[Step], uses: &FxHashMap<u64, Use>, after: &dyn Fn(Leaves) -> u16) -> Vec<u16> {
    let mut before = vec![0u16; steps.len()];
    loop {
        let mut grew = false;
        for (index, step) in steps.iter().enumerate().rev() {
            let mut live = live_after(step, &before, after);
            if let Some((callee, through)) = step.call {
                // A callee nothing is known of is taken to keep to the convention, which
                // lets it change everything.
                let callee = callee.and_then(|callee| uses.get(&callee)).copied().unwrap_or(Use { changed: Registers::ALL, ..Use::default() });
                live = live & !(callee.changed.0 | through) | callee.taken.0 & !through;
            }
            live = live & !step.writes | step.reads;
            grew |= live != before[index];
            before[index] = live;
        }
        if !grew {
            return before;
        }
    }
}

/// What is live after an instruction has run, which for a call is after the callee returned.
fn live_after(step: &Step, before: &[u16], after: &dyn Fn(Leaves) -> u16) -> u16 {
    step.next.iter().fold(after(step.leaves), |live, &next| live | before[next as usize])
}

/// One round of working out a part of [`Use`]: what `steps`, the function at the address,
/// adds to it for which functions.
type Round<'a> = &'a dyn Fn(&FxHashMap<u64, Use>, u64, &[Step]) -> Vec<(u64, Use)>;

/// What every function of the program does with the registers, by the function's address.
pub fn uses(image: &Image, analysis: &Analysis) -> FxHashMap<u64, Use> {
    let steps = steps(image, analysis);
    let mut uses: FxHashMap<u64, Use> = steps.keys().map(|&function| (function, Use::default())).collect();
    // A function reached through a trampoline is called by way of code that writes registers
    // of its own, which a call to it therefore changes.
    for (&entry, target) in &image.banking.trampolines {
        if let Some(target) = uses.get_mut(target) {
            target.changed.0 |= stub_writes(image, entry);
        }
    }
    for target in image.banking.calls.values() {
        if let Some(target) = uses.get_mut(target) {
            target.changed = Registers::ALL;
        }
    }
    let known = |uses: &FxHashMap<u64, Use>, callee: Callee| callee.and_then(|callee| uses.get(&callee)).copied();
    // Each part only grows, so its round is repeated until nothing does.
    let settle = |uses: &mut FxHashMap<u64, Use>, round: Round| loop {
        let mut grew = false;
        for (&function, steps) in &steps {
            for (function, more) in round(uses, function, steps) {
                let now = uses.get_mut(&function).expect("a function of the analysis");
                let given = match (now.given, more.given) {
                    (Some(now), Some(more)) => Some(Registers(now.0 | more.0)),
                    (now, more) => now.or(more),
                };
                let all = Use { taken: Registers(now.taken.0 | more.taken.0), changed: Registers(now.changed.0 | more.changed.0), given, set: Registers(now.set.0 | more.set.0) };
                grew |= all != *now;
                *now = all;
            }
        }
        if !grew {
            break;
        }
    };
    // What a function changes: what it writes, and what the functions it calls or jumps to
    // change.
    settle(&mut uses, &|uses, function, steps| {
        let changed = steps.iter().fold(0, |changed, step| {
            let call = step.call.map_or(0, |(callee, through)| through | known(uses, callee).map_or(ALL, |callee| callee.changed.0));
            let leaves = match step.leaves {
                Leaves::Jump(callee) => known(uses, callee).map_or(ALL, |callee| callee.changed.0),
                Leaves::Unknown => ALL,
                Leaves::No | Leaves::Return => 0,
            };
            changed | step.writes | call | leaves
        });
        vec![(function, Use { changed: Registers(changed), ..Use::default() })]
    });
    // What it takes: what is live where it starts, with nothing live where it returns.
    settle(&mut uses, &|uses, function, steps| {
        let taken = live(steps, uses, &|leaves| match leaves {
            Leaves::Jump(callee) => known(uses, callee).map_or(0, |callee| callee.taken.0),
            _ => 0,
        });
        vec![(function, Use { taken: Registers(taken.first().copied().unwrap_or(0)), ..Use::default() })]
    });
    // What it gives back: what it changes that is live after a call to it, where what a
    // function gives back is live when it returns. A function jumped to gives back what the
    // one that jumps does.
    settle(&mut uses, &|uses, function, steps| {
        let given = uses[&function].given.map_or(0, |given| given.0);
        let after = |leaves: Leaves| match leaves {
            Leaves::Return => given,
            Leaves::Jump(callee) => known(uses, callee).map_or(0, |callee| callee.taken.0),
            _ => 0,
        };
        let before = live(steps, uses, &after);
        let mut more = Vec::new();
        for step in steps {
            if let Some((Some(callee), _)) = step.call
                && let Some(callee_use) = uses.get(&callee)
            {
                more.push((callee, Use { given: Some(Registers(live_after(step, &before, &after) & callee_use.changed.0)), ..Use::default() }));
            }
            if let Leaves::Jump(Some(callee)) = step.leaves
                && let Some(callee_use) = uses.get(&callee)
            {
                more.push((callee, Use { given: Some(Registers(given & callee_use.changed.0)), ..Use::default() }));
            }
        }
        more
    });
    // What it has set when it returns. A call unsets what the callee changes or takes, and
    // sets what the callee has set.
    settle(&mut uses, &|uses, function, steps| {
        let after_call = |set: u16, callee: Callee| match known(uses, callee) {
            Some(callee) => set & !(callee.changed.0 | callee.taken.0) | callee.set.0,
            None => 0,
        };
        // Before each instruction, on every way to it: everything, until a way there is seen.
        let mut before = vec![ALL; steps.len()];
        if let Some(entry) = before.first_mut() {
            *entry = 0;
        }
        let returned = loop {
            let (mut shrank, mut at_return) = (false, ALL);
            for index in 0..steps.len() {
                let step = &steps[index];
                let mut set = before[index] | step.writes;
                if let Some((callee, through)) = step.call {
                    set = after_call(set, callee) & !through;
                }
                match step.leaves {
                    Leaves::Return => at_return &= set,
                    Leaves::Jump(callee) => at_return &= after_call(set, callee),
                    Leaves::No | Leaves::Unknown => {}
                }
                for &next in &step.next {
                    shrank |= before[next as usize] & set != before[next as usize];
                    before[next as usize] &= set;
                }
            }
            if !shrank {
                break at_return;
            }
        };
        // A function that never returns has set nothing for a caller.
        let returns = steps.iter().any(|step| matches!(step.leaves, Leaves::Return | Leaves::Jump(_)));
        vec![(function, Use { set: Registers(if returns && !steps.is_empty() { returned } else { 0 }), ..Use::default() })]
    });
    uses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(registers: u16) -> Vec<&'static str> {
        Registers(registers).names().collect()
    }

    #[test]
    fn an_instruction_writes_and_reads_the_registers_its_operands_name() {
        let insn = |bytes: [u8; 3]| Insn { addr: 0, bytes };
        let both = |bytes: [u8; 3]| (names(written(insn(bytes))), names(read(insn(bytes))));
        let none: Vec<&str> = Vec::new();
        assert_eq!(both([0x7F, 0x02, 0]), (vec!["R7"], none.clone())); // MOV R7,#2
        assert_eq!(both([0xEF, 0, 0]), (vec!["ACC"], vec!["R7"])); // MOV A,R7
        assert_eq!(both([0x3F, 0, 0]), (vec!["ACC", "CY"], vec!["R7", "ACC", "CY"])); // ADDC A,R7
        assert_eq!(both([0xF0, 0, 0]), (none.clone(), vec!["ACC", "DPTR"])); // MOVX @DPTR,A
        assert_eq!(both([0x85, 0x07, 0x82]), (vec!["DPL"], vec!["R7"])); // MOV DPL,R7
        assert_eq!(both([0xA4, 0, 0]), (vec!["ACC", "B", "CY"], vec!["ACC", "B"])); // MUL AB
        assert_eq!(both([0xCA, 0, 0]), (vec!["R2", "ACC"], vec!["R2", "ACC"])); // XCH A,R2
        assert_eq!(both([0xB4, 0x10, 0x00]), (vec!["CY"], vec!["ACC"])); // CJNE A,#0x10
        assert_eq!(both([0xC0, 0xE0, 0]), (none.clone(), none.clone())); // PUSH ACC
        assert_eq!(both([0xF6, 0, 0]), (none, vec!["R0", "ACC"])); // MOV @R0,A
        assert_eq!(names(written(insn([0xD2, 0xD3, 0]))), ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"]); // SETB RS0
    }

    #[test]
    fn a_function_takes_what_it_hands_on_and_gives_back_what_its_caller_reads() {
        #[rustfmt::skip]
        let code = [
            0x7F, 0x05,             // 00  MOV R7,#5
            0x12, 0x00, 0x10,       // 02  LCALL 0x10
            0xEF, 0xF0,             // 05  MOV A,R7; MOVX @DPTR,A
            0x22,                   // 07  RET
            0, 0, 0, 0, 0, 0, 0, 0,
            0x12, 0x00, 0x20,       // 10  LCALL 0x20
            0x0F,                   // 13  INC R7
            0x22,                   // 14  RET
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xED, 0xF0, 0x22,       // 20  MOV A,R5; MOVX @DPTR,A; RET
        ];
        let image = super::super::tests::image(&code, 0);
        let uses = uses(&image, &crate::analyze(&image));
        let of = |function: u64| {
            let Use { taken, changed, given, .. } = uses[&function];
            (taken.names().collect::<Vec<_>>(), changed.names().collect::<Vec<_>>(), given.map(|given| given.names().collect::<Vec<_>>()))
        };
        // The innermost reads R5 and DPTR and changes only A.
        assert_eq!(of(0x20), (vec!["R5", "DPTR"], vec!["ACC"], Some(vec![])));
        // The middle one hands both on, reads R7 itself and gives it back changed.
        assert_eq!(of(0x10), (vec!["R5", "R7", "DPTR"], vec!["R7", "ACC"], Some(vec!["R7"])));
        // The outer one sets R7 itself, and nothing calls it.
        assert_eq!(of(0), (vec!["R5", "DPTR"], vec!["R7", "ACC"], None));
        // The innermost has set A when it returns, and the others R7 as well: the middle one
        // itself, the outer one by calling it.
        let set = |function: u64| uses[&function].set.names().collect::<Vec<_>>();
        assert_eq!((set(0x20), set(0x10), set(0)), (vec!["ACC"], vec!["R7", "ACC"], vec!["R7", "ACC"]));
    }

    #[test]
    fn a_function_of_no_instructions_sets_nothing() {
        // Two LJMP 0x0010; at 0x0010: MOV A, #0x22; RET. The entry at 0x0011, inside the MOV,
        // leaves the function the jumps share no room for an instruction.
        let mut code = [0; 0x13];
        code[..6].copy_from_slice(&[0x02, 0x00, 0x10, 0x02, 0x00, 0x10]);
        code[0x10..].copy_from_slice(&[0x74, 0x22, 0x22]);
        let mut image = super::super::tests::image(&code, 0);
        image.exports = vec![0x0003, 0x0011];
        let uses = uses(&image, &crate::analyze(&image));
        assert_eq!(uses[&0x0010].set.names().count(), 0);
    }
}
