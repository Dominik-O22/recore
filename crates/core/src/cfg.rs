//! The control-flow graph of one function: its basic blocks and where each can go next.

use std::collections::BTreeSet;

use crate::arch::{Arch, Flow};
use crate::image::{Image, Machine};
use crate::report::{Analysis, CallTarget};
use crate::x86::X86;

/// A run of instructions entered only at its first and left only at its last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    /// Address just past the last instruction.
    pub end: u64,
    /// Starts of the blocks of this function that control can pass to, sorted.
    pub successors: Vec<u64>,
    /// How control leaves the function from here, if it does.
    pub exit: Option<Exit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Return,
    /// A jump to another function or to an import.
    TailCall,
    /// A call that never returns, or a trap.
    NoReturn,
    /// A jump through a pointer whose targets are not known.
    Unresolved,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cfg {
    /// Sorted by start.
    pub blocks: Vec<Block>,
    /// Calls through a register or a pointer whose target the analysis does not know.
    pub unresolved_calls: Vec<u64>,
    /// Start of every instruction, sorted.
    pub instructions: Vec<u64>,
}

/// The control-flow graph of the function whose body is `body`, as `[start, end)` ranges.
pub fn cfg(image: &Image, analysis: &Analysis, body: &[(u64, u64)]) -> Cfg {
    match image.machine {
        Machine::X86_64 => cfg_with::<X86<64, false>>(image, analysis, body),
        Machine::X86 => cfg_with::<X86<32, false>>(image, analysis, body),
        Machine::Aarch64 => cfg_with::<crate::arm64::Arm64>(image, analysis, body),
    }
}

fn cfg_with<A: Arch>(image: &Image, analysis: &Analysis, body: &[(u64, u64)]) -> Cfg {
    let inside = |addr: u64| body.iter().any(|&(start, end)| addr >= start && addr < end);
    let state = A::State::default();
    // Each instruction with what it does to control flow and where the next one starts.
    let mut instructions: Vec<(u64, u64, Option<Flow>)> = Vec::new();
    for &(start, end) in body {
        let Some(bytes) = image.bytes_from(start) else { continue };
        let bytes = &bytes[..bytes.len().min((end - start) as usize)];
        instructions.extend(A::decode(bytes, start).map(|decoded| (decoded.addr, decoded.next_addr(), decoded.insn.and_then(|insn| A::flow(&insn, &state)))));
    }
    let table = |jump: u64| analysis.jump_tables.iter().find(|table| table.jump == jump).map(|table| &table.targets);
    let call = |at: u64| analysis.calls.binary_search_by_key(&at, |call| call.at).ok().map(|index| &analysis.calls[index]);
    let noreturn = |at: u64| call(at).is_some_and(|call| call.noreturn) || analysis.noreturn_calls.contains(&at);

    // Where each instruction can pass control inside the function, and how it leaves otherwise.
    let leaves = |&(addr, next, flow): &(u64, u64, Option<Flow>)| -> (Vec<u64>, Option<Exit>, bool) {
        let tail = call(addr).is_some_and(|call| call.tail);
        match flow {
            Some(Flow::Jump(target)) if inside(target) && !tail => (vec![target], None, true),
            Some(Flow::Jump(_)) => (Vec::new(), Some(Exit::TailCall), true),
            Some(Flow::Branch(target)) if inside(target) && !tail => (vec![target, next], None, true),
            // A conditional tail call: taken, it leaves; otherwise execution carries on.
            Some(Flow::Branch(_)) => (vec![next], Some(Exit::TailCall), true),
            Some(Flow::JumpIndirect(_)) => match (table(addr), tail) {
                (Some(targets), _) => (targets.iter().copied().filter(|&target| inside(target)).collect(), None, true),
                (None, true) => (Vec::new(), Some(Exit::TailCall), true),
                (None, false) => (Vec::new(), Some(Exit::Unresolved), true),
            },
            Some(Flow::Return) => (Vec::new(), Some(Exit::Return), true),
            Some(Flow::Halt) => (Vec::new(), Some(Exit::NoReturn), true),
            Some(Flow::Call(_) | Flow::CallIndirect(_)) if noreturn(addr) => (Vec::new(), Some(Exit::NoReturn), true),
            Some(Flow::Call(_) | Flow::CallIndirect(_)) | None => (vec![next], None, false),
        }
    };

    let mut leaders: BTreeSet<u64> = body.iter().map(|&(start, _)| start).collect();
    for instruction in &instructions {
        let (targets, _, ends_block) = leaves(instruction);
        if ends_block {
            leaders.extend(targets);
            leaders.insert(instruction.1);
        }
    }

    let mut cfg = Cfg { instructions: instructions.iter().map(|instruction| instruction.0).collect(), ..Cfg::default() };
    let mut current: Option<Block> = None;
    for (index, instruction) in instructions.iter().enumerate() {
        let &(addr, next, flow) = instruction;
        if matches!(flow, Some(Flow::CallIndirect(_))) && !matches!(call(addr).map(|call| call.target), Some(CallTarget::Function(_) | CallTarget::Import(_))) {
            cfg.unresolved_calls.push(addr);
        }
        let block = current.get_or_insert(Block { start: addr, end: next, successors: Vec::new(), exit: None });
        block.end = next;
        let (mut targets, exit, ends_block) = leaves(instruction);
        // The next instruction starts a block of its own, or lies past a gap in the body.
        let last = ends_block || leaders.contains(&next) || instructions.get(index + 1).is_none_or(|following| following.0 != next);
        if last {
            targets.retain(|&target| inside(target));
            targets.sort_unstable();
            targets.dedup();
            block.successors = targets;
            block.exit = exit;
            cfg.blocks.extend(current.take());
        }
    }
    cfg.blocks.sort_by_key(|block| block.start);
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Format, Section};

    fn image(code: &[u8]) -> Image {
        Image {
            name: "test".into(),
            format: Format::Elf,
            machine: Machine::X86_64,
            base: 0,
            branch_targets_marked: false,
            entry: 0x1000,
            sections: vec![Section { name: ".text".into(), addr: 0x1000, data: code.to_vec(), file_offset: None, executable: true, writable: false }],
            import_slots: Default::default(),
            exports: Vec::new(),
            symbol_names: Default::default(),
            frames: Vec::new(),
            relative_targets: Vec::new(),
            data_in_code: false,
        }
    }

    #[test]
    fn splits_a_function_at_its_branch_and_join() {
        // 0x1000: test edi, edi; 0x1002: je 0x1009; 0x1004: mov eax, 1; 0x1009: ret
        let code = [0x85, 0xff, 0x74, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let analysis = Analysis { name: "test".into(), functions: Vec::new(), noreturn_calls: Vec::new(), instructions: 0, jump_tables: Vec::new(), calls: Vec::new(), imports: Vec::new(), data_refs: Vec::new(), strings: Vec::new(), classes: Vec::new() };
        let cfg = cfg(&image(&code), &analysis, &[(0x1000, 0x100a)]);
        let block = |start, end, successors: &[u64], exit| Block { start, end, successors: successors.to_vec(), exit };
        assert_eq!(cfg.blocks, [block(0x1000, 0x1004, &[0x1004, 0x1009], None), block(0x1004, 0x1009, &[0x1009], None), block(0x1009, 0x100a, &[], Some(Exit::Return))]);
        assert_eq!(cfg.instructions, [0x1000, 0x1002, 0x1004, 0x1009]);
    }
}
