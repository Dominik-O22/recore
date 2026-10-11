//! x86 function scan, decoded with iced-x86.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::{Callee, Scan};

/// Whether operand 0 is memory at a fixed address, with no base or index register.
pub fn is_absolute_memory(instr: &Instruction) -> bool {
    instr.op0_kind() == OpKind::Memory && instr.memory_base() == Register::None && instr.memory_index() == Register::None
}

/// Decodes one function body linearly as 32- or 64-bit code.
pub fn scan(bytes: &[u8], addr: u64, bitness: u32) -> Scan {
    let mut scan = Scan::default();
    let mut decoder = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
    let mut last_real: Option<(u64, bool)> = None;
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            scan.undecodable_bytes += instr.len().max(1) as u64;
            continue;
        }
        scan.instructions += 1;
        if !matches!(instr.mnemonic(), Mnemonic::Nop | Mnemonic::Int3) {
            let is_call = matches!(instr.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
            last_real = Some((instr.ip(), is_call));
        }
        match instr.flow_control() {
            FlowControl::Call => scan.calls.push((instr.ip(), Callee::Direct(instr.near_branch_target()))),
            FlowControl::IndirectCall if instr.is_ip_rel_memory_operand() => {
                scan.calls.push((instr.ip(), Callee::Slot(instr.ip_rel_memory_address())));
            }
            // 32-bit code names the import slot by absolute address: `call dword ptr [slot]`.
            FlowControl::IndirectCall if bitness == 32 && is_absolute_memory(&instr) => {
                scan.calls.push((instr.ip(), Callee::Slot(instr.memory_displacement64())));
            }
            _ => {}
        }
    }
    if let Some((addr, true)) = last_real {
        scan.final_call = Some(addr);
    }
    scan
}
