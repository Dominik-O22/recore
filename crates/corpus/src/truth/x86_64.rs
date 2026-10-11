//! x86-64 function scan, decoded with iced-x86.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};

use super::{Callee, Scan};

/// Decodes one function body linearly.
pub fn scan(bytes: &[u8], addr: u64) -> Scan {
    let mut scan = Scan::default();
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
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
            _ => {}
        }
    }
    if let Some((addr, true)) = last_real {
        scan.final_call = Some(addr);
    }
    scan
}
