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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_name_their_target_or_import_slot_and_the_last_one_ends_the_function_through_padding() {
        #[rustfmt::skip]
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00,       // 1000  call 0x2000
            0xff, 0x15, 0xf5, 0x1f, 0x00, 0x00, // 1005  call [rip + 0x1ff5], the slot at 0x3000
            0xff, 0xd0,                         // 100b  call rax
            0xe8, 0xee, 0x0f, 0x00, 0x00,       // 100d  call 0x2000
            0x90, 0xcc,                         // 1012  nop; int3
        ];
        let scan = scan(&code, 0x1000, 64);
        assert_eq!(scan.calls, [(0x1000, Callee::Direct(0x2000)), (0x1005, Callee::Slot(0x3000)), (0x100d, Callee::Direct(0x2000))]);
        assert_eq!((scan.instructions, scan.final_call), (6, Some(0x100d)));
    }

    #[test]
    fn an_absolute_slot_is_an_import_call_only_in_32_bit_code_and_only_without_registers() {
        let code = [0xff, 0x14, 0x25, 0x00, 0x30, 0x00, 0x00]; // call [0x3000]
        assert_eq!(scan(&code, 0x1000, 64).calls, []);
        #[rustfmt::skip]
        let code = [
            0xff, 0x15, 0x00, 0x30, 0x00, 0x00,       // 1000  call dword ptr [0x3000]
            0xff, 0x90, 0x00, 0x30, 0x00, 0x00,       // 1006  call dword ptr [eax + 0x3000]
            0xff, 0x14, 0x85, 0x00, 0x30, 0x00, 0x00, // 100c  call dword ptr [eax*4 + 0x3000]
        ];
        assert_eq!(scan(&code, 0x1000, 32).calls, [(0x1000, Callee::Slot(0x3000))]);
    }
}
