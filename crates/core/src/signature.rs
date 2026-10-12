//! Position-independent fingerprints of function bodies, for recognising library code.
//!
//! A statically linked C runtime puts the same compiled functions into many binaries. The bytes
//! differ only where they hold addresses, so hashing the instructions with those fields blanked
//! gives a fingerprint that matches across binaries built with the same compiler and library.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

use crate::image::{Image, Machine};

/// Functions shorter than this are too alike to tell apart: many are a move and a return.
const MIN_INSTRUCTIONS: usize = 10;
const MIN_BYTES: u64 = 32;

/// The fingerprint of the function occupying `[start, end)`, or `None` when it is too small to
/// be distinctive or the architecture is not supported.
pub fn fingerprint(image: &Image, pointer_slots: &HashMap<u64, u64>, start: u64, end: u64) -> Option<u64> {
    let bits = match image.machine {
        Machine::X86 => 32,
        Machine::X86_64 => 64,
        Machine::Aarch64 => return None,
    };
    if end.checked_sub(start)? < MIN_BYTES {
        return None;
    }
    let bytes = image.bytes_from(start)?;
    let bytes = bytes.get(..(end - start) as usize)?;
    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);

    // FNV-1a.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |byte: u8| hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    let mut instructions = 0;

    while decoder.can_decode() {
        let offset = decoder.position();
        let instr = decoder.decode();
        if instr.is_invalid() {
            return None;
        }
        instructions += 1;
        let offsets = decoder.get_constant_offsets(&instr);
        let raw = &bytes[offset..offset + instr.len()];

        // Which bytes of the instruction hold an address that moves between binaries.
        let mut blank = [false; 16];
        let mut mark = |at: usize, size: usize| blank[at..(at + size).min(16)].iter_mut().for_each(|b| *b = true);
        let leaves = |target: u64| target < start || target >= end;

        if offsets.has_displacement() {
            let at = offsets.displacement_offset();
            let relocated = pointer_slots.contains_key(&(instr.ip() + at as u64));
            if instr.is_ip_rel_memory_operand() || relocated {
                mark(at, offsets.displacement_size());
            }
        }
        if offsets.has_immediate() {
            let at = offsets.immediate_offset();
            let is_branch = matches!(
                instr.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            );
            let relocated = pointer_slots.contains_key(&(instr.ip() + at as u64));
            // A call or jump to somewhere else in the binary; branches within the function
            // are relative and identical everywhere.
            let external = is_branch && (instr.flow_control() == FlowControl::Call || leaves(instr.near_branch_target()));
            if relocated || external {
                mark(at, offsets.immediate_size());
            }
        }
        for (index, &byte) in raw.iter().enumerate() {
            feed(if blank[index] { 0 } else { byte });
        }
    }
    (instructions >= MIN_INSTRUCTIONS).then_some(hash)
}

/// Known fingerprints and the library function each belongs to.
pub struct Signatures {
    names: HashMap<u64, &'static str>,
}

impl Signatures {
    /// The signatures built into this crate for `machine`: one `hash name` pair per line.
    pub fn builtin(machine: Machine) -> Signatures {
        let text = match machine {
            Machine::X86 => include_str!("../data/x86.sigs"),
            Machine::X86_64 => include_str!("../data/x86_64.sigs"),
            Machine::Aarch64 => "",
        };
        let names = text
            .lines()
            .filter_map(|line| {
                let (hash, name) = line.split_once(' ')?;
                Some((u64::from_str_radix(hash, 16).ok()?, name))
            })
            .collect();
        Signatures { names }
    }

    pub fn name(&self, fingerprint: u64) -> Option<&'static str> {
        self.names.get(&fingerprint).copied()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}
