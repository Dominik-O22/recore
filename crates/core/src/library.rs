//! Library routines of a compiler, recognised by their code.
//!
//! A compiler calls routines of its library for what the processor has no instruction for:
//! on an 8051, arithmetic on more than a byte and loads through a pointer that says which
//! memory it points into. Some pass arguments in registers no C function would, so a call
//! to one reads as a call that takes nothing and leaves registers behind. The routines are
//! the same code in every program, and `data/*.lib` lists a hash of each.

use std::sync::LazyLock;

use rayon::prelude::*;
use rustc_hash::FxHashMap;

use crate::image::{Compiler, Image, Machine};

/// One routine of a library.
pub struct Routine {
    pub name: &'static str,
    /// Where it takes its arguments and leaves its result, as `ACC(R3:R2:R1,DPTR)`, if the
    /// list says.
    pub storage: Option<&'static str>,
    /// Registers it brings back before it returns, though its code writes them.
    pub restores: Vec<&'static str>,
    /// Bytes of code, and their hash with the bytes of `left_out` taken as zero.
    length: usize,
    hash: u64,
    /// `(offset, count, routine)`: bytes that differ from program to program. Where a routine
    /// is named, the two bytes are its address.
    left_out: Vec<(usize, usize, Option<&'static str>)>,
}

impl Routine {
    fn parse(line: &'static str) -> Option<Routine> {
        let mut words = line.split_whitespace();
        let (name, storage) = (words.next()?, words.next()?);
        let (length, hash) = (words.next()?.parse().ok()?, u64::from_str_radix(words.next()?, 16).ok()?);
        let left_out = words
            .map(|span| {
                let (span, routine) = span.split_once('=').map_or((span, None), |(span, routine)| (span, Some(routine)));
                let (offset, count) = span.split_once('+')?;
                Some((offset.parse().ok()?, count.parse().ok()?, routine))
            })
            .collect::<Option<_>>()?;
        let mut restores = storage.split(';');
        let storage = restores.next().filter(|&storage| storage != "-");
        Some(Routine { name, storage, restores: restores.collect(), length, hash, left_out })
    }

    /// Whether `bytes` start with the routine's code.
    pub fn is_at(&self, bytes: &[u8]) -> bool {
        bytes.get(..self.length).is_some_and(|code| hash(code, &self.left_out) == self.hash)
    }
}

/// FNV-1a over `code` with the bytes of `left_out` taken as zero, as `data/fingerprint.py`
/// has it.
fn hash(code: &[u8], left_out: &[(usize, usize, Option<&'static str>)]) -> u64 {
    let mut left_out = left_out.iter().peekable();
    let mut hash = 0xcbf29ce484222325u64;
    for (offset, &byte) in code.iter().enumerate() {
        while left_out.next_if(|&&(start, count, _)| start + count <= offset).is_some() {}
        let byte = if left_out.peek().is_some_and(|&&(start, _, _)| start <= offset) { 0 } else { byte };
        hash = (hash ^ byte as u64).wrapping_mul(0x100000001b3);
    }
    hash
}

fn parse(list: &'static str) -> Vec<Routine> {
    list.lines().filter(|line| !line.starts_with('#')).filter_map(Routine::parse).collect()
}

static KEIL: LazyLock<Vec<Routine>> = LazyLock::new(|| {
    let routines = parse(include_str!("../data/keil-c51.lib")).into_iter();
    #[cfg(test)]
    let routines = routines.chain(STAND_INS.iter().map(|&(name, code)| Routine { name, storage: None, restores: Vec::new(), length: code.len(), hash: hash(code, &[]), left_out: Vec::new() }));
    routines.collect()
});
static SDCC: LazyLock<Vec<Routine>> = LazyLock::new(|| parse(include_str!("../data/sdcc-mcs51.lib")));

/// Code the tests of this crate have in place of routines of Keil's library, under the names
/// of those, as the list holds no code to build the real ones from. Only `triple_index` does
/// what its routine does.
#[cfg(test)]
pub(crate) const STAND_INS: [(&str, &[u8]); 5] = [
    // MOV A, R4; ADD A, R5; ADD A, R6; ADD A, R7; MOV R7, A; RET.
    ("?C?LMUL", &[0xEC, 0x2D, 0x2E, 0x2F, 0xFF, 0x22]),
    // POP DPH; POP DPL; CLR A; JMP @A+DPTR.
    ("?C?CCASE", &[0xD0, 0x83, 0xD0, 0x82, 0xE4, 0x73]),
    // The same with MOV R0, B ahead of CLR A.
    ("?C?ICASE", &[0xD0, 0x83, 0xD0, 0x82, 0xA8, 0xF0, 0xE4, 0x73]),
    // POP DPH; POP DPL; four times INC DPTR; CLR A; JMP @A+DPTR.
    ("?C?LSTKXDATA", &[0xD0, 0x83, 0xD0, 0x82, 0xA3, 0xA3, 0xA3, 0xA3, 0xE4, 0x73]),
    // MOV R0, A; ADD A, R0; ADD A, R0; RET.
    ("triple_index", &[0xF8, 0x28, 0x28, 0x22]),
];

/// The routines of the library that code for `machine` calls when `compiler` built it. An
/// image that names no compiler is taken as Keil's.
pub fn routines(machine: Machine, compiler: Option<Compiler>) -> &'static [Routine] {
    match (machine, compiler) {
        (Machine::I8051, Some(Compiler::Sdcc)) => &SDCC,
        (Machine::I8051, Some(Compiler::Keil) | None) => &KEIL,
        _ => &[],
    }
}

/// Which of `functions`, the addresses of functions of the image, are routines of `library`.
pub fn recognise<'a>(image: &Image, functions: &[u64], library: &'a [Routine]) -> Vec<(u64, &'a Routine)> {
    let code_at = |function: u64| image.bytes_from(function).unwrap_or(&[]);
    // What each function may be by its own code. Routines that differ only in what they jump
    // to are told apart after, by what those are.
    let alike: FxHashMap<u64, Vec<&Routine>> = functions
        .par_iter()
        .map(|&function| (function, library.iter().filter(|routine| routine.is_at(code_at(function))).collect::<Vec<_>>()))
        .filter(|(_, alike)| !alike.is_empty())
        .collect();
    let goes_where_it_should = |function: u64, routine: &Routine| {
        routine.left_out.iter().all(|&(offset, _, target)| {
            let Some(target) = target else { return true };
            // An 8051 address in code: 16 bits, most significant first, in the bank of the code
            // or in what all banks share.
            let address = u64::from(u16::from_be_bytes([code_at(function)[offset], code_at(function)[offset + 1]]));
            [function & !0xffff | address, address].iter().any(|address| alike.get(address).is_some_and(|alike| alike.iter().any(|routine| routine.name == target)))
        })
    };
    let mut found: Vec<_> = alike.iter().filter_map(|(&function, alike)| Some((function, *alike.iter().find(|routine| goes_where_it_should(function, routine))?))).collect();
    found.sort_by_key(|&(function, _)| function);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_routine_is_its_code_wherever_the_bytes_left_out_allow() {
        // LCALL to anywhere; CLR A; RET; and three more bytes.
        let routine = Routine::parse("?C?X ACC(R3:R2:R1) 8 9a1e1d2081d71645 1+2").unwrap();
        assert_eq!((routine.name, routine.storage), ("?C?X", Some("ACC(R3:R2:R1)")));
        assert!(routine.is_at(&[0x12, 0x34, 0x56, 0xe4, 0x22, 1, 2, 3, 0xff]));
        assert!(routine.is_at(&[0x12, 0x00, 0x00, 0xe4, 0x22, 1, 2, 3]));
        assert!(!routine.is_at(&[0x12, 0x34, 0x56, 0xe5, 0x22, 1, 2, 3]));
        assert!(!routine.is_at(&[0x12, 0x34, 0x56, 0xe4, 0x22, 1, 2]));
    }

    #[test]
    fn every_line_of_a_list_is_a_routine() {
        for (compiler, list) in [(Compiler::Keil, include_str!("../data/keil-c51.lib")), (Compiler::Sdcc, include_str!("../data/sdcc-mcs51.lib"))] {
            let lines = list.lines().filter(|line| !line.starts_with('#')).count();
            let stand_ins = if compiler == Compiler::Keil { STAND_INS.len() } else { 0 };
            assert_eq!(routines(Machine::I8051, Some(compiler)).len(), lines + stand_ins);
        }
    }
}
