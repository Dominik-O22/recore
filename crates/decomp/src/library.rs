//! Library routines of a compiler, recognised by their code.
//!
//! A compiler calls routines of its library for what the processor has no instruction for:
//! on an 8051, arithmetic on more than a byte and loads through a pointer that says which
//! memory it points into. Some pass arguments in registers no C function would, so a call
//! to one reads as a call that takes nothing and leaves registers behind. The routines are
//! the same code in every program, and `data/*.lib` lists a hash of each.

use std::collections::HashMap;

use recore::Image;
use recore::report::Analysis;

use crate::Target;

/// One routine of a library.
pub struct Routine {
    pub name: &'static str,
    /// Where it takes its arguments and leaves its result, as `ACC(R3:R2:R1,DPTR)`, if the
    /// list says.
    pub storage: Option<&'static str>,
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
        Some(Routine { name, storage: Some(storage).filter(|&storage| storage != "-"), length, hash, left_out })
    }

    /// Whether `bytes` start with the routine's code. FNV-1a, as `data/fingerprint.py` has it.
    pub fn is_at(&self, bytes: &[u8]) -> bool {
        let Some(code) = bytes.get(..self.length) else { return false };
        let mut left_out = self.left_out.iter().peekable();
        let mut hash = 0xcbf29ce484222325u64;
        for (offset, &byte) in code.iter().enumerate() {
            while left_out.next_if(|&&(start, count, _)| start + count <= offset).is_some() {}
            let byte = if left_out.peek().is_some_and(|&&(start, _, _)| start <= offset) { 0 } else { byte };
            hash = (hash ^ byte as u64).wrapping_mul(0x100000001b3);
        }
        hash == self.hash
    }
}

/// The routines of the library that code for `target` calls.
pub fn routines(target: Target) -> Vec<Routine> {
    let list = match target {
        Target::I8051 => include_str!("../data/keil-c51.lib"),
        Target::I8051Sdcc => include_str!("../data/sdcc-mcs51.lib"),
        _ => "",
    };
    list.lines().filter(|line| !line.starts_with('#')).filter_map(Routine::parse).collect()
}

/// The functions of the image that are routines of `library`, by address.
pub fn recognise<'a>(image: &Image, analysis: &Analysis, library: &'a [Routine]) -> Vec<(u64, &'a Routine)> {
    let code_at = |function: u64| image.bytes_from(function).unwrap_or(&[]);
    // What each function may be by its own code. Routines that differ only in what they jump
    // to are told apart after, by what those are.
    let functions = analysis.functions.iter().filter(|function| function.fragment_of.is_none()).map(|function| function.addr);
    let alike: HashMap<u64, Vec<&Routine>> = functions.map(|function| (function, library.iter().filter(|routine| routine.is_at(code_at(function))).collect())).filter(|(_, alike): &(_, Vec<_>)| !alike.is_empty()).collect();
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
        for (target, list) in [(Target::I8051, include_str!("../data/keil-c51.lib")), (Target::I8051Sdcc, include_str!("../data/sdcc-mcs51.lib"))] {
            let lines = list.lines().filter(|line| !line.starts_with('#')).count();
            assert_eq!(routines(target).len(), lines);
        }
    }
}
