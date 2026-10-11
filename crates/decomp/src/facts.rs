//! recore's analysis, rearranged into the per-function statements the decompiler takes.

use std::borrow::Cow;

use recore::Image;
use recore::image::Machine;
use recore::report::{Analysis, CallTarget};

/// Control-flow facts for one binary. Each override is attributed to the function whose
/// decompilation it affects: the function containing the instruction and, when that is a cold
/// fragment, also the function the fragment belongs to, because the decompiler follows jumps
/// into fragments.
#[derive(Debug, Default)]
pub struct Facts {
    /// Entry points to declare, with whether the function never returns. Fragments are left
    /// out: they are reached by jumps, never called, and a declared entry stops flow from other
    /// functions.
    pub functions: Vec<(u64, bool)>,
    /// Names the image carries for functions, demangled.
    pub names: Vec<(u64, String)>,
    /// `(address, slot)`: code that only forwards to the import behind `slot`. These are PLT
    /// stubs, which recore does not list as functions, and import thunks, which it does.
    pub import_aliases: Vec<(u64, u64)>,
    /// `(function, jump)`: an unconditional jump that leaves the function for another one or
    /// for an import. Conditional tail calls are left out, so the decompiler still follows those
    /// into the callee.
    pub tail_calls: Vec<(u64, u64)>,
    /// `(function, call, slot)`: a call through an import slot.
    pub import_calls: Vec<(u64, u64, u64)>,
    /// `(function, call, target)`: a call through a pointer slot that holds a local function.
    pub local_calls: Vec<(u64, u64, u64)>,
}

impl Facts {
    pub fn derive(image: &Image, analysis: &Analysis) -> Facts {
        let mut facts = Facts {
            functions: analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| (f.addr, f.noreturn)).collect(),
            names: analysis.functions.iter().filter_map(|f| Some((f.addr, f.name.clone()?))).collect(),
            ..Facts::default()
        };
        // Every range with the functions an instruction inside it affects.
        let mut ranges: Vec<(u64, u64, u64, Option<u64>)> = analysis
            .functions
            .iter()
            .flat_map(|f| f.ranges.iter().map(move |&(start, end)| (start, end, f.addr, f.fragment_of)))
            .collect();
        ranges.sort_unstable();

        let x86 = matches!(image.machine, Machine::X86 | Machine::X86_64);
        for call in &analysis.calls {
            let index = ranges.partition_point(|range| range.0 <= call.at);
            let Some(&(_, _, function, owner)) = ranges[..index].last().filter(|range| call.at < range.1) else { continue };
            // recore says where a call goes, not how. On x86 the opcode tells a call through a
            // pointer slot (ff /2, possibly behind a `notrack` prefix) from a direct one (e8).
            let bytes = image.bytes_from(call.at).filter(|_| x86).unwrap_or(&[]);
            let bytes = bytes.strip_prefix(&[0x3e]).unwrap_or(bytes);
            let through_slot = bytes.first() == Some(&0xff);
            for function in std::iter::once(function).chain(owner) {
                match (call.tail, call.target) {
                    // The engine can only turn an unconditional jump into a call and return.
                    (true, _) if !call.conditional => facts.tail_calls.push((function, call.at)),
                    (false, CallTarget::Import(slot)) if through_slot => facts.import_calls.push((function, call.at, slot)),
                    (false, CallTarget::Function(target)) if through_slot => facts.local_calls.push((function, call.at, target)),
                    _ => {}
                }
            }
            if let (Machine::Aarch64, false, CallTarget::Import(slot)) = (image.machine, call.tail, call.target) {
                // `bl` to a PLT stub: the top six bits are the opcode, the rest a word offset.
                let word = image.bytes_from(call.at).and_then(|b| b.first_chunk::<4>()).map(|b| u32::from_le_bytes(*b));
                if let Some(word) = word.filter(|word| word >> 26 == 0b100101) {
                    let offset = i64::from((word << 6) as i32 >> 6) * 4;
                    facts.import_aliases.push((call.at.wrapping_add_signed(offset), slot));
                }
            }
            match (call.tail, call.target, bytes.first_chunk::<5>()) {
                // A direct call that recore resolves to an import goes to a PLT stub.
                (false, CallTarget::Import(slot), Some([0xe8, rel @ ..])) => {
                    facts.import_aliases.push(((call.at + 5).wrapping_add_signed(i32::from_le_bytes(*rel).into()), slot));
                }
                // A function that starts by jumping through an import slot is a thunk for it.
                (true, CallTarget::Import(slot), _) if call.at == function && through_slot => facts.import_aliases.push((function, slot)),
                _ => {}
            }
        }
        facts.import_aliases.sort_unstable();
        facts.import_aliases.dedup_by_key(|alias| alias.0);
        facts
    }
}

/// A piece of the image as the program sees it once the loader is done.
pub struct Loaded<'a> {
    pub addr: u64,
    pub data: Cow<'a, [u8]>,
    /// The bytes cannot change at run time, so the decompiler may use them as constants.
    pub constant: bool,
    pub code: bool,
}

/// The image's sections after loading. Relative relocations are applied, so that pointer tables
/// and GOT entries for local functions hold their real targets; in the file they are zero or an
/// addend. Slots bound to imports get whatever address the other library ends up at, so each is
/// split off as a piece that is not constant.
pub fn loaded(image: &Image) -> Vec<Loaded<'_>> {
    let mut slots: Vec<u64> = image.import_slots.keys().copied().collect();
    slots.sort_unstable();
    let mut relocations = image.relative_targets.clone();
    relocations.sort_unstable();

    let pointer = if image.machine == Machine::X86 { 4 } else { 8 };
    let mut pieces = Vec::new();
    for section in &image.sections {
        let inside = |addr: u64| addr >= section.addr && addr + pointer as u64 <= section.end();
        if section.writable {
            pieces.push(Loaded { addr: section.addr, data: Cow::Borrowed(&section.data[..]), constant: false, code: section.executable });
            continue;
        }
        let mut data = Cow::Borrowed(&section.data[..]);
        let first = relocations.partition_point(|r| r.0 < section.addr);
        for &(slot, target) in relocations[first..].iter().take_while(|r| inside(r.0)) {
            let offset = (slot - section.addr) as usize;
            data.to_mut()[offset..offset + pointer].copy_from_slice(&target.to_le_bytes()[..pointer]);
        }
        // Cut the section at every import slot it contains.
        let first = slots.partition_point(|&slot| slot < section.addr);
        let mut cuts = vec![0];
        for &slot in slots[first..].iter().take_while(|&&slot| inside(slot)) {
            let offset = (slot - section.addr) as usize;
            cuts.extend([offset, offset + pointer]);
        }
        cuts.push(data.len());
        for (index, range) in cuts.windows(2).enumerate().filter(|(_, range)| range[0] < range[1]) {
            let piece = match &data {
                Cow::Borrowed(bytes) => Cow::Borrowed(&bytes[range[0]..range[1]]),
                Cow::Owned(bytes) => Cow::Owned(bytes[range[0]..range[1]].to_vec()),
            };
            // Even windows lie between slots, odd ones are the slots themselves.
            pieces.push(Loaded { addr: section.addr + range[0] as u64, data: piece, constant: index % 2 == 0, code: section.executable });
        }
    }
    pieces
}
