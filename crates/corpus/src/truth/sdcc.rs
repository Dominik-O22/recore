//! Ground truth for an 8051 program built by `corpus/build_8051.py` with SDCC.
//!
//! The linker's debug records (`.cdb`) give each C function's start and the address of its last
//! instruction: `L:G$name$0$0:ADDR` and `L:XG$name$0$0:ADDR`, with `F<module>` in place of `G`
//! for a static function. Routines written in assembly have no such records. They come from the
//! linker's map, which lists each global label of a code area. A label is a function where a C
//! function calls it. One that code only jumps to or runs into is a piece of some routine with
//! no agreed owner, which scoring neither demands nor penalises. Either has the code up to the
//! next label or function.
//!
//! A `switch` over a dense range is `MOV DPTR, #table` and `JMP @A+DPTR` into a run of jumps, one
//! per case. The listing of each module at its final addresses (`.rst`) shows the run: the lines
//! from the label the `MOV` names to the next label. Where that would not fit, the jump follows
//! two runs of bytes, the low and then the high halves of the cases' addresses, which the code
//! reads into `DPTR` with `MOVC A, @A+PC`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use recore::arch::{Arch, Flow};
use recore::i8051::I8051;

use super::{Function, Truth};
use crate::jumptables::{Extracted, JumpTable, JumpTables, Rejected};

/// The name of a program, which its layout is named after.
fn name(layout: &Path) -> String {
    layout.file_stem().unwrap_or_default().to_string_lossy().into_owned()
}

/// The start and the last instruction's address of every C function in the debug records.
fn c_functions(cdb: &str) -> BTreeMap<u64, (String, Option<u64>)> {
    // `F:` records name the functions, which tells them from the variables among the `L:` ones.
    let functions: HashSet<&str> = cdb.lines().filter_map(|line| line.strip_prefix("F:")?.split_once("$0_0$0(")).map(|(symbol, _)| symbol).collect();
    let (mut starts, mut ends) = (HashMap::new(), HashMap::new());
    for line in cdb.lines() {
        let Some((symbol, addr)) = line.strip_prefix("L:").and_then(|record| record.split_once("$0$0:")) else { continue };
        let Ok(addr) = u64::from_str_radix(addr, 16) else { continue };
        match symbol.strip_prefix('X') {
            Some(symbol) if functions.contains(symbol) => ends.insert(symbol, addr),
            _ if functions.contains(symbol) => starts.insert(symbol, addr),
            _ => None,
        };
    }
    starts.into_iter().map(|(symbol, start)| (start, (symbol.rsplit_once('$').map_or(symbol, |(_, name)| name).to_string(), ends.get(symbol).copied()))).collect()
}

/// The global labels of the map's code areas, as `(address, name, area)`.
fn code_labels(map: &str) -> Vec<(u64, &str, &str)> {
    let mut labels = Vec::new();
    let mut area = None;
    for line in map.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            // `CSEG  000000AA  000037D8 =  14296. bytes (REL,CON,CODE)` opens an area.
            (Some(name), Some(_), Some(_)) if line.ends_with(')') && line.contains(" bytes (") => area = line.ends_with(",CODE)").then_some(name),
            (Some("C:"), Some(addr), Some(label)) => {
                if let (Some(area), Ok(addr)) = (area, u64::from_str_radix(addr, 16)) {
                    labels.push((addr, label, area));
                }
            }
            _ => {}
        }
    }
    labels
}

pub fn extract(layout: &Path, cdb_path: &Path) -> Result<Truth> {
    let image = recore::Image::load(layout)?;
    let cdb = std::fs::read_to_string(cdb_path).with_context(|| format!("reading {cdb_path:?}"))?;
    let map_path = cdb_path.with_extension("map");
    let map = std::fs::read_to_string(&map_path).with_context(|| format!("reading {map_path:?}"))?;
    let first = |addr: u64| I8051::decode(image.bytes_from(addr)?, addr).next();

    let mut by_addr: BTreeMap<u64, Function> = BTreeMap::new();
    for (addr, (name, last)) in c_functions(&cdb) {
        let size = last.and_then(|last| Some(last + u64::from(first(last)?.len) - addr)).unwrap_or(0);
        by_addr.insert(addr, Function { addr, size, name, fragment: false, noreturn: false, thunk: false });
    }
    // The decode of each C function gives the instruction counts, and the calls that say which
    // labels are functions.
    let (mut instructions, mut undecodable_bytes) = (0, 0);
    let mut called = HashSet::new();
    let c_ranges: Vec<(u64, u64)> = by_addr.values().map(|function| (function.addr, function.addr + function.size)).collect();
    for function in by_addr.values() {
        let Some(bytes) = image.bytes_from(function.addr).and_then(|bytes| bytes.get(..function.size as usize)) else { continue };
        for decoded in I8051::decode(bytes, function.addr) {
            instructions += u64::from(decoded.insn.is_some());
            undecodable_bytes += if decoded.insn.is_none() { u64::from(decoded.len) } else { 0 };
            if let Some(Flow::Call(target)) = decoded.insn.and_then(|insn| I8051::flow(&insn, &Default::default(), &image)) {
                called.insert(target);
            }
        }
    }
    // A lone jump is a thunk, as in a PE image: nothing says whether it is a function or the
    // way to one.
    let is_thunk = |addr: u64| first(addr).and_then(|decoded| decoded.insn).is_some_and(|insn| matches!(I8051::flow(&insn, &Default::default(), &image), Some(Flow::Jump(_))));
    for (addr, label, area) in code_labels(&map) {
        // Debug symbols, the linker's own, and constants: only code areas hold routines.
        if label.contains('$') || !(area == "HOME" || area == "CSEG" || area.starts_with("GSINIT") || area.starts_with("BANK")) || !image.is_code(addr) {
            continue;
        }
        let thunk = is_thunk(addr);
        by_addr.entry(addr).or_insert(Function { addr, size: 0, name: label.to_string(), fragment: thunk || !called.contains(&addr), noreturn: false, thunk });
    }
    // The hardware enters at the reset and interrupt vectors, each a jump to its handler.
    for addr in std::iter::once(image.entry).chain(image.exports.iter().copied().filter(|&addr| addr < 0x100 && addr % 8 == 3)) {
        let thunk = is_thunk(addr);
        by_addr.entry(addr).or_insert(Function { addr, size: 0, name: format!("vector_{addr:02x}"), fragment: thunk, noreturn: false, thunk });
    }

    // Assembly has no record of where a routine ends: it has what follows its label, up to the
    // next label or function, within its section.
    let starts: Vec<u64> = by_addr.keys().copied().collect();
    for (function, next) in by_addr.values_mut().zip(starts.iter().skip(1).copied().chain([u64::MAX])) {
        if c_ranges.binary_search_by_key(&function.addr, |&(start, _)| start).is_err() {
            let section_end = image.sections.iter().find(|section| section.contains(function.addr)).map_or(function.addr, |section| section.end());
            function.size = next.min(section_end) - function.addr;
        }
    }
    let exec: Vec<(u64, u64)> = image.sections.iter().filter(|section| section.executable).map(|section| (section.addr, section.end())).collect();
    Ok(Truth {
        name: name(layout),
        text: (0, exec.iter().map(|&(_, end)| end).max().unwrap_or(0)),
        exec,
        functions: by_addr.into_values().collect(),
        instructions,
        noreturn_calls: Vec::new(),
        terminal_calls: Vec::new(),
        noreturn_imports: Vec::new(),
        undecodable_bytes,
        data_bytes: 0,
    })
}

/// One line of a listing that assembled to something or is a label: its address, its bytes,
/// and its text.
fn listed(line: &str) -> Option<(u64, Vec<u8>, &str)> {
    // The address is six digits after six spaces. A line without one starts with more spaces.
    let addr = line.get(6..12).filter(|_| line.starts_with("      ")).and_then(|word| u64::from_str_radix(word, 16).ok())?;
    // The bytes have the columns up to the cycle count or, in a line of data, the line number.
    let bytes = line.get(12..30).unwrap_or(&line[12..]).split_whitespace().map_while(|word| u8::from_str_radix(word, 16).ok()).collect();
    // After the bytes come the cycle count in brackets, the line number, and the source text,
    // which a tab sets off unless it is a label.
    let text = line.split_once('\t').map_or_else(|| line.rsplit(' ').next().unwrap_or(""), |(_, text)| text);
    Some((addr, bytes, text.trim()))
}

pub fn jump_tables(layout: &Path, rst_path: &Path) -> Result<Option<Extracted>> {
    let rst = std::fs::read_to_string(rst_path).with_context(|| format!("reading {rst_path:?}"))?;
    let (tables, rejected, listed) = listed_tables(&rst);
    Ok(Some(Extracted { truth: JumpTables { name: name(layout), tables }, listed, rejected }))
}

/// The tables of a listing, those left out, and how many there are in all.
fn listed_tables(rst: &str) -> (Vec<JumpTable>, Vec<Rejected>, usize) {
    let lines: Vec<(u64, Vec<u8>, &str)> = rst.lines().filter_map(listed).filter(|(_, bytes, text)| !bytes.is_empty() || text.ends_with(':')).collect();
    let is_label = |index: usize| lines.get(index).is_some_and(|(_, bytes, text)| bytes.is_empty() && text.ends_with(':'));
    let (mut tables, mut rejected, mut listed) = (Vec::new(), Vec::new(), 0);
    for (index, (jump, _, text)) in lines.iter().enumerate() {
        // Only a jump with a label straight after it has a table. Others call through a pointer.
        if !text.starts_with("jmp\t@a+dptr") || !is_label(index + 1) {
            continue;
        }
        let (table, _, label) = lines[index + 1];
        let run = |from: usize| -> Vec<&(u64, Vec<u8>, &str)> { lines.get(from..).unwrap_or_default().iter().take_while(|(_, bytes, _)| !bytes.is_empty()).collect() };
        let slots = run(index + 2);
        let starts_with = |slot: &&(u64, Vec<u8>, &str), words: &[&str]| words.iter().any(|word| slot.2.starts_with(word));
        let is_jump = |slot: &&(u64, Vec<u8>, &str)| starts_with(slot, &["ljmp\t", "sjmp\t", "ajmp\t"]);
        let is_byte = |slot: &&(u64, Vec<u8>, &str)| starts_with(slot, &[".db\t"]);
        let before = &lines[index.saturating_sub(10)..index];
        let label = label.trim_end_matches(':');
        if slots.first().is_some_and(is_jump) {
            listed += 1;
            let loads_table = format!("mov\tdptr,#{label}");
            if !before.iter().any(|(_, _, text)| *text == loads_table) {
                rejected.push(Rejected { table, reason: "the code before the jump does not load the table's address".to_string() });
            } else if !slots.iter().all(is_jump) {
                rejected.push(Rejected { table, reason: "something other than a jump lies among the table's jumps".to_string() });
            } else {
                // The jump lands on one of the table's jumps, which goes on to the case.
                tables.push(JumpTable { jump: *jump, table, targets: slots.iter().map(|slot| slot.0).collect(), unreachable: None });
            }
        } else if slots.first().is_some_and(is_byte) {
            listed += 1;
            // The low halves, a label, and as many high halves.
            let low: Vec<u8> = slots.iter().flat_map(|slot| slot.1.iter().copied()).collect();
            let second = index + 2 + slots.len();
            let high: Vec<u8> = run(second + 1).iter().flat_map(|slot| slot.1.iter().copied()).take(low.len()).collect();
            let reads = |label: &str| before.iter().any(|(_, _, text)| *text == format!("add\ta,#({label}-3-.)"));
            if !slots.iter().all(is_byte) || !is_label(second) || high.len() != low.len() {
                rejected.push(Rejected { table, reason: "the bytes after the jump are not two runs of one length".to_string() });
            } else if !reads(label) || !reads(lines[second].2.trim_end_matches(':')) {
                rejected.push(Rejected { table, reason: "the code before the jump does not read both runs".to_string() });
            } else {
                // A case is in the function, and so in the bank, of the jump.
                let mut targets: Vec<u64> = low.iter().zip(&high).map(|(&low, &high)| jump & !0xFFFF | u64::from(u16::from_be_bytes([high, low]))).collect();
                targets.sort_unstable();
                targets.dedup();
                tables.push(JumpTable { jump: *jump, table, targets, unreachable: None });
            }
        }
    }
    tables.sort_by_key(|table| table.jump);
    (tables, rejected, listed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_function_runs_from_its_record_to_the_record_of_its_last_instruction() {
        let cdb = "F:G$pick$0_0$0({2}DF,SC:U),C,0,0,0,0,0\nF:Fmod$local$0_0$0({2}DF,SI:S),C,0,0,0,0,0\nS:G$P0$0_0$0({1}SC:U),I,0,0\n\
                   L:G$P0$0_0$0:80\nL:G$pick$0$0:B9\nL:XG$pick$0$0:F3\nL:Fmod$local$0$0:18000\nL:XFmod$local$0$0:1801A\nL:C$t.c$6$1_0$45:B9\n";
        let functions: Vec<_> = c_functions(cdb).into_iter().collect();
        assert_eq!(functions, [(0xB9, ("pick".to_string(), Some(0xF3))), (0x1_8000, ("local".to_string(), Some(0x1_801A)))]);
    }

    #[test]
    fn a_table_is_two_runs_of_bytes_where_the_code_reads_them() {
        let rst = "      0018DF 24 08            [12] 1285 \tadd\ta,#(00182$-3-.)\n\
                   \x20     0018E5 24 05            [12] 1289 \tadd\ta,#(00183$-3-.)\n\
                   \x20     0018EA 73               [24] 1293 \tjmp\t@a+dptr\n\
                   \x20     0018EB                       1294 00182$:\n\
                   \x20     0018EB 36                    1295 \t.db\t00101$\n\
                   \x20     0018EC B9                    1296 \t.db\t00102$\n\
                   \x20     0018ED 36                    1297 \t.db\t00101$\n\
                   \x20     0018EE                       1298 00183$:\n\
                   \x20     0018EE 19                    1299 \t.db\t00101$>>8\n\
                   \x20     0018EF 1A                    1300 \t.db\t00102$>>8\n\
                   \x20     0018F0 19                    1301 \t.db\t00101$>>8\n\
                   \x20     0018F1                       1302 00101$:\n";
        let (tables, rejected, listed) = listed_tables(rst);
        let tables: Vec<_> = tables.iter().map(|table| (table.jump, table.table, table.targets.as_slice())).collect();
        assert_eq!(tables, [(0x18EA, 0x18EB, &[0x1936, 0x1AB9][..])]);
        assert_eq!((rejected.len(), listed), (0, 1));
    }

    #[test]
    fn a_table_is_the_jumps_between_the_label_its_jump_loads_and_the_next() {
        // A switch of three cases, and a call through a pointer, which has no table.
        let rst = "      0000C2 90 00 C6         [24]  527 \tmov\tdptr,#00119$\n\
                   \x20     0000C5 73               [24]  528 \tjmp\t@a+dptr\n\
                   \x20     0000C6                        529 00119$:\n\
                   \x20     0000C6 80 0A            [24]  530 \tsjmp\t00101$\n\
                   \x20     0000C8 80 0D            [24]  531 \tsjmp\t00102$\n\
                   \x20     0000CA 80 10            [24]  532 \tsjmp\t00103$\n\
                   \x20     0000D2                        536 00101$:\n\
                   \x20     0000D2 80 FE            [24]  537 \tsjmp\t00101$\n\
                   \x20     000100 E4               [12]  600 \tclr\ta\n\
                   \x20     000101 73               [24]  601 \tjmp\t@a+dptr\n\
                   \x20     000102                        602 _next:\n\
                   \x20     000102 22               [24]  603 \tret\n";
        let (tables, rejected, listed) = listed_tables(rst);
        let tables: Vec<_> = tables.iter().map(|table| (table.jump, table.table, table.targets.as_slice())).collect();
        assert_eq!(tables, [(0xC5, 0xC6, &[0xC6, 0xC8, 0xCA][..])]);
        assert_eq!((rejected.len(), listed), (0, 1));
    }
}
