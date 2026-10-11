//! Ground truth for PE images, PE32 (i386) and PE32+ (x86-64), from the image and its PDB.
//!
//! The PDB's module symbols give functions with lengths and a "never returns" flag
//! (`S_GPROC32`/`S_LPROC32`), the pieces split off them (`S_SEPCODE`), and thunks (`S_THUNK32`,
//! `S_TRAMPOLINE`). Public symbols add the functions of objects linked without debug info, such
//! as a static C runtime; those carry no length, so on x86-64 it comes from the exception
//! directory and on i386 it stays zero. All addresses are image base plus RVA.
//!
//! Three kinds of entries are flagged `fragment`, which takes them out of scoring both ways:
//! separated code, exception funclets (`catch$0`, `fin$0`, `filt$0`, `dtor$0` on x86-64,
//! `__ehhandler$f` and `__unwindfunclet$f$0` on i386), and thunks, which are also flagged
//! `thunk`. Calls to a thunk are classified by what the thunk jumps to.
//!
//! MSVC keeps switch tables in `.text`, after the function's last instruction and inside its
//! length. [`Image::code_ranges`] separates them; they count as `data_bytes`, not code.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{LittleEndian as LE, Object};
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE,
};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData, PeFile, SectionTable};
use pdb2::{FallibleIterator, SymbolData, TrampolineType};

use super::{Callee, Callees, Function, Scan, Truth, classify, is_runtime_noreturn, x86};

/// The largest share of `.text` that may lie outside every PDB function without being padding,
/// for an image to get truth. A PDB stripped of private symbols, or one that leaves out
/// statically linked libraries, names too little of the code to be scored against.
const MAX_UNNAMED_PERCENT: u64 = 5;

/// One `RUNTIME_FUNCTION` of the x86-64 exception directory, as virtual addresses.
#[derive(Clone, Copy)]
pub struct RuntimeFunction {
    pub begin: u64,
    pub end: u64,
    /// Address of its `UNWIND_INFO`.
    pub unwind: u64,
}

/// A PE image and what its PDB says about it.
pub struct Image<'d> {
    data: &'d [u8],
    sections: SectionTable<'d>,
    pub base: u64,
    /// 32 or 64.
    pub bitness: u32,
    pub entry: u64,
    /// Exported code addresses.
    pub exports: Vec<u64>,
    /// Executable section ranges as `[start, end)`.
    pub exec: Vec<(u64, u64)>,
    pub text: (u64, u64),
    /// Import address table slots, delay-loaded ones included, to `name` or `dll#ordinal`.
    pub slots: HashMap<u64, String>,
    /// Addresses of the slots the base relocation table lists, sorted.
    pub relocations: Vec<u64>,
    /// The exception directory sorted by `begin`. Empty for PE32.
    pub pdata: Vec<RuntimeFunction>,
    /// The `IMAGE_LOAD_CONFIG_DIRECTORY`, if any.
    pub load_config: &'d [u8],
    pub functions: BTreeMap<u64, Function>,
    /// Functions known from a public symbol only, so without debug info.
    pub public_only: HashSet<u64>,
    /// Where each thunk jumps.
    thunks: HashMap<u64, Callee>,
    /// Code labels inside functions (`S_LABEL32`).
    pub labels: BTreeSet<u64>,
    /// Data symbols of modules (`S_LDATA32`, `S_GDATA32`) that lie in an executable section.
    pub data_symbols: BTreeSet<u64>,
    /// Decorated public names of functions, for calling-convention statistics.
    pub publics: HashMap<u64, String>,
    /// i386 frame data: function start to the bytes of arguments it expects on the stack.
    pub frame_params: HashMap<u64, u32>,
}

/// What the headers alone give, read generically over PE32 and PE32+.
struct Headers<'d> {
    sections: SectionTable<'d>,
    machine: u16,
    base: u64,
    bitness: u32,
    entry: u64,
    exports: Vec<u64>,
    slots: HashMap<u64, String>,
    relocations: Vec<u64>,
    pdata: Vec<RuntimeFunction>,
    load_config: &'d [u8],
    /// The GUID of the PDB the image was linked with.
    guid: Option<[u8; 16]>,
}

fn headers<'d, Pe: ImageNtHeaders>(data: &'d [u8]) -> Result<Headers<'d>> {
    let pe = PeFile::<Pe>::parse(data)?;
    let base = pe.relative_address_base();
    let bitness = if pe.is_64() { 64 } else { 32 };
    let sections = pe.section_table();
    let directories = pe.data_directories();
    let pointer = u64::from(bitness / 8);

    let mut slots = HashMap::new();
    let mut name_slots = |table: u32, thunks: object::read::pe::ImportThunkList<'d>, name: &dyn Fn(u32) -> Option<&'d [u8]>, dll: &[u8]| {
        let mut thunks = thunks;
        let mut slot = base + u64::from(table);
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            let imported = if thunk.is_ordinal() {
                Some(format!("{}#{}", String::from_utf8_lossy(dll), thunk.ordinal()))
            } else {
                name(thunk.address()).map(|name| String::from_utf8_lossy(name).into_owned())
            };
            slots.extend(imported.map(|imported| (slot, imported)));
            slot += pointer;
        }
    };
    if let Some(table) = pe.import_table()? {
        let mut descriptors = table.descriptors()?;
        while let Some(descriptor) = descriptors.next()? {
            let iat = descriptor.first_thunk.get(LE);
            // The lookup table survives binding; without one the unbound IAT holds the same names.
            let lookup = Some(descriptor.original_first_thunk.get(LE)).filter(|&rva| rva != 0).unwrap_or(iat);
            let dll = table.name(descriptor.name.get(LE)).unwrap_or_default();
            if let Ok(thunks) = table.thunks(lookup) {
                name_slots(iat, thunks, &|rva| table.hint_name(rva).ok().map(|(_, name)| name), dll);
            }
        }
    }
    if let Some(table) = pe.delay_load_import_table()? {
        let mut descriptors = table.descriptors()?;
        while let Some(descriptor) = descriptors.next()? {
            let dll = table.name(descriptor.dll_name_rva.get(LE)).unwrap_or_default();
            if let Ok(thunks) = table.thunks(descriptor.import_name_table_rva.get(LE)) {
                let iat = descriptor.import_address_table_rva.get(LE);
                name_slots(iat, thunks, &|rva| table.hint_name(rva).ok().map(|(_, name)| name), dll);
            }
        }
    }

    let mut relocations = Vec::new();
    if let Some(mut blocks) = directories.relocation_blocks(data, &sections)? {
        while let Some(block) = blocks.next()? {
            relocations.extend(
                block
                    .filter(|reloc| matches!(reloc.typ, IMAGE_REL_BASED_HIGHLOW | IMAGE_REL_BASED_DIR64))
                    .map(|reloc| base + u64::from(reloc.virtual_address)),
            );
        }
    }
    relocations.sort_unstable();

    let directory = |index: usize| directories.get(index).and_then(|directory| directory.data(data, &sections).ok()).unwrap_or_default();
    let u32_at = |bytes: &[u8]| u64::from(u32::from_le_bytes(bytes.try_into().unwrap()));
    let mut pdata: Vec<RuntimeFunction> = Vec::new();
    if bitness == 64 {
        pdata = directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .chunks_exact(12)
            .map(|entry| RuntimeFunction {
                begin: base + u32_at(&entry[0..4]),
                end: base + u32_at(&entry[4..8]),
                unwind: base + u32_at(&entry[8..12]),
            })
            .filter(|entry| entry.begin != base)
            .collect();
        pdata.sort_unstable_by_key(|entry| entry.begin);
    }

    // The directory entry of a PE32 image gives the load configuration's size as 64 whatever it
    // really is, so the structure's own leading size field is the one to go by.
    let load_config = directories
        .get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        .and_then(|directory| sections.pe_data_at(data, directory.virtual_address.get(LE)))
        .and_then(|bytes| bytes.get(..u32_at(bytes.get(..4)?) as usize))
        .unwrap_or_default();

    let exports = match pe.export_table()? {
        Some(table) => table.addresses().iter().map(|rva| base + u64::from(rva.get(LE))).collect(),
        None => Vec::new(),
    };
    Ok(Headers {
        sections,
        machine: pe.nt_headers().file_header().machine.get(LE).0,
        base,
        bitness,
        entry: base + u64::from(pe.nt_headers().optional_header().address_of_entry_point()),
        exports,
        slots,
        relocations,
        pdata,
        load_config,
        guid: pe.pdb_info()?.map(|info| info.guid()),
    })
}

/// A function entry the compiler emits for a C++ `catch`, `__finally`, `__except` filter or
/// unwind destructor. Named `` `f'::`1'::catch$0 `` in module symbols and `f$catch$0` or
/// `?catch$0@?0??f@@...` in publics: the marker follows punctuation and a number follows it.
fn is_funclet(name: &str) -> bool {
    ["catch$", "fin$", "filt$", "dtor$"].iter().any(|marker| {
        name.match_indices(marker).any(|(at, _)| {
            let boundary = name[..at].chars().next_back().is_none_or(|c| !c.is_alphanumeric() && c != '_');
            boundary && name[at + marker.len()..].starts_with(|c: char| c.is_ascii_digit())
        })
    })
}

/// Strips i386 name decoration from a C symbol: `_exit` for `exit`, `_ExitProcess@4`, `@f@8`.
fn undecorated(name: &str, bitness: u32) -> &str {
    if bitness == 64 || name.starts_with('?') {
        return name;
    }
    let name = name.strip_prefix(['_', '@']).unwrap_or(name);
    match name.rsplit_once('@') {
        Some((stem, bytes)) if !bytes.is_empty() && bytes.bytes().all(|b| b.is_ascii_digit()) => stem,
        _ => name,
    }
}

/// Functions that never return, by the name a Windows import or a statically linked runtime
/// function goes by. A PDB flags only functions compiled with debug info, so these names stand in
/// for the rest. Each is declared `__declspec(noreturn)` or `[[noreturn]]` in the Windows SDK,
/// UCRT, VC runtime or STL headers, with one exception noted below.
fn is_windows_noreturn(name: &str) -> bool {
    const NAMES: &[&str] = &[
        // kernel32, DECLSPEC_NORETURN in processthreadsapi.h and libloaderapi.h.
        "ExitProcess",
        "ExitThread",
        "FreeLibraryAndExitThread",
        // Annotated `__analysis_noreturn` only, so compilers emit code after it, but it terminates
        // the process by contract.
        "RaiseFailFastException",
        // UCRT. `exit`, `_exit` and `abort` are in the shared list.
        "_Exit",
        // End in `ExitThread`. mingw-w64 declares them noreturn, the UCRT headers do not.
        "_endthread",
        "_endthreadex",
        "quick_exit",
        "_invalid_parameter_noinfo_noreturn",
        "_invoke_watson",
        "terminate",
        "?terminate@@YAXXZ",
        // VC runtime.
        "_CxxThrowException",
        "__std_terminate",
        "longjmp",
        // Static runtime: the /GS and range check failure reports end in `__fastfail`.
        "__report_gsfailure",
        "__report_rangecheckfailure",
        // msvcp140: `[[noreturn]] void std::_Throw_Cpp_error(int)` and `_Throw_C_error`.
        "?_Throw_Cpp_error@std@@YAXH@Z",
        "?_Throw_C_error@std@@YAXH@Z",
    ];
    // msvcp140's `[[noreturn]] void std::_Xlength_error(const char*)` and its siblings
    // (`_Xout_of_range`, `_Xbad_alloc`, `_Xbad_function_call`, ...): `void __cdecl std::_X*`.
    NAMES.contains(&name) || (name.starts_with("?_X") && (name.contains("@std@@YAX") || name.contains("@std@@YGX")))
}

fn is_noreturn_name(name: &str) -> bool {
    is_runtime_noreturn(name) || is_windows_noreturn(name)
}

impl<'d> Image<'d> {
    /// Loads the image in `data` with the PDB at `pdb_path`, which must be the one it was linked with.
    pub fn load(data: &'d [u8], pdb_path: &Path) -> Result<Self> {
        let headers = match object::FileKind::parse(data)? {
            object::FileKind::Pe32 => headers::<object::pe::ImageNtHeaders32>(data)?,
            object::FileKind::Pe64 => headers::<object::pe::ImageNtHeaders64>(data)?,
            kind => bail!("unsupported file kind {kind:?}"),
        };
        let Headers { sections, base, bitness, .. } = headers;
        ensure!(
            [object::pe::IMAGE_FILE_MACHINE_I386.0, object::pe::IMAGE_FILE_MACHINE_AMD64.0].contains(&headers.machine),
            "unsupported machine {:#x}",
            headers.machine
        );

        let exec_sections: Vec<_> = sections
            .iter()
            .filter(|section| section.characteristics.get(LE).0 & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE).0 != 0)
            .filter(|section| section.virtual_size.get(LE) > 0)
            .collect();
        let exec: Vec<(u64, u64)> = exec_sections
            .iter()
            .map(|section| {
                let start = base + u64::from(section.virtual_address.get(LE));
                (start, start + u64::from(section.virtual_size.get(LE)))
            })
            .collect();
        let text = exec_sections
            .iter()
            .position(|section| section.raw_name() == b".text")
            .map(|index| exec[index])
            .context("no .text section")?;

        let in_exec = |addr: u64| exec.iter().any(|&(start, end)| addr >= start && addr < end);
        let exports = headers.exports.into_iter().filter(|&addr| in_exec(addr)).collect();
        let mut image = Image {
            data,
            sections,
            base,
            bitness,
            entry: headers.entry,
            exports,
            exec,
            text,
            slots: headers.slots,
            relocations: headers.relocations,
            pdata: headers.pdata,
            load_config: headers.load_config,
            functions: BTreeMap::new(),
            public_only: HashSet::new(),
            thunks: HashMap::new(),
            labels: BTreeSet::new(),
            data_symbols: BTreeSet::new(),
            publics: HashMap::new(),
            frame_params: HashMap::new(),
        };
        image.read_pdb(pdb_path, headers.guid)?;
        image.resolve_thunks();
        Ok(image)
    }

    pub fn in_exec(&self, addr: u64) -> bool {
        self.exec.iter().any(|&(start, end)| addr >= start && addr < end)
    }

    /// The image's bytes from `addr` to the end of its section's file data.
    fn bytes_from(&self, addr: u64) -> Option<&'d [u8]> {
        let rva = u32::try_from(addr.checked_sub(self.base)?).ok()?;
        self.sections.pe_data_at(self.data, rva)
    }

    /// The image's bytes at `[addr, addr + len)`, if they are all backed by the file.
    pub fn bytes(&self, addr: u64, len: u64) -> Option<&'d [u8]> {
        self.bytes_from(addr)?.get(..len as usize)
    }

    /// The pointer-sized value stored at `addr`.
    pub fn pointer(&self, addr: u64) -> Option<u64> {
        let bytes = self.bytes(addr, u64::from(self.bitness / 8))?;
        Some(if self.bitness == 64 {
            u64::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(bytes.try_into().unwrap()))
        })
    }

    /// The share of `.text` that lies outside every function and is not `int3`, `nop` or zero
    /// padding. A function without a size is taken to run up to the next function: its start
    /// is known, so the code after it is not anonymous.
    fn unnamed_percent(&self) -> u64 {
        let (text_start, text_end) = self.text;
        let (mut unnamed, mut at, mut sized) = (0, text_start, true);
        let ends = self.functions.range(text_start..text_end).map(|(&addr, function)| (addr, addr + function.size));
        for (start, end) in ends.chain([(text_end, text_end)]) {
            if start > at && sized {
                let gap = self.bytes(at, start - at).unwrap_or_default();
                unnamed += gap.iter().filter(|byte| !matches!(byte, 0xcc | 0x90 | 0x00)).count() as u64;
            }
            sized = end > start;
            at = at.max(end);
        }
        100 * unnamed / (text_end - text_start)
    }

    /// The `RUNTIME_FUNCTION` that begins exactly at `addr`.
    pub fn runtime_function(&self, addr: u64) -> Option<&RuntimeFunction> {
        self.pdata.binary_search_by_key(&addr, |entry| entry.begin).ok().map(|index| &self.pdata[index])
    }

    /// Fills in functions, labels and data symbols from the PDB.
    fn read_pdb(&mut self, pdb_path: &Path, image_guid: Option<[u8; 16]>) -> Result<()> {
        let file = std::fs::File::open(pdb_path).with_context(|| format!("opening {pdb_path:?}"))?;
        let mut pdb = pdb2::PDB::open(file)?;
        let guid = pdb.pdb_information()?.guid.to_bytes_le();
        ensure!(image_guid == Some(guid), "PDB does not belong to this image (GUID mismatch)");
        let address_map = pdb.address_map()?;
        let base = self.base;
        let va = |offset: pdb2::PdbInternalSectionOffset| offset.to_rva(&address_map).map(|rva| base + u64::from(rva.0));

        let mut procedures = Vec::new();
        let mut separated = Vec::new();
        let mut thunks = Vec::new();
        let mut funclets = Vec::new();
        let debug_information = pdb.debug_information()?;
        let mut modules = debug_information.modules()?;
        while let Some(module) = modules.next()? {
            let Some(info) = pdb.module_info(&module)? else { continue };
            let mut symbols = info.symbols()?;
            while let Some(symbol) = symbols.next()? {
                // Record kinds the reader does not know fail to parse; none of them matter here.
                match symbol.parse() {
                    Ok(SymbolData::Procedure(procedure)) => {
                        let name = procedure.name.to_string().into_owned();
                        // cv2pdb sets no flags, so GCC's `__stack_chk_fail` and the like go by name.
                        let noreturn = procedure.flags.never || is_runtime_noreturn(&name);
                        procedures.extend(va(procedure.offset).map(|addr| (addr, u64::from(procedure.len), name, noreturn)));
                    }
                    Ok(SymbolData::SeparatedCode(code)) => {
                        separated.extend(va(code.offset).zip(va(code.parent_offset)).map(|(addr, parent)| (addr, u64::from(code.len), parent)));
                    }
                    Ok(SymbolData::Thunk(thunk)) => {
                        thunks.extend(va(thunk.offset).map(|addr| (addr, u64::from(thunk.len), thunk.name.to_string().into_owned())));
                    }
                    Ok(SymbolData::Trampoline(trampoline)) if trampoline.tramp_type == TrampolineType::Incremental => {
                        thunks.extend(va(trampoline.thunk).map(|addr| (addr, u64::from(trampoline.size), String::new())));
                    }
                    // A label flagged "not reached" names a switch table, not code.
                    Ok(SymbolData::Label(label)) if !label.flags.notreached => {
                        let name = label.name.to_string();
                        let addr = va(label.offset);
                        if name.starts_with("__ehhandler$") || name.starts_with("__unwindfunclet$") {
                            funclets.extend(addr.map(|addr| (addr, name.into_owned())));
                        }
                        self.labels.extend(addr);
                    }
                    Ok(SymbolData::Data(data)) => self.data_symbols.extend(va(data.offset).filter(|&addr| self.in_exec(addr))),
                    _ => {}
                }
            }
        }

        let mut publics = Vec::new();
        let globals = pdb.global_symbols()?;
        let mut symbols = globals.iter();
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(SymbolData::Public(public)) if public.function => {
                    publics.extend(va(public.offset).map(|addr| (addr, public.name.to_string().into_owned())));
                }
                _ => {}
            }
        }
        if let Some(frames) = pdb.frame_table().ok().filter(|_| self.bitness == 32) {
            let mut frames = frames.iter();
            while let Ok(Some(frame)) = frames.next() {
                if let Some(rva) = frame.code_start.to_rva(&address_map).filter(|_| frame.is_function_start) {
                    self.frame_params.entry(base + u64::from(rva.0)).or_insert(frame.params_size);
                }
            }
        }

        // Identical code folding leaves several names at one address; the first non-fragment wins,
        // as it does for ELF aliases.
        let bitness = self.bitness;
        let add = |functions: &mut BTreeMap<u64, Function>, function: Function| {
            if !self.exec.iter().any(|&(start, end)| function.addr >= start && function.addr < end) {
                return false;
            }
            match functions.get(&function.addr) {
                Some(existing) if !existing.fragment && existing.noreturn >= function.noreturn => false,
                Some(existing) if existing.fragment && function.fragment => false,
                _ => functions.insert(function.addr, function).is_none(),
            }
        };
        let mut functions = BTreeMap::new();
        for (addr, size, name, noreturn) in procedures {
            let fragment = is_funclet(&name);
            add(&mut functions, Function { addr, size, name, fragment, noreturn, thunk: false });
        }
        for (addr, size, parent) in separated {
            let name = format!("{}$sepcode", functions.get(&parent).map_or("", |function| function.name.as_str()));
            add(&mut functions, Function { addr, size, name, fragment: true, noreturn: false, thunk: false });
        }
        for (addr, size, name) in thunks {
            if !functions.contains_key(&addr) {
                add(&mut functions, Function { addr, size, name, fragment: true, noreturn: false, thunk: true });
            }
        }
        for (addr, name) in publics {
            self.publics.entry(addr).or_insert_with(|| name.clone());
            if functions.contains_key(&addr) {
                continue;
            }
            let size = self.runtime_function(addr).map_or(0, |entry| entry.end - entry.begin);
            let noreturn = is_noreturn_name(undecorated(&name, bitness));
            let function = Function { addr, size, fragment: is_funclet(&name), name, noreturn, thunk: false };
            if add(&mut functions, function) {
                self.public_only.insert(addr);
            }
        }
        // i386 C++ exception handling keeps catch blocks inside their function, but emits its
        // per-function handler stub (`__ehhandler$f`) and unwind funclets (`__unwindfunclet$f$0`)
        // after it, outside every length, as bare labels. Each runs to the next label or function.
        for (addr, name) in funclets {
            let covered = functions.range(..=addr).next_back().is_some_and(|(_, function)| addr < function.addr + function.size);
            let section_end = self.exec.iter().find(|&&(start, end)| addr >= start && addr < end).map(|&(_, end)| end);
            let Some(limit) = section_end.filter(|_| !covered) else { continue };
            let next_function = functions.range(addr + 1..).next().map_or(limit, |(&next, _)| next);
            let next_label = self.labels.range(addr + 1..).next().copied().unwrap_or(limit);
            let end = limit.min(next_function).min(next_label);
            let padding = self.bytes(addr, end - addr).map_or(0, |bytes| bytes.iter().rev().take_while(|&&byte| byte == 0xcc).count());
            let size = end - addr - padding as u64;
            add(&mut functions, Function { addr, size, name, fragment: true, noreturn: false, thunk: false });
        }
        self.functions = functions;
        Ok(())
    }

    /// Where the lone jump at `addr` goes, if that is what the code there is.
    fn jump_at(&self, addr: u64) -> Option<Callee> {
        let instr = Decoder::with_ip(self.bitness, self.bytes_from(addr)?, addr, DecoderOptions::NONE).decode();
        match instr.flow_control() {
            FlowControl::UnconditionalBranch => Some(Callee::Direct(instr.near_branch_target())),
            FlowControl::IndirectBranch if instr.is_ip_rel_memory_operand() => Some(Callee::Slot(instr.ip_rel_memory_address())),
            FlowControl::IndirectBranch if self.bitness == 32 && x86::is_absolute_memory(&instr) => Some(Callee::Slot(instr.memory_displacement64())),
            _ => None,
        }
    }

    /// Records where each thunk jumps, and marks as thunks the functions without debug info
    /// that are a lone jump through an import slot, which is how an import library provides
    /// `name` next to `__imp_name`.
    fn resolve_thunks(&mut self) {
        let candidates: Vec<u64> =
            self.functions.values().filter(|function| function.thunk || self.public_only.contains(&function.addr)).map(|function| function.addr).collect();
        for addr in candidates {
            match self.jump_at(addr) {
                Some(Callee::Slot(slot)) if self.slots.contains_key(&slot) => {
                    self.thunks.insert(addr, Callee::Slot(slot));
                }
                Some(Callee::Direct(target)) if self.functions[&addr].thunk => {
                    self.thunks.insert(addr, Callee::Direct(target));
                }
                // A thunk record over anything else, such as a virtual-call or adjustor thunk,
                // stays a neutral fragment with no known target.
                _ => continue,
            }
            let function = self.functions.get_mut(&addr).unwrap();
            (function.fragment, function.thunk) = (true, true);
        }
        let noreturn: Vec<u64> = self
            .thunks
            .keys()
            .copied()
            .filter(|&addr| match self.resolve(Callee::Direct(addr)) {
                Callee::Direct(target) => self.functions.get(&target).is_some_and(|function| function.noreturn),
                Callee::Slot(slot) => self.slots.get(&slot).is_some_and(|name| is_noreturn_name(name)),
            })
            .collect();
        for addr in noreturn {
            self.functions.get_mut(&addr).unwrap().noreturn = true;
        }
    }

    /// Follows thunks from a call's target to the function or import slot finally reached.
    pub(super) fn resolve(&self, mut callee: Callee) -> Callee {
        for _ in 0..4 {
            match callee {
                Callee::Direct(target) => match self.thunks.get(&target) {
                    Some(&next) => callee = next,
                    None => break,
                },
                Callee::Slot(_) => break,
            }
        }
        callee
    }

    /// The instructions of `[start, end)`, decoded linearly.
    pub fn decode(&self, start: u64, end: u64) -> impl Iterator<Item = Instruction> + use<'d> {
        let bytes = self.bytes(start, end - start).unwrap_or_default();
        Decoder::with_ip(self.bitness, bytes, start, DecoderOptions::NONE).into_iter()
    }

    /// The parts of the function `[start, end)` that are code, in order.
    ///
    /// MSVC emits a function's switch tables (jump tables, and the byte tables that map case
    /// values to entries) after its last instruction but inside its length. Three things mark
    /// where they begin, and the earliest one ends the code:
    ///
    /// - The PDB has an unnamed `S_LDATA32` at each table.
    /// - On i386 every jump-table entry carries a base relocation, while no instruction can
    ///   have one on its first byte or outside its displacement and immediate. A relocation the
    ///   instruction at hand does not explain is therefore data.
    /// - On x86-64 the dispatch reads the table as an RVA off a register holding the image base:
    ///   `lea rdx, [rip + __ImageBase]` then `mov ecx, dword ptr [rdx + rax*4 + table_rva]`.
    ///   A table named that way ahead of the instruction is data. This is what covers functions
    ///   the PDB has no symbols for.
    ///
    /// Data runs to the end of the function, unless a code label follows it: hand-written
    /// assembly such as the C runtime's `memcpy` puts tables between its code paths.
    pub fn code_ranges(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let Some(bytes) = self.bytes(start, end - start) else { return Vec::new() };
        let mut ranges = Vec::new();
        let mut at = start;
        let mut has_image_base = false;
        while at < end {
            let mut stop = self.data_symbols.range(at..end).next().copied().unwrap_or(end);
            let mut decoder = Decoder::with_ip(self.bitness, &bytes[(at - start) as usize..(stop - start) as usize], at, DecoderOptions::NONE);
            while decoder.can_decode() && decoder.ip() < stop {
                let ip = decoder.ip();
                let instr = decoder.decode();
                if self.bitness == 32 {
                    let offsets = decoder.get_constant_offsets(&instr);
                    let explained = |slot: u64| {
                        (offsets.has_displacement() && slot == ip + offsets.displacement_offset() as u64)
                            || (offsets.has_immediate() && slot == ip + offsets.immediate_offset() as u64)
                    };
                    let first = self.relocations.partition_point(|&slot| slot < ip);
                    if self.relocations[first..].iter().take_while(|&&slot| slot < decoder.ip()).any(|&slot| !explained(slot)) {
                        stop = ip;
                    }
                } else if let Some(table) = self.based_table(&instr, &mut has_image_base).filter(|&table| table > ip && table < stop) {
                    stop = table;
                }
            }
            if stop > at {
                ranges.push((at, stop));
            }
            at = self.labels.range(stop.saturating_add(1).min(end)..end).next().copied().unwrap_or(end);
        }
        ranges
    }

    /// Jump tables as the image and its PDB show them, as `(address, entry count)`.
    ///
    /// This is for MSVC output, which keeps a function's jump tables in `.text` inside its
    /// length. A table is listed when the function's own code dispatches through it, with
    /// `jmp dword ptr [index*4 + table]` on i386 or `mov r32, dword ptr [base + index*4 +
    /// table_rva]` on x86-64, and it starts in the function's data. It ends at the next table
    /// or PDB data symbol or at the end of the data. On i386 it also ends at the first entry
    /// without a base relocation, since every real entry has one.
    pub fn switch_tables(&self) -> Vec<(u64, u64)> {
        let mut tables = Vec::new();
        for function in self.functions.values().filter(|function| function.size > 0 && !function.thunk) {
            let (start, end) = (function.addr, function.addr + function.size);
            let code = self.code_ranges(start, end);
            let in_data = |addr: u64| addr >= start && addr < end && !code.iter().any(|&(s, e)| addr >= s && addr < e);
            if code.iter().map(|&(s, e)| e - s).sum::<u64>() == function.size {
                continue;
            }
            let mut has_image_base = false;
            let mut starts: BTreeSet<u64> = BTreeSet::new();
            for instr in code.iter().flat_map(|&(s, e)| self.decode(s, e)) {
                let table = if self.bitness == 64 {
                    self.based_table(&instr, &mut has_image_base).filter(|_| instr.mnemonic() == Mnemonic::Mov && instr.memory_index_scale() == 4)
                } else {
                    let dispatch = instr.flow_control() == FlowControl::IndirectBranch
                        && instr.op0_kind() == OpKind::Memory
                        && instr.memory_base() == Register::None
                        && instr.memory_index_scale() == 4;
                    dispatch.then(|| instr.memory_displacement64())
                };
                starts.extend(table.filter(|&table| in_data(table)));
            }
            for &table in &starts {
                // Where this table must end at the latest: the next table, data symbol or code.
                let mut limit = table + 4;
                while limit < end && in_data(limit) && !starts.contains(&limit) && !self.data_symbols.contains(&limit) {
                    limit += 1;
                }
                let mut entries = (limit - table) / 4;
                if self.bitness == 32 {
                    entries = (0..entries).take_while(|index| self.relocations.binary_search(&(table + 4 * index)).is_ok()).count() as u64;
                }
                tables.push((table, entries));
            }
        }
        tables
    }

    /// The address of the table an x86-64 instruction indexes off the image base, as in
    /// `mov ecx, dword ptr [rdx + rax*4 + table_rva]`. Believed only once `has_image_base` is
    /// set, which this does on seeing `lea reg, [rip + __ImageBase]`.
    pub fn based_table(&self, instr: &Instruction, has_image_base: &mut bool) -> Option<u64> {
        if instr.is_ip_rel_memory_operand() {
            *has_image_base |= instr.mnemonic() == Mnemonic::Lea && instr.ip_rel_memory_address() == self.base;
            return None;
        }
        let indexed = instr.memory_base() != Register::None && instr.memory_index() != Register::None && instr.memory_displ_size() >= 4;
        let reads = (0..instr.op_count()).any(|op| instr.op_kind(op) == OpKind::Memory);
        (*has_image_base && indexed && reads).then(|| self.base.wrapping_add(instr.memory_displacement64())).filter(|&table| self.in_exec(table))
    }

    /// Decodes the code of one function, with every callee followed through thunks.
    fn scan(&self, function: &Function) -> Option<Scan> {
        let (start, end) = (function.addr, function.addr + function.size);
        self.bytes(start, function.size)?;
        let mut scan = Scan { data_bytes: function.size, ..Scan::default() };
        for (start, end) in self.code_ranges(start, end) {
            let piece = x86::scan(self.bytes(start, end - start)?, start, self.bitness);
            scan.instructions += piece.instructions;
            scan.undecodable_bytes += piece.undecodable_bytes;
            scan.data_bytes -= end - start;
            scan.calls.extend(piece.calls.into_iter().map(|(at, callee)| (at, self.resolve(callee))));
            scan.final_call = piece.final_call;
        }
        Some(scan)
    }
}

pub fn extract(binary_path: &Path, binary_data: &[u8], pdb_path: &Path) -> Result<Truth> {
    let image = Image::load(binary_data, pdb_path)?;
    let unnamed = image.unnamed_percent();
    ensure!(unnamed <= MAX_UNNAMED_PERCENT, "{unnamed}% of .text is code the PDB has no function for");
    let noreturn_addrs: HashSet<u64> = image.functions.values().filter(|function| function.noreturn).map(|function| function.addr).collect();
    // A thunk's one instruction is counted, but its jump is not a call and it has no callers of
    // its own to classify: calls to it were resolved to its target.
    let scans = image.functions.values().filter_map(|function| image.scan(function));
    let callees = Callees {
        noreturn_addrs: &noreturn_addrs,
        stubs: &HashMap::new(),
        slots: &image.slots,
        is_noreturn_import: &is_noreturn_name,
        widen_slots: true,
    };
    let calls = classify(scans, &callees);
    Ok(Truth {
        name: binary_path.file_name().unwrap().to_string_lossy().into_owned(),
        exec: image.exec.clone(),
        text: image.text,
        instructions: calls.instructions,
        noreturn_calls: calls.noreturn_calls,
        terminal_calls: calls.terminal_calls,
        noreturn_imports: calls.noreturn_imports.into_iter().collect(),
        undecodable_bytes: calls.undecodable_bytes,
        data_bytes: calls.data_bytes,
        functions: image.functions.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funclets_are_recognised_by_their_numbered_marker() {
        assert!(is_funclet("`icu_56::UDataPathIterator::UDataPathIterator'::`1'::dtor$0"));
        assert!(is_funclet("main$catch$0"));
        assert!(is_funclet("?fin$1@?0??f@@YAXXZ@4HA"));
        assert!(is_funclet("`anonymous namespace'::run$filt$0"));
        // Rust mangling uses `$LT$` and friends, and words may merely end in a marker.
        assert!(!is_funclet("core::ptr::drop_in_place$LT$coffin$GT$"));
        assert!(!is_funclet("begin$0"));
        assert!(!is_funclet("catch_all"));
    }

    #[test]
    fn i386_decoration_is_stripped_for_c_names_only() {
        assert_eq!(undecorated("_exit", 32), "exit");
        assert_eq!(undecorated("__exit", 32), "_exit");
        assert_eq!(undecorated("_ExitProcess@4", 32), "ExitProcess");
        assert_eq!(undecorated("@fast@8", 32), "fast");
        assert_eq!(undecorated("?terminate@@YAXXZ", 32), "?terminate@@YAXXZ");
        assert_eq!(undecorated("_exit", 64), "_exit");
    }

    #[test]
    fn noreturn_names_cover_both_runtimes() {
        assert!(is_noreturn_name("ExitProcess"));
        assert!(is_noreturn_name("?_Xlength_error@std@@YAXPEBD@Z"));
        assert!(is_noreturn_name("__cxa_throw"));
        assert!(!is_noreturn_name("TerminateProcess"));
        assert!(!is_noreturn_name("_purecall"));
        assert!(!is_noreturn_name("_wassert"));
    }
}
