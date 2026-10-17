//! Ghidra's decompiler engine as an in-process library, fed by recore instead of by Ghidra.
//!
//! A [`Session`] wraps one decompiler `Architecture` for a [`Target`]. It reads bytes from the
//! sections it is given, never from a file, and learns from the caller what recore already
//! knows: function starts, names, imports, strings, functions that never return, tail calls and
//! jump-table targets.
//!
//! A session is single-threaded but independent of every other session, so use one per thread.
//! Results can depend on what a session decompiled earlier, because the globals a function
//! refers to become symbols that later functions see.

pub mod dwarf;
pub mod facts;
mod ffi;
pub mod flow;
pub mod isolate;
pub mod pdb;
pub mod prototypes;
mod structs;
pub mod types;

// The engine is only reached through the shim, so name the crate to keep it in the link.
extern crate ghidra_decompiler_sys;

use std::ffi::{CStr, CString, c_char};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use anyhow::{Context, Result, bail};
use recore::Image;
use recore::image::{Compiler, Format, Machine};
use recore::report::Analysis;
use recore::structs::{Layout, Recovered, Slot};
use std::collections::BTreeMap;

pub use facts::Facts;
pub use flow::Flow;
pub use structs::{ObjectReport, StructReport};

/// The allocator the engine's C++ side is built to use. A program that decompiles a lot does
/// well to make it the Rust side's too.
pub use mimalloc::MiMalloc;

/// Bytes mapped at a virtual address.
pub struct Section<'a> {
    pub addr: u64,
    pub data: &'a [u8],
    /// The decompiler reads constants and jump tables only out of read-only memory.
    pub readonly: bool,
    /// Holds instructions. While one function is decompiled, the entry points of all other
    /// declared functions in such sections are hidden, so flow cannot leak into them.
    pub code: bool,
}

/// The processor and compiler conventions a session decompiles for. Each is one of Ghidra's
/// language ids plus a compiler spec, which fixes pointer size, calling conventions and which
/// side cleans up the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// 32-bit x86 with Microsoft conventions: `__stdcall` by default, with `__cdecl`,
    /// `__fastcall` and `__thiscall` recognised per function.
    X86Windows,
    /// 32-bit x86 with the System V conventions.
    X86Gcc,
    /// x86-64 with the Microsoft x64 convention.
    X86_64Windows,
    /// x86-64 with the System V convention.
    X86_64Gcc,
    Aarch64,
    /// The 8051 as Keil's C51 compiles for it, banked or not: code at `bank << 16 | address`.
    I8051,
    /// The 8051 as SDCC compiles for it.
    I8051Sdcc,
    /// An ARM Cortex-M, in Thumb code.
    Thumb,
    /// 32-bit ARM code, A32 and Thumb, with the EABI's conventions.
    Arm,
}

/// Where SDCC keeps the frame pointer of an 8051 program whose functions have their arguments
/// and variables on the stack: the byte of internal memory that functions save, load from
/// `SP` and restore. SDCC has no register to spare for it.
fn frame_pointer(image: &Image) -> Option<u8> {
    // PUSH direct; MOV direct, SP
    let saves = |code: &[u8]| match *code {
        [0xc0, pushed, 0x85, 0x81, loaded] if pushed == loaded && pushed < 0x80 => Some(pushed),
        _ => None,
    };
    let mut counts = [0usize; 0x80];
    for section in image.sections.iter().filter(|section| section.executable) {
        section.data.windows(5).filter_map(saves).for_each(|direct| counts[direct as usize] += 1);
    }
    // One function may keep some other byte so. The frame pointer is kept by more.
    let (direct, &most) = counts.iter().enumerate().max_by_key(|&(_, count)| *count)?;
    (most >= 2).then_some(direct as u8)
}

impl Target {
    /// The target an image was built for.
    pub fn of(image: &Image) -> Target {
        match (image.machine, image.format) {
            (Machine::X86, Format::Pe) => Target::X86Windows,
            (Machine::X86, Format::Elf | Format::MachO | Format::Raw) => Target::X86Gcc,
            (Machine::X86_64, Format::Pe) => Target::X86_64Windows,
            // macOS follows the System V convention on x86-64.
            (Machine::X86_64, Format::Elf | Format::MachO | Format::Raw) => Target::X86_64Gcc,
            (Machine::Aarch64, _) => Target::Aarch64,
            (Machine::I8051, _) if image.compiler == Some(Compiler::Sdcc) => Target::I8051Sdcc,
            (Machine::I8051, _) => Target::I8051,
            (Machine::Thumb, _) => Target::Thumb,
            (Machine::Arm, _) => Target::Arm,
        }
    }

    /// Ghidra's `processor:endian:size:variant:compiler` id.
    fn language(self) -> &'static CStr {
        match self {
            Target::X86Windows => c"x86:LE:32:default:windows",
            Target::X86Gcc => c"x86:LE:32:default:gcc",
            Target::X86_64Windows => c"x86:LE:64:default:windows",
            Target::X86_64Gcc => c"x86:LE:64:default:gcc",
            Target::Aarch64 => c"AARCH64:LE:64:v8A:default",
            Target::I8051 => c"8051:BE:24:cip-51:default",
            Target::I8051Sdcc => c"8051:BE:24:cip-51:sdcc",
            Target::Thumb => c"ARM:LE:32:Cortex:default",
            Target::Arm => c"ARM:LE:32:v7:default",
        }
    }

    /// The compiler spec file among the language files.
    fn compiler_spec(self) -> &'static str {
        match self {
            Target::X86Windows => "x86win.cspec",
            Target::X86Gcc => "x86gcc.cspec",
            Target::X86_64Windows => "x86-64-win.cspec",
            Target::X86_64Gcc => "x86-64-gcc.cspec",
            Target::Aarch64 => "AARCH64.cspec",
            Target::I8051 => "keil-cx51.cspec",
            Target::I8051Sdcc => "sdcc-mcs51.cspec",
            Target::Thumb | Target::Arm => "ARM.cspec",
        }
    }

    /// The call fixups of the compiler spec, as (function name, fixup name). The engine reads
    /// the fixups themselves from the spec but leaves it to its host to apply them by name.
    fn call_fixups(self) -> Vec<(String, String)> {
        let attribute = |line: &str, tag: &str| Some(line.trim().strip_prefix(tag)?.split('"').nth(1)?.to_string());
        let mut fixups = Vec::new();
        let mut current = None;
        let spec = languages::FILES.iter().find(|(name, _)| *name == self.compiler_spec()).map_or(&[][..], |(_, bytes)| bytes);
        for line in String::from_utf8_lossy(spec).lines() {
            if let Some(name) = attribute(line, "<callfixup name=") {
                current = Some(name);
            } else if let (Some(target), Some(fixup)) = (attribute(line, "<target name="), &current) {
                fixups.push((target, fixup.clone()));
            }
        }
        fixups
    }

    /// Whether a call passes just the parameters its callee was found to read, and not also
    /// whatever else the call site has put in argument registers. GCC and clang keep a caller's
    /// own values in those registers across a call to a function known to leave them alone,
    /// so there the callee is the better witness, on 32-bit ARM as well. MSVC does not, and
    /// 32-bit x86 code passes on the stack, where a function may be passed more than it reads:
    /// against PDB signatures, taking the callee's word alone gets 87.5% of 64-bit parameter
    /// lists right and taking it as the least gets 89.8%.
    fn callers_pass_what_is_read(self) -> bool {
        matches!(self, Target::X86_64Gcc | Target::Aarch64 | Target::Arm)
    }

    /// The address spaces the target has besides the one its code is in: the address recore
    /// gives the first byte of each, and the engine's name for the space.
    fn spaces(self) -> &'static [(u64, &'static CStr)] {
        use recore::hardware::BIT;
        use recore::i8051::{IDATA, SFR, XDATA};
        match self {
            Target::I8051 | Target::I8051Sdcc => &[(XDATA, c"EXTMEM"), (IDATA, c"INTMEM"), (SFR, c"SFR"), (BIT, c"BITS")],
            _ => &[],
        }
    }

    /// Whether code that runs from the end of one function into the start of the next is meant
    /// to, and the first function ends by calling the second. 8051 code shares the end of a
    /// function this way, and what recore makes of it is two functions. Elsewhere such code
    /// follows a call that never returns, and is none of the function's.
    fn functions_run_on(self) -> bool {
        matches!(self, Target::I8051 | Target::I8051Sdcc)
    }

    /// Whether a result comes back in the register the first argument goes in: `R7` for C51,
    /// `DPL` for SDCC.
    fn result_in_first_argument(self) -> bool {
        matches!(self, Target::I8051 | Target::I8051Sdcc)
    }

    /// Whether a structure of more than 16 bytes goes on the stack whatever registers are free,
    /// as x86-64 System V passes it.
    fn passes_aggregates_on_stack(self) -> bool {
        matches!(self, Target::X86_64Gcc)
    }

    pub fn pointer_bytes(self) -> usize {
        match self {
            Target::X86Windows | Target::X86Gcc | Target::Thumb | Target::Arm => 4,
            Target::X86_64Windows | Target::X86_64Gcc | Target::Aarch64 => 8,
            Target::I8051 | Target::I8051Sdcc => 2,
        }
    }
}

/// How far the engine takes a function. These are Ghidra's own "simplification styles".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Style {
    /// The full pipeline, ending in structured C.
    #[default]
    Decompile,
    /// Stops before type recovery and control-flow structuring. Enough for jump tables; this is
    /// what Ghidra's switch analysis runs. No C text.
    Normalize,
    /// The pipeline Ghidra's parameter-ID analysis runs to recover prototypes. No C text.
    ParamId,
}

/// One parameter of a recovered prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// The decompiler's name for the data type, such as `undefined8` or `char *`.
    pub type_name: String,
    /// Register name (`RDI`, `XMM0_Qa`) or `stack:0x8`.
    pub storage: String,
    pub size: u32,
}

/// An indirect jump and the table of addresses the decompiler used for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    pub jump: u64,
    /// In table order, duplicates included.
    pub targets: Vec<u64>,
}

/// A variable of a decompiled function: a parameter, a stack variable or a temporary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Local {
    /// As the C spells it.
    pub name: String,
    /// The storage that identifies the variable when the function is decompiled again, as
    /// [`Session::name_local`] takes it.
    pub place: String,
}

/// The result of decompiling one function.
#[derive(Debug, Clone)]
pub struct Decompiled {
    /// Empty unless the session's style is [`Style::Decompile`].
    pub c_text: String,
    pub params: Vec<Param>,
    pub return_type: String,
    pub returns_value: bool,
    /// Control flow ran into bytes that do not decode, usually a missed non-returning call.
    pub bad_data: bool,
    /// Control flow hit an instruction the processor spec has no semantics for.
    pub unimplemented: bool,
    pub jump_tables: Vec<JumpTable>,
    /// The function's data flow, if [`Session::keep_flow`] asked for it.
    pub flow: Option<Flow>,
    pub locals: Vec<Local>,
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Instruction {
    pub addr: u64,
    pub len: u64,
    /// Mnemonic and operands as Ghidra's listing prints them, or `(bad)` for bytes that do not
    /// decode.
    pub text: String,
    /// Its raw p-code, one operation each, when asked for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pcode: Vec<String>,
}

impl Decompiled {
    pub fn param_count(&self) -> usize {
        self.params.len()
    }
}

/// What [`Session::set_structs`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Converged {
    /// New structs, holders and names of fields took effect in this session.
    InPlace,
    /// A struct the session holds has another layout now. The engine cannot redefine a type,
    /// so only a new session shows it; this one is as it was.
    Restart,
}

/// A program loaded into the decompiler.
pub struct Session {
    raw: NonNull<ffi::RdSession>,
    target: Target,
    /// Jump tables of recore's, by function, that the engine is first left to read itself:
    /// see [`Facts::engine_tables`].
    engine_tables: std::collections::HashMap<u64, Vec<JumpTable>>,
    /// The structs recovered so far. The shim's hook holds this pointer, which the session
    /// owns and touches nowhere else.
    structs: NonNull<structs::Registry>,
}

// A session owns all of its C++ state. The engine's globals are written only while a session
// is created and while C is printed, and the shim takes a lock around both.
unsafe impl Send for Session {}

/// The engine's language files, which are part of the program: see `build.rs`.
mod languages {
    include!(concat!(env!("OUT_DIR"), "/languages.rs"));
}

/// A directory holding the language files, which the engine reads by path. They are written
/// out the first time, under the user's cache directory, and again only when they change.
pub fn vendored_spec_dir() -> Result<PathBuf> {
    let cache = match (std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME")) {
        (Some(cache), _) => PathBuf::from(cache),
        (None, Some(home)) => PathBuf::from(home).join(".cache"),
        (None, None) => std::env::temp_dir(),
    };
    let dir = cache.join(format!("recore/languages-{:016x}", languages::ID));
    // One thread of this process writes; the process number keeps other processes apart.
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _writing = WRITING.lock();
    if dir.is_dir() {
        return Ok(dir);
    }
    // Written beside it and renamed, so that no process finds half of the files.
    let partial = dir.with_extension(format!("{}.partial", std::process::id()));
    std::fs::create_dir_all(&partial).with_context(|| format!("writing the language files to {partial:?}"))?;
    for (name, bytes) in languages::FILES {
        std::fs::write(partial.join(name), bytes)?;
    }
    if std::fs::rename(&partial, &dir).is_err() {
        // Another process got there first.
        std::fs::remove_dir_all(&partial)?;
    }
    Ok(dir)
}

/// Runs a shim call that reports failure through an error buffer.
fn check(call: impl FnOnce(*mut c_char, usize) -> bool) -> Result<()> {
    let mut err = [0 as c_char; 512];
    if call(err.as_mut_ptr(), err.len()) {
        return Ok(());
    }
    bail!("{}", unsafe { CStr::from_ptr(err.as_ptr()) }.to_string_lossy())
}

impl Session {
    /// Loads `sections` using the language files in `spec_dir`. The first session of the process
    /// decides the directory; later sessions reuse it.
    pub fn new(spec_dir: &Path, target: Target, sections: &[Section]) -> Result<Session> {
        let spec_dir = CString::new(spec_dir.as_os_str().as_encoded_bytes())?;
        let raw_sections: Vec<ffi::RdSection> = sections
            .iter()
            .map(|s| ffi::RdSection { addr: s.addr, data: s.data.as_ptr(), len: s.data.len(), readonly: s.readonly.into(), code: s.code.into() })
            .collect();
        let mut raw = std::ptr::null_mut();
        check(|err, len| {
            // The shim copies the section bytes, so nothing borrowed outlives this call.
            raw = unsafe { ffi::rd_session_new(spec_dir.as_ptr(), target.language().as_ptr(), raw_sections.as_ptr(), raw_sections.len(), err, len) };
            !raw.is_null()
        })?;
        let raw = NonNull::new(raw).expect("checked above");
        unsafe { ffi::rd_keep_prototypes_exact(raw.as_ptr(), target.callers_pass_what_is_read().into()) };
        unsafe { ffi::rd_functions_run_on(raw.as_ptr(), target.functions_run_on().into()) };
        unsafe { ffi::rd_result_in_first_argument(raw.as_ptr(), target.result_in_first_argument().into()) };
        unsafe { ffi::rd_stack_aggregates(raw.as_ptr(), target.passes_aggregates_on_stack().into()) };
        // The session frees the engine's side if a space is not there.
        let structs = NonNull::from(Box::leak(Box::<structs::Registry>::default()));
        unsafe { ffi::rd_set_struct_hooks(raw.as_ptr(), structs.as_ptr().cast(), structs::plan_hook, structs::wrapped_hook) };
        let session = Session { raw, target, engine_tables: Default::default(), structs };
        for &(base, name) in target.spaces() {
            check(|err, len| unsafe { ffi::rd_map_space(raw.as_ptr(), base, name.as_ptr(), err, len) != 0 })?;
        }
        Ok(session)
    }

    /// Loads a recore image as it looks after relocation, with the vendored language files, and
    /// declares the imports its code calls, with prototypes for the well-known ones.
    pub fn from_image(image: &Image, analysis: &Analysis) -> Result<Session> {
        let mut session = Session::load(image)?;
        session.add_imports(image, analysis)?;
        Ok(session)
    }

    /// Loads a recore image as it looks after relocation, with the vendored language files.
    /// This needs no analysis and takes tens of milliseconds, so it can run alongside one.
    pub fn load(image: &Image) -> Result<Session> {
        let loaded = facts::loaded(image);
        let sections: Vec<Section> = loaded.iter().map(|l| Section { addr: l.addr, data: &l.data, readonly: l.constant, code: l.code }).collect();
        let session_target = Target::of(image);
        let mut session = Session::new(&vendored_spec_dir()?, session_target, &sections)?;
        // Banked code: every bank shows the code all banks share, which the image holds once,
        // as bank 0, and a trampoline entry stands for the function it reaches.
        let banking = &image.banking;
        let mut banks: Vec<u64> = image.sections.iter().filter(|section| section.executable && !banking.common.is_empty()).map(|section| section.addr >> 16).collect();
        banks.sort_unstable();
        banks.dedup();
        for bank in banks.into_iter().filter(|&bank| bank != 0) {
            for &(start, end) in &banking.common {
                session.mirror(bank << 16 | start, end - start, start);
            }
        }
        for (&entry, &target) in &banking.trampolines {
            session.redirect(entry, target);
        }
        // Through the frame pointer a function reaches what it was passed on the stack and
        // what it keeps there, which the engine follows only if a call leaves the pointer be.
        if session_target == Target::I8051Sdcc
            && let Some(direct) = frame_pointer(image)
        {
            session.register_at(recore::i8051::IDATA + u64::from(direct))?;
        }
        // The engine decodes 32-bit ARM code by its TMode: A32, or Thumb where it is 1.
        for (index, &(start, set)) in image.instruction_sets.iter().enumerate() {
            let end = image.instruction_sets.get(index + 1).map_or(0, |&(next, _)| next);
            session.set_context(c"TMode", start, end, u32::from(set == recore::image::InstructionSet::Thumb))?;
        }
        Ok(session)
    }

    /// Gives the context variable `name` the value `value` over the code from `start` up to
    /// `end`, or to the end of the address space where `end` is 0.
    pub fn set_context(&mut self, name: &CStr, start: u64, end: u64, value: u32) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_set_context(self.raw.as_ptr(), name.as_ptr(), start, end, value, err, len) != 0 })
    }

    /// Says that the `len` bytes of code at `addr` are those at `target`: reading them reads
    /// those, and a jump or call into them goes to the code at `target`.
    pub fn mirror(&mut self, addr: u64, len: u64, target: u64) {
        unsafe { ffi::rd_mirror(self.raw.as_ptr(), addr, len, target) }
    }

    /// Says that the byte of memory at `addr` is the running function's own, as a register is,
    /// and no global variable: what a function keeps there, a function it calls leaves there.
    pub fn register_at(&mut self, addr: u64) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_register_at(self.raw.as_ptr(), addr, err, len) != 0 })
    }

    /// Says that a jump or call to `from` goes to `to`, because the code at `from` only passes
    /// control on.
    pub fn redirect(&mut self, from: u64, to: u64) {
        unsafe { ffi::rd_redirect(self.raw.as_ptr(), from, to) }
    }

    /// Declares the imports the code calls, with prototypes for the well-known ones.
    pub fn add_imports(&mut self, image: &Image, analysis: &Analysis) -> Result<()> {
        for import in &analysis.imports {
            self.add_import(import.slot, &import.name, import.noreturn)?;
        }
        prototypes::declare(self, Target::of(image), image.format, analysis.imports.iter().map(|i| i.name.as_str()))
    }

    /// Declares that the GOT entry at `slot` points to the imported function `name`. Indirect
    /// calls through the slot then show up as calls to `name`, and end control flow if `noreturn`.
    pub fn add_import(&mut self, slot: u64, name: &str, noreturn: bool) -> Result<()> {
        let name = CString::new(name)?;
        check(|err, len| unsafe { ffi::rd_add_import(self.raw.as_ptr(), slot, name.as_ptr(), noreturn.into(), err, len) != 0 })
    }

    /// Declares a function start, so that calls to it resolve to a symbol and control flow from
    /// other functions stops at it. With `noreturn`, flow also ends after every call to it.
    pub fn add_function(&mut self, addr: u64, noreturn: bool) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_add_function(self.raw.as_ptr(), addr, c"".as_ptr(), noreturn.into(), err, len) != 0 })
    }

    /// Declares the code at `addr` as a stub that only forwards to the import behind `slot`,
    /// which must be declared: it takes the import's name, prototype and non-returning flag.
    pub fn alias_import(&mut self, addr: u64, slot: u64) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_alias_import(self.raw.as_ptr(), addr, slot, err, len) != 0 })
    }

    /// Declares the function at `addr` under `name`. A function that is already declared keeps
    /// the name it has, so name functions first.
    pub fn name_function(&mut self, addr: u64, name: &str) -> Result<()> {
        let name = CString::new(name)?;
        check(|err, len| unsafe { ffi::rd_add_function(self.raw.as_ptr(), addr, name.as_ptr(), 0, err, len) != 0 })
    }

    /// Parses one C declaration with the engine's parser. `extern int f(char *s);` sets the
    /// prototype of the already declared function `f`; `typedef` and `struct` add data types.
    /// A calling convention goes before the return type: `extern __stdcall int f(void);`.
    pub fn declare(&mut self, declaration: &str) -> Result<()> {
        let declaration = CString::new(declaration)?;
        check(|err, len| unsafe { ffi::rd_declare(self.raw.as_ptr(), declaration.as_ptr(), err, len) != 0 })
    }

    /// Declares the NUL-terminated string at `addr`, `chars` characters long without the
    /// terminator. A pointer to it is then printed as a string literal, if it is in read-only
    /// memory, or as the symbol `name` otherwise.
    pub fn add_string(&mut self, addr: u64, name: &str, chars: usize, wide: bool) -> Result<()> {
        let name = CString::new(name)?;
        check(|err, len| unsafe { ffi::rd_add_string(self.raw.as_ptr(), addr, name.as_ptr(), chars + 1, wide.into(), err, len) != 0 })
    }

    /// Selects the pipeline that [`Session::decompile`] runs from now on.
    pub fn set_style(&mut self, style: Style) -> Result<()> {
        let name = match style {
            Style::Decompile => c"decompile",
            Style::Normalize => c"normalize",
            Style::ParamId => c"paramid",
        };
        check(|err, len| unsafe { ffi::rd_set_style(self.raw.as_ptr(), name.as_ptr(), err, len) != 0 })
    }

    /// Declares the functions in `facts` and applies the rest of it: names, tail calls, and the
    /// targets of calls through pointer slots.
    pub fn add_functions(&mut self, facts: &Facts) -> Result<()> {
        // Names go first: a function keeps the name it is first declared under.
        for &(addr, slot) in &facts.import_aliases {
            self.alias_import(addr, slot)?;
        }
        for (function, name) in &facts.names {
            self.name_function(*function, name)?;
        }
        // Before anything else is said of a function's prototype, which this sets afresh.
        for (function, kept) in &facts.kept_registers {
            let kept = CString::new(kept.as_str())?;
            check(|err, len| unsafe { ffi::rd_keep_registers(self.raw.as_ptr(), *function, kept.as_ptr(), err, len) != 0 })?;
        }
        for (function, fixup) in &facts.call_fixups {
            let fixup = CString::new(fixup.as_str())?;
            check(|err, len| unsafe { ffi::rd_set_call_fixup(self.raw.as_ptr(), *function, fixup.as_ptr(), err, len) != 0 })?;
        }
        for &(function, noreturn) in &facts.functions {
            self.add_function(function, noreturn)?;
        }
        for &function in &facts.returns_nothing {
            check(|err, len| unsafe { ffi::rd_returns_nothing(self.raw.as_ptr(), function, err, len) != 0 })?;
        }
        for (function, storage) in &facts.storage {
            self.set_storage(*function, storage)?;
        }
        for &(function, count) in &facts.param_counts {
            check(|err, len| unsafe { ffi::rd_set_param_count(self.raw.as_ptr(), function, count, err, len) != 0 })?;
        }
        for &(caller, function) in &facts.inlined {
            check(|err, len| unsafe { ffi::rd_inline(self.raw.as_ptr(), caller, function, err, len) != 0 })?;
        }
        for &(function, jump) in &facts.tail_calls {
            self.override_tail_call(function, jump)?;
        }
        for &(function, jump) in &facts.returns {
            check(|err, len| unsafe { ffi::rd_override_return(self.raw.as_ptr(), function, jump, err, len) != 0 })?;
        }
        for &(function, call, slot) in &facts.import_calls {
            self.override_import_call(function, call, slot)?;
        }
        for &(function, entry) in &facts.own_entries {
            check(|err, len| unsafe { ffi::rd_allow_entry(self.raw.as_ptr(), function, entry, err, len) != 0 })?;
        }
        for &(function, call, target) in &facts.local_calls {
            check(|err, len| unsafe { ffi::rd_override_call(self.raw.as_ptr(), function, call, target, err, len) != 0 })?;
        }
        for switch in &facts.switch_calls {
            let (assist, count, list) = switch.cases.map_or((std::ptr::null(), 0, 0), |(assist, count, list)| (assist.as_ptr(), count, list));
            check(|err, len| unsafe { ffi::rd_call_switches(self.raw.as_ptr(), switch.call, switch.selector.as_ptr(), assist, count, list, err, len) != 0 })?;
        }
        for &(call, len) in &facts.data_after_calls {
            unsafe { ffi::rd_call_skips(self.raw.as_ptr(), call, len) };
        }
        Ok(())
    }

    /// Declares the strings recore found, so that references to them print as literals.
    pub fn add_strings(&mut self, analysis: &Analysis) -> Result<()> {
        for string in &analysis.strings {
            // Named in Ghidra's style: a readable prefix of the text, then the address.
            let prefix: String = string.text.chars().take(16).map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
            let chars = if string.wide { string.text.encode_utf16().count() } else { string.text.len() };
            self.add_string(string.addr, &format!("s_{prefix}_{:x}", string.addr), chars, string.wide)?;
        }
        Ok(())
    }

    /// Declares the vtables of the classes recore found, so that a constructor storing one
    /// reads `*this = Class::vftable` and not a bare address.
    pub fn add_classes(&mut self, analysis: &Analysis) -> Result<()> {
        // An Objective-C class has no vtable: its methods are found by name.
        for class in analysis.classes.iter().filter(|class| !class.objc) {
            let name = CString::new(format!("{}::vftable", class.name))?;
            check(|err, len| unsafe { ffi::rd_add_pointer_table(self.raw.as_ptr(), class.vtable, name.as_ptr(), class.methods.len(), err, len) != 0 })?;
        }
        Ok(())
    }

    /// Names the image's Objective-C selector and class references, so that a message send
    /// reads `objc_msgSend(class_NSString, sel_alloc)` and not two bare addresses.
    pub fn add_objc(&mut self, image: &Image) -> Result<()> {
        let Some(metadata) = recore::objc::metadata(image) else { return Ok(()) };
        let named = |prefix: &str, slots: &recore::FxHashMap<u64, String>| slots.iter().map(|(&slot, name)| (slot, format!("{prefix}{name}"))).collect::<Vec<_>>();
        for (slot, name) in named("sel_", &metadata.selectors).into_iter().chain(named("class_", &metadata.class_refs)) {
            self.add_global(slot, &name, Some("void *"))?;
        }
        Ok(())
    }

    /// States that the indirect call at `call` in `function` goes through the import slot
    /// `slot`, which must have been declared with [`Session::add_import`]. The decompiler works
    /// this out by itself, but late, and for a non-returning import it then starts over.
    pub fn override_import_call(&mut self, function: u64, call: u64, slot: u64) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_override_import_call(self.raw.as_ptr(), function, call, slot, err, len) != 0 })
    }

    /// Marks the unconditional jump at `jump` in `function` as a call followed by a return.
    /// Otherwise the decompiler follows it and treats the target's body as part of `function`.
    pub fn override_tail_call(&mut self, function: u64, jump: u64) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_override_tail_call(self.raw.as_ptr(), function, jump, err, len) != 0 })
    }

    /// With `keep`, the parameters recovered by every later successful [`Session::decompile`]
    /// stay attached to the function, and callers decompiled afterwards pass those and whatever
    /// else the call shows. Decompile callees before callers to benefit.
    pub fn keep_prototypes(&mut self, keep: bool) {
        unsafe { ffi::rd_keep_prototypes(self.raw.as_ptr(), keep.into()) }
    }

    /// States that `function` returns what `callee` returns, because it ends by jumping to it.
    /// `callee` is a function this session has decompiled, or an import, by its slot, whose
    /// prototype is declared. Says whether the callee returns a value; if it does, `function`
    /// is from now on decompiled as returning one too.
    pub fn returns_like(&mut self, function: u64, callee: recore::report::CallTarget) -> bool {
        let (callee, import) = match callee {
            recore::report::CallTarget::Function(entry) => (entry, false),
            recore::report::CallTarget::Import(slot) => (slot, true),
        };
        let mut err = [0 as c_char; 64];
        unsafe { ffi::rd_returns_like(self.raw.as_ptr(), function, callee, import.into(), err.as_mut_ptr(), err.len()) != 0 }
    }

    /// With `keep`, every later [`Session::decompile`] prints each line of C after the address of
    /// the instruction the line came from, in a column, where it came from one.
    pub fn keep_addresses(&mut self, keep: bool) {
        unsafe { ffi::rd_set_addresses(self.raw.as_ptr(), keep.into()) }
    }

    /// With `keep`, every later [`Session::decompile`] also returns the function's data flow.
    pub fn keep_flow(&mut self, keep: bool) {
        unsafe { ffi::rd_set_flow(self.raw.as_ptr(), keep.into()) }
    }

    /// Says that the function at `addr` takes a format and a variable number of arguments for
    /// it. A call that passes it a printf format is then given the arguments the format asks for.
    pub fn takes_variable_arguments(&mut self, addr: u64) {
        unsafe { ffi::rd_takes_variable_arguments(self.raw.as_ptr(), addr) }
    }

    /// Settles what the call at `call` in `function` passes, from the format at `format` that
    /// it passes as argument `position`, counted from zero. Nothing happens unless the callee
    /// takes a variable number of arguments and the text is a printf or scanf format. To be
    /// said before `function` is decompiled.
    pub fn format_call(&mut self, function: u64, call: u64, callee: recore::report::CallTarget, position: usize, format: u64) -> Result<()> {
        let (callee, import) = match callee {
            recore::report::CallTarget::Function(entry) => (entry, false),
            recore::report::CallTarget::Import(slot) => (slot, true),
        };
        check(|err, len| unsafe { ffi::rd_format_call(self.raw.as_ptr(), function, call, callee, import.into(), position, format, err, len) != 0 })
    }

    /// Puts a note on the instruction at `addr` of `function`, which the function's C shows
    /// as a comment beside the code of that instruction, when any of it is left.
    pub fn add_comment(&mut self, function: u64, addr: u64, text: &str) -> Result<()> {
        let text = CString::new(text)?;
        check(|err, len| unsafe { ffi::rd_add_comment(self.raw.as_ptr(), function, addr, text.as_ptr(), err, len) != 0 })
    }

    /// Names the variable of `function` at `place`, one of [`Decompiled::locals`]. The name
    /// shows whenever the function is decompiled and still has a variable there.
    pub fn name_local(&mut self, function: u64, place: &str, name: &str) -> Result<()> {
        let (place, name) = (CString::new(place)?, CString::new(name)?);
        unsafe { ffi::rd_name_local(self.raw.as_ptr(), function, place.as_ptr(), name.as_ptr()) };
        Ok(())
    }

    /// Drops the names [`Session::name_local`] gave the variables of `function`.
    pub fn forget_local_names(&mut self, function: u64) {
        unsafe { ffi::rd_forget_local_names(self.raw.as_ptr(), function) }
    }

    /// Drops the comments [`Session::add_comment`] entered for `function`.
    pub fn forget_comments(&mut self, function: u64) {
        unsafe { ffi::rd_forget_comments(self.raw.as_ptr(), function) }
    }

    /// Renames the function at `addr`, which keeps what the session knows of it, its prototype
    /// included. Returns the name it had.
    pub fn rename_function(&mut self, addr: u64, name: &str) -> Result<String> {
        let name = CString::new(name)?;
        let mut old = std::ptr::null();
        check(|err, len| unsafe { ffi::rd_rename_function(self.raw.as_ptr(), addr, name.as_ptr(), &mut old, err, len) != 0 })?;
        Ok(unsafe { CStr::from_ptr(old) }.to_string_lossy().into_owned())
    }

    /// The machine and compiler the session decompiles for.
    pub fn target(&self) -> Target {
        self.target
    }

    /// Brings the named structs and the slots that hold them to those of the edits. Called
    /// again with the same edits it does nothing. Renames the structs the session holds that
    /// the edits renamed, defines those new to it, gives the fields of those it holds the
    /// names they have now, and has decompilations put each on the objects its holders reach,
    /// where it fits.
    pub fn set_structs(&mut self, structs: &BTreeMap<String, Layout>, holders: &BTreeMap<u64, BTreeMap<Slot, String>>) -> Result<Converged> {
        // SAFETY: the session owns the registry, and the shim reads it only inside `rd_decompile`.
        let converge = unsafe { self.structs.as_mut() }.converge(self.target.pointer_bytes() as u32, structs, holders);
        if converge.restart {
            return Ok(Converged::Restart);
        }
        // Renamed first: new structs refer to the ones the engine holds by their names now.
        for (old, name) in converge.renamed {
            let (old, name) = (CString::new(old)?, CString::new(name)?);
            check(|err, len| unsafe { ffi::rd_rename_type(self.raw.as_ptr(), old.as_ptr(), name.as_ptr(), err, len) != 0 })?;
        }
        if let Some(xml) = converge.xml {
            let rejected = self.add_types(&xml)?;
            anyhow::ensure!(rejected.is_empty(), "the decompiler did not take the structs: {}", rejected.join("; "));
        }
        for (name, offset, field) in converge.renames {
            let (name, field) = (CString::new(name)?, CString::new(field)?);
            check(|err, len| unsafe { ffi::rd_name_field(self.raw.as_ptr(), name.as_ptr(), offset, field.as_ptr(), err, len) != 0 })?;
        }
        Ok(Converged::InPlace)
    }

    /// The recovered struct `name` stands for and those it points to, as the last
    /// decompilation of its function in this session left them; none if no decompilation
    /// recovered it.
    pub fn recovered(&self, name: &str) -> Option<Recovered> {
        // SAFETY: as in `set_structs`.
        unsafe { self.structs.as_ref() }.recovered(name)
    }

    /// What the last decompilation of the function at `function` made of the objects its
    /// pointers reach; none if this session has not decompiled it.
    pub fn structs_of(&self, function: u64) -> Option<StructReport> {
        // SAFETY: as in `set_structs`.
        unsafe { self.structs.as_ref() }.report(function)
    }

    /// Disassembles `[start, end)` linearly, with each instruction's raw p-code if `pcode`.
    pub fn listing(&mut self, start: u64, end: u64, pcode: bool) -> Result<Vec<Instruction>> {
        self.listed(start, end, pcode.into())
    }

    /// Lifts `[start, end)` to raw p-code for a program to run: each operation as
    /// `OPNAME out input...`, with `-` for no output and each operand as `space:offset:size`, the
    /// offset in hex. The first input of a LOAD or STORE is the name of the space it reaches, and
    /// that of a CALLOTHER the name of the processor operation.
    pub fn lift(&mut self, start: u64, end: u64) -> Result<Vec<Instruction>> {
        self.listed(start, end, 2)
    }

    /// Where the register `name` is: the name of its space, its offset there and its size in bytes.
    pub fn register(&mut self, name: &str) -> Result<(String, u64, u32)> {
        let name = CString::new(name)?;
        let (mut space, mut offset, mut size) = (std::ptr::null(), 0u64, 0i32);
        check(|err, len| unsafe { ffi::rd_register(self.raw.as_ptr(), name.as_ptr(), &mut space, &mut offset, &mut size, err, len) != 0 })?;
        Ok((unsafe { CStr::from_ptr(space) }.to_string_lossy().into_owned(), offset, size as u32))
    }

    fn listed(&mut self, start: u64, end: u64, pcode: i32) -> Result<Vec<Instruction>> {
        let mut out = std::ptr::null();
        check(|err, len| unsafe { ffi::rd_listing(self.raw.as_ptr(), start, end, pcode, &mut out, err, len) != 0 })?;
        let text = unsafe { CStr::from_ptr(out) }.to_string_lossy();
        let mut instructions: Vec<Instruction> = Vec::new();
        for line in text.lines() {
            if let Some(operation) = line.strip_prefix('\t') {
                instructions.last_mut().context("p-code before an instruction")?.pcode.push(operation.to_string());
                continue;
            }
            let mut fields = line.splitn(3, '\t');
            let mut hex = || Ok::<u64, anyhow::Error>(u64::from_str_radix(fields.next().context("short listing line")?, 16)?);
            let (addr, len) = (hex()?, hex()?);
            instructions.push(Instruction { addr, len, text: fields.next().unwrap_or_default().to_string(), pcode: Vec::new() });
        }
        Ok(instructions)
    }

    /// Declares a global variable `name` at `addr`, of the C type `type_name` if one is given.
    /// Replaces what was declared there before.
    pub fn add_global(&mut self, addr: u64, name: &str, type_name: Option<&str>) -> Result<()> {
        let (name, type_name) = (CString::new(name)?, CString::new(type_name.unwrap_or_default())?);
        check(|err, len| unsafe { ffi::rd_add_global(self.raw.as_ptr(), addr, name.as_ptr(), type_name.as_ptr(), err, len) != 0 })
    }

    /// Adds data types, function prototypes and typed globals written in the engine's own XML,
    /// which [`types::Types::xml`] produces from debug information. Returns what the engine
    /// rejected, one line each; a rejected entry costs only itself.
    pub fn add_types(&mut self, xml: &str) -> Result<Vec<String>> {
        let xml = CString::new(xml)?;
        let mut out = std::ptr::null();
        check(|err, len| unsafe { ffi::rd_add_types(self.raw.as_ptr(), xml.as_ptr(), &mut out, err, len) != 0 })?;
        Ok(unsafe { CStr::from_ptr(out) }.to_string_lossy().lines().map(str::to_string).collect())
    }

    /// Describes a data type the session knows: its size, and the fields of a struct or union
    /// with their offsets, or the values of an enum.
    pub fn type_layout(&mut self, name: &str) -> Result<String> {
        let name = CString::new(name)?;
        let mut out = std::ptr::null();
        check(|err, len| unsafe { ffi::rd_type_layout(self.raw.as_ptr(), name.as_ptr(), &mut out, err, len) != 0 })?;
        Ok(unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned())
    }

    /// Hands recore's jump tables to the decompiler as overrides. Call before decompiling.
    pub fn override_jump_tables(&mut self, analysis: &Analysis, facts: &Facts) -> Result<()> {
        for &(function, index) in &facts.jump_tables {
            let table = &analysis.jump_tables[index];
            // The engine finds the cases of this one itself, each with its value.
            if facts.switch_calls.iter().any(|switch| switch.call == table.jump && switch.cases.is_some()) {
                continue;
            }
            // A call that comes back past its data is no jump to the engine, and a table for
            // a jump it never meets is one it trips over.
            if facts.data_after_calls.iter().any(|&(call, _)| call == table.jump) {
                continue;
            }
            if facts.engine_tables.contains(&(function, index)) {
                self.engine_tables.entry(function).or_default().push(JumpTable { jump: table.jump, targets: table.targets.clone() });
                continue;
            }
            self.override_jump_table(function, table.jump, &table.targets)?;
        }
        Ok(())
    }

    /// Supplies the destinations of the indirect jump at `jump` in `function`, replacing the
    /// decompiler's own table recovery. Must be called before the function is decompiled.
    pub fn override_jump_table(&mut self, function: u64, jump: u64, targets: &[u64]) -> Result<()> {
        check(|err, len| unsafe {
            ffi::rd_override_jump_table(self.raw.as_ptr(), function, jump, targets.as_ptr(), targets.len(), err, len) != 0
        })
    }

    /// Says where the function at `addr` takes its arguments and leaves its result, when a
    /// calling convention does not: `ACC(B:DPTR,stack:0xbf/1)` for a result in ACC, an argument
    /// in B and DPTR and one of a byte on the stack. `?` for the result leaves it to be found.
    pub fn set_storage(&mut self, addr: u64, storage: &str) -> Result<()> {
        let storage = CString::new(storage)?;
        check(|err, len| unsafe { ffi::rd_set_storage(self.raw.as_ptr(), addr, storage.as_ptr(), err, len) != 0 })
    }

    /// Decompiles the function at `addr`. SDCC passes an argument of three or four bytes in
    /// registers that are no pair, and code reads the bytes one by one, so the engine takes
    /// the argument for one of two bytes and the other registers for ones nothing passed.
    /// Such a function is given the parameter whole and decompiled again; calls to it then
    /// pass it whole. For C51 [`Facts::storage`] says where each function takes its
    /// arguments before any is decompiled.
    pub fn decompile(&mut self, addr: u64) -> Result<Decompiled> {
        let mut decompiled = self.decompile_as_declared(addr);
        // A table the engine was left to read is taken from recore after all if the engine
        // found other places than recore did, or none.
        if let Some(tables) = self.engine_tables.get(&addr) {
            let same = |table: &JumpTable| {
                let found = decompiled.as_ref().ok().and_then(|decompiled| decompiled.jump_tables.iter().find(|found| found.jump == table.jump));
                // The engine lists the place the jump is kept from, the default, with the others.
                found.is_some_and(|found| table.targets.iter().all(|target| found.targets.contains(target)) && found.targets.iter().filter(|target| !table.targets.contains(target)).count() <= 1)
            };
            if !tables.iter().all(same) {
                for table in self.engine_tables.remove(&addr).unwrap_or_default() {
                    self.override_jump_table(addr, table.jump, &table.targets)?;
                }
                decompiled = self.decompile_as_declared(addr);
            }
        }
        let decompiled = decompiled?;
        let reads = |register: &str| decompiled.c_text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).any(|word| word.strip_prefix("in_") == Some(register));
        // The parameter the engine found, the register it left out, and the two as one.
        let whole = match self.target {
            // SDCC's first argument: a pointer that says what memory it points into, or a long.
            Target::I8051Sdcc if reads("B") && reads("ACC") => Some(("DPTR", "ACC:B:DPTR")),
            Target::I8051Sdcc if reads("B") => Some(("DPTR", "B:DPTR")),
            _ => None,
        };
        let Some((at, whole)) = whole.and_then(|(part, whole)| Some((decompiled.params.iter().position(|param| param.storage == part)?, whole))) else {
            return Ok(decompiled);
        };
        let place = |(index, param): (usize, &Param)| match (index == at, param.storage.contains(':')) {
            (true, _) => whole.to_string(),
            (false, true) => format!("{}/{}", param.storage, param.size),
            (false, false) => param.storage.clone(),
        };
        let places: Vec<String> = decompiled.params.iter().enumerate().map(place).collect();
        self.set_storage(addr, &format!("?({})", places.join(",")))?;
        self.decompile_as_declared(addr)
    }

    /// Runs the session's [`Style`] on the function starting at `addr`. The function need not
    /// have been declared.
    fn decompile_as_declared(&mut self, addr: u64) -> Result<Decompiled> {
        let mut out = std::mem::MaybeUninit::<ffi::RdDecompiled>::uninit();
        check(|err, len| unsafe { ffi::rd_decompile(self.raw.as_ptr(), addr, out.as_mut_ptr(), err, len) != 0 })?;
        // Everything `out` points to lives in the session until its next call; copy it out now.
        unsafe {
            let out = out.assume_init();
            let text = |ptr| CStr::from_ptr(ptr).to_string_lossy().into_owned();
            let params = slice(out.params, out.param_count)
                .iter()
                .map(|p| Param { type_name: text(p.type_name), storage: text(p.storage), size: p.size })
                .collect();
            let mut targets = slice(out.jump_targets, slice(out.jump_counts, out.jump_table_count).iter().sum());
            let jump_tables = slice(out.jump_addrs, out.jump_table_count)
                .iter()
                .zip(slice(out.jump_counts, out.jump_table_count))
                .map(|(&jump, &count)| {
                    let (table, rest) = targets.split_at(count);
                    targets = rest;
                    JumpTable { jump, targets: table.to_vec() }
                })
                .collect();
            let flow = text(out.flow);
            let locals = text(out.locals).lines().filter_map(|line| line.split_once('\t')).map(|(name, place)| Local { name: name.into(), place: place.into() }).collect();
            Ok(Decompiled {
                locals,
                flow: if flow.is_empty() { None } else { Some(Flow::parse(&flow)?) },
                c_text: text(out.c_text),
                params,
                return_type: text(out.return_type),
                returns_value: out.flags & ffi::RD_RETURNS_VALUE != 0,
                bad_data: out.flags & ffi::RD_BAD_DATA != 0,
                unimplemented: out.flags & ffi::RD_UNIMPLEMENTED != 0,
                jump_tables,
            })
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            ffi::rd_session_free(self.raw.as_ptr());
            drop(Box::from_raw(self.structs.as_ptr()));
        }
    }
}

/// A C array as a slice. An empty `std::vector` may hand out a null pointer, which a slice cannot hold.
unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(ptr, len) } }
}
