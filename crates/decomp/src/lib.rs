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
pub mod isolate;
pub mod prototypes;

// The engine is only reached through the shim, so name the crate to keep it in the link.
extern crate ghidra_decompiler_sys;

use std::ffi::{CStr, CString, c_char};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use anyhow::{Result, bail};
use recore::Image;
use recore::image::{Format, Machine};
use recore::report::Analysis;

pub use facts::Facts;

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
}

impl Target {
    /// The target an image was built for.
    pub fn of(image: &Image) -> Target {
        match (image.machine, image.format) {
            (Machine::X86, Format::Pe) => Target::X86Windows,
            (Machine::X86, Format::Elf) => Target::X86Gcc,
            (Machine::X86_64, Format::Pe) => Target::X86_64Windows,
            (Machine::X86_64, Format::Elf) => Target::X86_64Gcc,
            (Machine::Aarch64, _) => Target::Aarch64,
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
        }
    }

    pub fn pointer_bytes(self) -> usize {
        if matches!(self, Target::X86Windows | Target::X86Gcc) { 4 } else { 8 }
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
}

impl Decompiled {
    pub fn param_count(&self) -> usize {
        self.params.len()
    }
}

/// A program loaded into the decompiler.
pub struct Session {
    raw: NonNull<ffi::RdSession>,
}

// A session owns all of its C++ state. The engine's globals are written only while a session
// is created and while C is printed, and the shim takes a lock around both.
unsafe impl Send for Session {}

/// The x86-64 language files vendored with the decompiler sources.
pub fn vendored_spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/ghidra-decompiler/languages")
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
        Ok(Session { raw: NonNull::new(raw).expect("checked above") })
    }

    /// Loads a recore image as it looks after relocation, with the vendored language files, and
    /// declares the imports its code calls, with prototypes for the well-known ones.
    pub fn from_image(image: &Image, analysis: &Analysis) -> Result<Session> {
        let target = Target::of(image);
        let loaded = facts::loaded(image);
        let sections: Vec<Section> = loaded.iter().map(|l| Section { addr: l.addr, data: &l.data, readonly: l.constant, code: l.code }).collect();
        let mut session = Session::new(&vendored_spec_dir(), target, &sections)?;
        for import in &analysis.imports {
            session.add_import(import.slot, &import.name, import.noreturn)?;
        }
        prototypes::declare(&mut session, target, analysis.imports.iter().map(|i| i.name.as_str()))?;
        Ok(session)
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
        for &(function, noreturn) in &facts.functions {
            self.add_function(function, noreturn)?;
        }
        for &(function, jump) in &facts.tail_calls {
            self.override_tail_call(function, jump)?;
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
        for class in &analysis.classes {
            let name = CString::new(format!("{}::vftable", class.name))?;
            check(|err, len| unsafe { ffi::rd_add_pointer_table(self.raw.as_ptr(), class.vtable, name.as_ptr(), class.methods.len(), err, len) != 0 })?;
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
    /// stay attached to the function, and callers decompiled afterwards pass exactly those.
    /// Decompile callees before callers, or make several passes, to benefit.
    pub fn keep_prototypes(&mut self, keep: bool) {
        unsafe { ffi::rd_keep_prototypes(self.raw.as_ptr(), keep.into()) }
    }

    /// Hands recore's jump tables to the decompiler as overrides. Call before decompiling.
    pub fn override_jump_tables(&mut self, analysis: &Analysis, facts: &Facts) -> Result<()> {
        for &(function, index) in &facts.jump_tables {
            let table = &analysis.jump_tables[index];
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

    /// Runs the session's [`Style`] on the function starting at `addr`. The function need not
    /// have been declared.
    pub fn decompile(&mut self, addr: u64) -> Result<Decompiled> {
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
            Ok(Decompiled {
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
        unsafe { ffi::rd_session_free(self.raw.as_ptr()) }
    }
}

/// A C array as a slice. An empty `std::vector` may hand out a null pointer, which a slice cannot hold.
unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(ptr, len) } }
}
