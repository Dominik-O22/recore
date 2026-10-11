//! Ghidra's decompiler engine as an in-process library, fed by recore instead of by Ghidra.
//!
//! A [`Session`] wraps one decompiler `Architecture` for x86-64 with the gcc compiler spec. It
//! reads bytes from the sections it is given, never from a file, and learns from the caller what
//! recore already knows: function starts, imports, functions that never return, tail calls and
//! jump-table targets.
//!
//! A session is single-threaded but independent of every other session, so use one per thread.
//! Results can depend on what a session decompiled earlier, because the globals a function
//! refers to become symbols that later functions see.

pub mod dwarf;
pub mod facts;
mod ffi;

// The engine is only reached through the shim, so name the crate to keep it in the link.
extern crate ghidra_decompiler_sys;

use std::ffi::{CStr, CString, c_char};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use anyhow::{Result, bail};
use recore::Image;
use recore::image::Machine;
use recore::report::{AnalyzedFunction, Analysis};

pub use facts::Facts;

/// Bytes mapped at a virtual address.
pub struct Section<'a> {
    pub addr: u64,
    pub data: &'a [u8],
    /// The decompiler reads constants and jump tables only out of read-only memory.
    pub readonly: bool,
    /// Holds instructions. [`Session::bound_flow`] hides code past a function's end, not data.
    pub code: bool,
}

/// How far the engine takes a function. These are Ghidra's own "simplification styles".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// The decompiler's name for the data type, such as `xunknown8` or `char *`.
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
    pub fn new(spec_dir: &Path, sections: &[Section]) -> Result<Session> {
        let spec_dir = CString::new(spec_dir.as_os_str().as_encoded_bytes())?;
        let raw_sections: Vec<ffi::RdSection> = sections
            .iter()
            .map(|s| ffi::RdSection { addr: s.addr, data: s.data.as_ptr(), len: s.data.len(), readonly: s.readonly.into(), code: s.code.into() })
            .collect();
        let mut raw = std::ptr::null_mut();
        check(|err, len| {
            // The shim copies the section bytes, so nothing borrowed outlives this call.
            raw = unsafe { ffi::rd_session_new(spec_dir.as_ptr(), raw_sections.as_ptr(), raw_sections.len(), err, len) };
            !raw.is_null()
        })?;
        Ok(Session { raw: NonNull::new(raw).expect("checked above") })
    }

    /// Loads a recore image as it looks after relocation, with the vendored language files, and
    /// declares the imports its code calls.
    pub fn from_image(image: &Image, analysis: &Analysis) -> Result<Session> {
        if image.machine != Machine::X86_64 {
            bail!("only x86-64 is supported, {} is {:?}", image.name, image.machine);
        }
        let loaded = facts::loaded(image);
        let sections: Vec<Section> = loaded.iter().map(|l| Section { addr: l.addr, data: &l.data, readonly: l.constant, code: l.code }).collect();
        let mut session = Session::new(&vendored_spec_dir(), &sections)?;
        for import in &analysis.imports {
            session.add_import(import.slot, &import.name, import.noreturn)?;
        }
        Ok(session)
    }

    /// Declares that the GOT entry at `slot` points to the imported function `name`. Indirect
    /// calls through the slot then show up as calls to `name`, and end control flow if `noreturn`.
    pub fn add_import(&mut self, slot: u64, name: &str, noreturn: bool) -> Result<()> {
        let name = CString::new(name)?;
        check(|err, len| unsafe { ffi::rd_add_import(self.raw.as_ptr(), slot, name.as_ptr(), noreturn.into(), err, len) != 0 })
    }

    /// Declares a function start, so that calls to it resolve to a symbol. With `noreturn`, the
    /// decompiler ends control flow after every call to it.
    pub fn add_function(&mut self, addr: u64, noreturn: bool) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_add_function(self.raw.as_ptr(), addr, noreturn.into(), err, len) != 0 })
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

    /// Declares the functions in `facts` and applies the rest of it: where each function ends,
    /// tail calls, and the imports behind indirect calls.
    pub fn add_functions(&mut self, facts: &Facts) -> Result<()> {
        for &(function, noreturn) in &facts.functions {
            self.add_function(function, noreturn)?;
        }
        for &stub in &facts.noreturn_stubs {
            self.add_function(stub, true)?;
        }
        for &(function, end) in &facts.ends {
            self.bound_flow(function, end)?;
        }
        for &(function, jump) in &facts.tail_calls {
            self.override_tail_call(function, jump)?;
        }
        for &(function, call, slot) in &facts.import_calls {
            self.override_import_call(function, call, slot)?;
        }
        Ok(())
    }

    /// Sets the address where `function` ends. The decompiler then stops, with a "bad
    /// instruction" warning, at control flow that runs or jumps past it, instead of decompiling
    /// whatever comes next as part of `function`.
    pub fn bound_flow(&mut self, function: u64, end: u64) -> Result<()> {
        check(|err, len| unsafe { ffi::rd_bound_flow(self.raw.as_ptr(), function, end, err, len) != 0 })
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
    pub fn override_jump_tables(&mut self, analysis: &Analysis) -> Result<()> {
        for table in &analysis.jump_tables {
            let inside = |f: &&AnalyzedFunction| f.ranges.iter().any(|&(start, end)| (start..end).contains(&table.jump));
            if let Some(function) = analysis.functions.iter().find(inside) {
                // A table inside a cold fragment is reached while decompiling the fragment's owner.
                self.override_jump_table(function.fragment_of.unwrap_or(function.addr), table.jump, &table.targets)?;
            }
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
