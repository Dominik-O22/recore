//! Declarations matching `shim/shim.cc`.

use std::ffi::c_char;

#[repr(C)]
pub struct RdSession {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct RdSection {
    pub addr: u64,
    pub data: *const u8,
    pub len: usize,
    pub readonly: u32,
    pub code: u32,
}

#[repr(C)]
pub struct RdParam {
    pub type_name: *const c_char,
    pub storage: *const c_char,
    pub size: u32,
}

pub const RD_BAD_DATA: u32 = 4;
pub const RD_UNIMPLEMENTED: u32 = 8;
pub const RD_RETURNS_VALUE: u32 = 16;

#[repr(C)]
pub struct RdDecompiled {
    pub c_text: *const c_char,
    pub return_type: *const c_char,
    pub params: *const RdParam,
    pub param_count: usize,
    pub jump_addrs: *const u64,
    pub jump_counts: *const usize,
    pub jump_table_count: usize,
    pub jump_targets: *const u64,
    pub flags: u32,
    pub flow: *const c_char,
    pub locals: *const c_char,
}

unsafe extern "C" {
    pub fn rd_session_new(
        spec_dir: *const c_char,
        language: *const c_char,
        sections: *const RdSection,
        count: usize,
        err: *mut c_char,
        errlen: usize,
    ) -> *mut RdSession;
    pub fn rd_session_free(session: *mut RdSession);
    pub fn rd_map_space(session: *mut RdSession, base: u64, name: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_mirror(session: *mut RdSession, addr: u64, len: u64, target: u64);
    pub fn rd_redirect(session: *mut RdSession, from: u64, to: u64);
    pub fn rd_call_switches(session: *mut RdSession, call: u64, selector: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_call_skips(session: *mut RdSession, call: u64, len: u64);
    pub fn rd_add_function(session: *mut RdSession, addr: u64, name: *const c_char, noreturn: i32, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_import(session: *mut RdSession, slot: u64, name: *const c_char, noreturn: i32, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_override_jump_table(
        session: *mut RdSession,
        function: u64,
        jump: u64,
        targets: *const u64,
        count: usize,
        err: *mut c_char,
        errlen: usize,
    ) -> i32;
    pub fn rd_override_import_call(session: *mut RdSession, function: u64, call: u64, slot: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_alias_import(session: *mut RdSession, addr: u64, slot: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_allow_entry(session: *mut RdSession, function: u64, entry: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_override_call(session: *mut RdSession, function: u64, call: u64, target: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_declare(session: *mut RdSession, declaration: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_string(session: *mut RdSession, addr: u64, name: *const c_char, count: usize, wide: i32, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_set_call_fixup(session: *mut RdSession, addr: u64, fixup: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_pointer_table(session: *mut RdSession, addr: u64, name: *const c_char, count: usize, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_override_tail_call(session: *mut RdSession, function: u64, jump: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_keep_prototypes(session: *mut RdSession, keep: i32);
    pub fn rd_keep_prototypes_exact(session: *mut RdSession, exact: i32);
    pub fn rd_takes_variable_arguments(session: *mut RdSession, addr: u64);
    #[allow(clippy::too_many_arguments)]
    pub fn rd_format_call(session: *mut RdSession, function: u64, call: u64, callee: u64, import: i32, position: usize, format: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_comment(session: *mut RdSession, function: u64, addr: u64, text: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_set_style(session: *mut RdSession, name: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_set_param_count(session: *mut RdSession, addr: u64, count: usize, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_returns_like(session: *mut RdSession, function: u64, callee: u64, import_slot: i32, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_set_flow(session: *mut RdSession, on: i32);
    pub fn rd_set_addresses(session: *mut RdSession, on: i32);
    pub fn rd_name_local(session: *mut RdSession, function: u64, place: *const c_char, name: *const c_char);
    pub fn rd_listing(session: *mut RdSession, start: u64, end: u64, pcode: i32, out: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_global(session: *mut RdSession, addr: u64, name: *const c_char, type_name: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_types(session: *mut RdSession, xml: *const c_char, out: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_type_layout(session: *mut RdSession, name: *const c_char, out: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_decompile(session: *mut RdSession, addr: u64, out: *mut RdDecompiled, err: *mut c_char, errlen: usize) -> i32;
}
