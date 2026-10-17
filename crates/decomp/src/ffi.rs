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

/// One object of [`RdEvidence`]: the lowest and highest offset a member points to, and flags
/// as [`crate::structs::Object`] has them.
#[repr(C)]
pub struct RdObject {
    pub low: i64,
    pub high: i64,
    pub locked: u8,
    pub global: u8,
    pub number: u8,
}

/// A parameter that points to an object: a register by name, or with a null name the stack at
/// `stack`. `offset` is from the object's base.
#[repr(C)]
pub struct RdRoot {
    pub object: u32,
    pub register: *const c_char,
    pub stack: u64,
    pub offset: i64,
}

/// `kind`: 0 unknown, 1 signed, 2 unsigned, 3 floating point, 4 boolean.
#[repr(C)]
pub struct RdAccess {
    pub object: u32,
    pub offset: i64,
    pub size: u32,
    pub kind: u8,
}

/// The field at `offset` of `object` holds pointers to `child`.
#[repr(C)]
pub struct RdLink {
    pub object: u32,
    pub offset: i64,
    pub child: u32,
}

#[repr(C)]
pub struct RdStride {
    pub object: u32,
    pub stride: u64,
}

/// A member at `offset` of `object` handed to the function at `callee`, in a register by name or
/// with a null name on the stack at `stack`.
#[repr(C)]
pub struct RdPass {
    pub object: u32,
    pub callee: u64,
    pub register: *const c_char,
    pub stack: u64,
    pub offset: i64,
}

#[repr(C)]
pub struct RdEvidence {
    pub function: u64,
    pub pointer: u32,
    pub objects: *const RdObject,
    pub object_count: usize,
    pub roots: *const RdRoot,
    pub root_count: usize,
    pub accesses: *const RdAccess,
    pub access_count: usize,
    pub links: *const RdLink,
    pub link_count: usize,
    pub strides: *const RdStride,
    pub stride_count: usize,
    pub passed: *const RdPass,
    pub pass_count: usize,
}

/// What the plan hook answers: XML that defines new structs, or null; per object the name of
/// its struct, or null; every struct the plan uses, each with whether it is an element of an
/// array; and lines for the function's warning header.
#[repr(C)]
pub struct RdPlan {
    pub xml: *const c_char,
    pub names: *const *const c_char,
    pub recovered: *const *const c_char,
    pub arrays: *const u8,
    pub recovered_count: usize,
    pub warnings: *const *const c_char,
    pub warning_count: usize,
}

pub type PlanHook = extern "C" fn(ctx: *mut std::ffi::c_void, evidence: *const RdEvidence, out: *mut RdPlan) -> i32;
pub type WrappedHook = extern "C" fn(ctx: *mut std::ffi::c_void, function: u64, name: *const c_char);

unsafe extern "C" {
    pub fn rd_set_struct_hooks(session: *mut RdSession, ctx: *mut std::ffi::c_void, plan: PlanHook, wrapped: WrappedHook);
    pub fn rd_rename_type(session: *mut RdSession, old: *const c_char, name: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_name_field(session: *mut RdSession, type_name: *const c_char, offset: u64, name: *const c_char, err: *mut c_char, errlen: usize) -> i32;
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
    pub fn rd_register_at(session: *mut RdSession, addr: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_set_context(session: *mut RdSession, name: *const c_char, start: u64, end: u64, value: u32, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_mirror(session: *mut RdSession, addr: u64, len: u64, target: u64);
    pub fn rd_redirect(session: *mut RdSession, from: u64, to: u64);
    pub fn rd_call_switches(session: *mut RdSession, call: u64, selector: *const c_char, assist: *const c_char, count: u64, list: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_call_skips(session: *mut RdSession, call: u64, len: u64);
    pub fn rd_functions_run_on(session: *mut RdSession, on: i32);
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
    pub fn rd_set_storage(session: *mut RdSession, addr: u64, storage: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_inline(session: *mut RdSession, caller: u64, function: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_returns_nothing(session: *mut RdSession, addr: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_keep_registers(session: *mut RdSession, addr: u64, kept: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_set_call_fixup(session: *mut RdSession, addr: u64, fixup: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_pointer_table(session: *mut RdSession, addr: u64, name: *const c_char, count: usize, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_override_tail_call(session: *mut RdSession, function: u64, jump: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_override_return(session: *mut RdSession, function: u64, jump: u64, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_keep_prototypes(session: *mut RdSession, keep: i32);
    pub fn rd_stack_aggregates(session: *mut RdSession, on: i32);
    pub fn rd_keep_prototypes_exact(session: *mut RdSession, exact: i32);
    pub fn rd_result_in_first_argument(session: *mut RdSession, shared: i32);
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
    pub fn rd_forget_local_names(session: *mut RdSession, function: u64);
    pub fn rd_forget_comments(session: *mut RdSession, function: u64);
    pub fn rd_rename_function(session: *mut RdSession, addr: u64, name: *const c_char, old: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_listing(session: *mut RdSession, start: u64, end: u64, pcode: i32, out: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_global(session: *mut RdSession, addr: u64, name: *const c_char, type_name: *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_add_types(session: *mut RdSession, xml: *const c_char, out: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_type_layout(session: *mut RdSession, name: *const c_char, out: *mut *const c_char, err: *mut c_char, errlen: usize) -> i32;
    pub fn rd_decompile(session: *mut RdSession, addr: u64, out: *mut RdDecompiled, err: *mut c_char, errlen: usize) -> i32;
}
