//! Imported functions that are known never to return.

use crate::image::Image;

/// C library and compiler-runtime functions that never return to their caller.
const NAMES: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__assert_fail",
    "__assert_perror_fail",
    "__stack_chk_fail",
    "__fortify_fail",
    "__chk_fail",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "__cxa_pure_virtual",
    "__cxa_call_unexpected",
    "_Unwind_Resume",
    "_ZSt9terminatev",
    "_ZSt21__glibcxx_assert_failPKciS0_S0_",
    // macOS: what `assert` calls, and the Objective-C runtime's `@throw`.
    "__assert_rtn",
    "objc_exception_throw",
    "objc_exception_rethrow",
];

/// Windows API and Microsoft C runtime functions that never return.
const WINDOWS_NAMES: &[&str] = &[
    "ExitProcess",
    "ExitThread",
    "FreeLibraryAndExitThread",
    "FatalExit",
    "RaiseFailFastException",
    "_CxxThrowException",
    "__std_terminate",
    "terminate",
    "?terminate@@YAXXZ",
    "_invalid_parameter_noinfo_noreturn",
    "__report_rangecheckfailure",
    "__report_gsfailure",
];

/// Linux kernel functions that never return, which a kernel module imports. objtool's list of
/// them, `tools/objtool/noreturns.h`, as of Linux 7.4-rc3. It holds every noreturn callee that
/// DWARF names in the kernel module corpora. The corpus truth takes it too, for a module without
/// DWARF and for the kernel's own functions.
pub const KERNEL_NAMES: &[&str] = &[
    "__fortify_panic",
    "__ia32_sys_exit",
    "__ia32_sys_exit_group",
    "__kunit_abort",
    "__module_put_and_kthread_exit",
    "__stack_chk_fail",
    "__tdx_hypercall_failed",
    "__ubsan_handle_builtin_unreachable",
    "__x64_sys_exit",
    "__x64_sys_exit_group",
    "acpi_processor_ffh_play_dead",
    "arch_cpu_idle_dead",
    "bch2_trans_in_restart_error",
    "bch2_trans_restart_error",
    "bch2_trans_unlocked_or_in_restart_error",
    "cpu_bringup_and_idle",
    "cpu_startup_entry",
    "do_exit",
    "do_group_exit",
    "do_task_dead",
    "efi_rts_park_worker",
    "ex_handler_msr_mce",
    "hlt_play_dead",
    "hv_ghcb_terminate",
    "kthread_complete_and_exit",
    "kthread_exit",
    "kunit_try_catch_throw",
    "machine_real_restart",
    "make_task_dead",
    "mpt_halt_firmware",
    "mwait_play_dead",
    "native_play_dead",
    "nmi_panic_self_stop",
    "panic",
    "vpanic",
    "panic_smp_self_stop",
    "rest_init",
    "rewind_stack_and_make_dead",
    "rust_begin_unwind",
    "rust_helper_BUG",
    "sev_es_terminate",
    "start_kernel",
    "stop_this_cpu",
    "usercopy_abort",
    "x86_64_start_kernel",
    "x86_64_start_reservations",
    "xen_cpu_bringup_again",
    "xen_start_kernel",
];

/// Whether the import `name` of `image` never returns. The kernel's names count only in a kernel
/// module: in a user-space program an import called `panic` is some library's own function.
pub fn is_noreturn_import(image: &Image, name: &str) -> bool {
    if image.kernel_module && KERNEL_NAMES.contains(&name) {
        return true;
    }
    // libstdc++ helpers such as `std::__throw_bad_alloc()` mangle to `_ZSt<len>__throw_...`.
    NAMES.contains(&name)
        || WINDOWS_NAMES.contains(&name)
        || (name.starts_with("_ZSt") && name.contains("__throw_"))
        // The Microsoft STL's throw helpers: `std::_Xlength_error`, `std::_Xbad_alloc` and so on.
        || ((name.starts_with("?_X") || name.starts_with("?_Throw_")) && name.contains("@std@@YAX"))
}
