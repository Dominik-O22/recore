//! Imported functions that are known never to return.

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

pub fn is_noreturn_import(name: &str) -> bool {
    // libstdc++ helpers such as `std::__throw_bad_alloc()` mangle to `_ZSt<len>__throw_...`.
    NAMES.contains(&name)
        || WINDOWS_NAMES.contains(&name)
        || (name.starts_with("_ZSt") && name.contains("__throw_"))
        // The Microsoft STL's throw helpers: `std::_Xlength_error`, `std::_Xbad_alloc` and so on.
        || ((name.starts_with("?_X") || name.starts_with("?_Throw_")) && name.contains("@std@@YAX"))
}
