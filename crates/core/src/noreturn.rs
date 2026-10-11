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

pub fn is_noreturn_import(name: &str) -> bool {
    // libstdc++ helpers such as `std::__throw_bad_alloc()` mangle to `_ZSt<len>__throw_...`.
    NAMES.contains(&name) || (name.starts_with("_ZSt") && name.contains("__throw_"))
}
