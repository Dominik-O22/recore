//! Turning linker-level symbol names into readable ones.

/// The name as a person would write it, when `symbol` is a mangled C++ or Rust name. Other
/// names come back unchanged.
pub fn display_name(symbol: &str) -> String {
    if let Ok(demangled) = rustc_demangle::try_demangle(symbol) {
        // The alternate form drops the trailing hash.
        return format!("{demangled:#}");
    }
    if symbol.starts_with("_Z") {
        if let Some(demangled) = cpp_demangle::Symbol::new(symbol).ok().and_then(|parsed| parsed.demangle().ok()) {
            return demangled;
        }
    }
    if symbol.starts_with('?') {
        if let Ok(demangled) = msvc_demangler::demangle(symbol, msvc_demangler::DemangleFlags::NAME_ONLY) {
            return demangled;
        }
    }
    symbol.to_string()
}
