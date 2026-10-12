//! Turning linker-level symbol names into readable ones.

/// A mangled Swift name as Swift's own demangler prints it. `None` for a name that is not
/// Swift's.
pub fn swift_name(symbol: &str) -> Option<String> {
    // Swift 5 and later, Swift 4.x, and Swift 4.0, each with or without the underscore that
    // Mach-O puts before every symbol.
    let mangled = ["$s", "_$s", "$S", "_$S", "_T0", "__T0"].iter().any(|prefix| symbol.starts_with(prefix));
    mangled.then(|| swift_demangler::demangle(symbol)).flatten()
}

/// The name as a person would write it, when `symbol` is a mangled C++, Rust or Swift name.
/// Other names come back unchanged.
pub fn display_name(symbol: &str) -> String {
    if let Some(demangled) = swift_name(symbol) {
        return demangled;
    }
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

#[cfg(test)]
mod tests {
    use super::{display_name, swift_name};

    #[test]
    fn swift_names_demangle_with_or_without_the_linkers_underscore() {
        let hello = Some("main.hello() async throws -> Swift.String".to_string());
        assert_eq!(swift_name("$s4main5helloSSyYaKF"), hello);
        assert_eq!(swift_name("_$s4main5helloSSyYaKF"), hello);
        assert_eq!(swift_name("main"), None);
        assert_eq!(display_name("$s10Foundation12NotificationVMa"), "type metadata accessor for Foundation.Notification");
    }
}
