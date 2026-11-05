//! Parameters of a C++ function from its Itanium-mangled name.
//!
//! The name of a C++ function encodes the types of its parameters, so an import such as
//! `_ZNSt6localeD1Ev`, `std::locale::~locale()`, needs no table to say it takes only `this`.
//! Without a prototype the engine takes every argument register a call leaves set as passed,
//! and those that the caller never set become parameters of the caller. What the function
//! returns is only encoded for templates, so it is left for each call to show. A function that
//! returns a class in memory takes the address of it first, in the first argument register on
//! 32-bit ARM and x86-64, and its name does not say so: a call to one passes one argument too few.
//! Nor does a name tell a static member function from another member, so a static member of a
//! class takes a `this` it does not have.

use std::collections::HashSet;

use cpp_demangle::{DemangleOptions, Symbol};

use crate::Target;

/// A mangled function name, read as far as [`declaration`] needs.
struct Function {
    /// The scopes the function is declared in, as `std::basic_string<char>`, and empty for a
    /// function in the global namespace.
    scope: String,
    /// The C type of each parameter, without `this`.
    params: Vec<&'static str>,
    variadic: bool,
    /// Whether the name alone shows the function to be a member: a constructor, a destructor,
    /// or a function with a `const` or reference qualifier.
    member: bool,
}

/// The classes that the mangling abbreviates, which the demangler prints without their
/// template arguments.
const ABBREVIATED: &[&str] = &["std::allocator", "std::basic_string", "std::string", "std::istream", "std::ostream", "std::iostream"];

/// A C declaration for each of `names` that is a mangled function name, for `target`, with
/// `this` first where its scope is a class. A member function's mangled name does not say that
/// it is one, so a scope is a class where one of `names` shows it to be: the scope of a
/// constructor, a destructor or a qualified function, any scope with template arguments, and
/// the classes the mangling abbreviates.
///
/// A name is left out where it has a parameter whose size it does not tell, or one whose place
/// `target` leaves open: a floating parameter on 32-bit ARM, which goes in core registers under
/// the soft-float ABI and in VFP registers under the hard-float one, and `this` on 32-bit
/// Windows, which MinGW passes in ECX.
pub fn declarations<'a>(names: &[&'a str], target: Target) -> Vec<(&'a str, String)> {
    let functions: Vec<(&str, Function)> = names.iter().filter_map(|&name| Some((name, read(name)?))).collect();
    let members = functions.iter().filter(|(_, function)| function.member || function.scope.contains('<'));
    let classes: HashSet<&str> = members.map(|(_, function)| function.scope.as_str()).chain(ABBREVIATED.iter().copied()).collect();
    functions.iter().filter_map(|(name, function)| Some((*name, declaration(name, function, &classes, target)?))).collect()
}

fn declaration(name: &str, function: &Function, classes: &HashSet<&str>, target: Target) -> Option<String> {
    let word = if target.pointer_bytes() == 8 { "undefined8" } else { "undefined4" };
    let this = function.member || classes.contains(function.scope.as_str());
    let floating = function.params.iter().any(|param| param.starts_with("float"));
    if (this && target == Target::X86Windows) || (floating && matches!(target, Target::Arm | Target::Thumb)) {
        return None;
    }
    let params = function.params.iter().map(|&param| if param == WORD { word } else { param });
    let mut params: Vec<&str> = this.then_some("void *").into_iter().chain(params).collect();
    if function.variadic {
        params.push("...");
    }
    let params = if params.is_empty() { "void".to_string() } else { params.join(", ") };
    Some(format!("extern {word} {name}({params});"))
}

/// Whether the mangled name `name` is of a constructor or a destructor.
pub fn is_structor(name: &str) -> bool {
    let bare = || Symbol::new(name).ok()?.demangle_with_options(&DemangleOptions::new().no_return_type().no_params()).ok();
    name.starts_with("_Z") && bare().is_some_and(|bare| structor(&bare))
}

/// Whether the demangled name `bare`, without its parameters, is of a constructor or destructor.
fn structor(bare: &str) -> bool {
    let (scope, last) = split_scope(bare);
    let unqualified = |component: &str| component.split('<').next().unwrap_or(component).trim().to_string();
    !scope.is_empty() && (last.starts_with('~') || unqualified(last) == unqualified(split_scope(scope).1))
}

fn read(name: &str) -> Option<Function> {
    if !name.starts_with("_Z") {
        return None;
    }
    let symbol = Symbol::new(name).ok()?;
    let full = symbol.demangle_with_options(&DemangleOptions::new().no_return_type()).ok()?;
    let bare = symbol.demangle_with_options(&DemangleOptions::new().no_return_type().no_params()).ok()?;
    // Data, such as a vtable, and clones such as `f() [clone .cold]` have no parameter list
    // right after the name.
    let list = full.strip_prefix(&bare)?.strip_prefix('(')?;
    let close = closing(list)?;
    let (list, qualifiers) = (&list[..close], &list[close + 1..]);
    let (scope, _) = split_scope(&bare);
    let member = structor(&bare) || !qualifiers.trim().is_empty();
    let mut params = Vec::new();
    let mut variadic = false;
    for param in top_level(list, ',').into_iter().map(str::trim).filter(|param| !param.is_empty()) {
        match param {
            "..." => variadic = true,
            _ => params.push(c_type(param)?),
        }
    }
    Some(Function { scope: scope.to_string(), params, variadic, member })
}

/// Where the parenthesis that `text` is inside of closes.
fn closing(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (at, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(at),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// `name` split at its last `::` outside brackets, before any operator in it.
fn split_scope(name: &str) -> (&str, &str) {
    let mut depth = 0usize;
    let mut last = None;
    for (at, c) in name.char_indices() {
        let component = at == 0 || name[..at].ends_with("::");
        if depth == 0 && component && name[at..].starts_with("operator") {
            break;
        }
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth = depth.saturating_sub(1),
            ':' if depth == 0 && name[at..].starts_with("::") => last = Some(at),
            _ => {}
        }
    }
    match last {
        Some(at) => (&name[..at], &name[at + 2..]),
        None => ("", name),
    }
}

/// `text` split at each `separator` outside brackets.
fn top_level(text: &str, separator: char) -> Vec<&str> {
    let (mut parts, mut depth, mut start) = (Vec::new(), 0usize, 0);
    for (at, c) in text.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth = depth.saturating_sub(1),
            c if c == separator && depth == 0 => {
                parts.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// Stands for an integer as wide as a pointer, which [`declaration`] puts in.
const WORD: &str = "{word}";

/// The C type a parameter of the demangled type `param` is passed as. A class or enum passed
/// by value takes a word: an enum is an integer, and a class with a copy constructor or a
/// destructor is passed by reference. A trivially copyable class wider than a word, such as a
/// `std::chrono::duration<long long>`, takes more and is declared too small.
fn c_type(param: &str) -> Option<&'static str> {
    let mut param = param.trim();
    while let Some(rest) = [" const", " volatile", " restrict"].iter().find_map(|q| param.strip_suffix(q)) {
        param = rest.trim_end();
    }
    if param.contains("::*") {
        // A pointer to a member function takes two words, and one to a data member one.
        return None;
    }
    if param.ends_with(['*', '&']) || param.contains("(*)") || param.contains("(&)") {
        return Some("void *");
    }
    Some(match param {
        "bool" | "char" | "signed char" | "unsigned char" | "short" | "unsigned short" | "int" | "unsigned int" | "wchar_t" | "char8_t" | "char16_t" | "char32_t" => "int",
        "long" | "unsigned long" => "long",
        "long long" | "unsigned long long" => "int8",
        "decltype(nullptr)" | "std::nullptr_t" => "void *",
        "float" => "float4",
        "double" => "float8",
        // `long double`, `__int128` and vector types differ in size between targets.
        "long double" | "__int128" | "unsigned __int128" | "__float128" => return None,
        _ if param.contains("__vector") || param.starts_with("std::complex<") => return None,
        _ => WORD,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(names: &[&str], target: Target) -> Vec<Option<String>> {
        let found = declarations(names, target);
        names.iter().map(|name| found.iter().find(|(found, _)| found == name).map(|(_, declaration)| declaration.clone())).collect()
    }

    #[test]
    fn a_destructor_takes_this() {
        assert_eq!(declared(&["_ZNSt6localeD1Ev"], Target::Arm), [Some("extern undefined4 _ZNSt6localeD1Ev(void *);".to_string())]);
    }

    #[test]
    fn a_member_takes_this_where_another_name_shows_its_scope_is_a_class() {
        let names = ["_ZN4Json5ValueD1Ev", "_ZN4Json5ValueixEPKc", "_ZN4Json13valueToStringEi"];
        let declared = declared(&names, Target::Arm);
        assert_eq!(declared[1].as_deref(), Some("extern undefined4 _ZN4Json5ValueixEPKc(void *, void *);"));
        // `Json` is a namespace: nothing shows it to be a class.
        assert_eq!(declared[2].as_deref(), Some("extern undefined4 _ZN4Json13valueToStringEi(int);"));
    }

    #[test]
    fn a_template_function_takes_what_its_parameters_say() {
        let insert = "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_i";
        assert_eq!(declared(&[insert], Target::Arm)[0].as_deref(), Some(format!("extern undefined4 {insert}(void *, void *, int);").as_str()));
        let shift = "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc";
        assert_eq!(declared(&[shift], Target::Arm)[0].as_deref(), Some(format!("extern undefined4 {shift}(void *, void *);").as_str()));
    }

    #[test]
    fn a_member_of_an_abbreviated_class_takes_this() {
        assert_eq!(declared(&["_ZNSo3putEc"], Target::Arm)[0].as_deref(), Some("extern undefined4 _ZNSo3putEc(void *, int);"));
    }

    #[test]
    fn a_member_of_a_class_template_takes_this() {
        let create = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERjj";
        assert_eq!(declared(&[create], Target::Arm)[0].as_deref(), Some(format!("extern undefined4 {create}(void *, void *, int);").as_str()));
    }

    #[test]
    fn wide_and_floating_parameters_keep_their_size() {
        let names = ["_ZN3Foo3setExd", "_ZN3FooC1Ev"];
        assert_eq!(declared(&names, Target::X86Gcc)[0].as_deref(), Some("extern undefined4 _ZN3Foo3setExd(void *, int8, float8);"));
        // Whether the `double` goes in core or VFP registers depends on the float ABI.
        assert_eq!(declared(&names, Target::Arm)[0], None);
    }

    #[test]
    fn an_operator_ends_the_scope_only_at_the_start_of_a_component() {
        assert_eq!(split_scope("ns::cooperator::run"), ("ns::cooperator", "run"));
        assert_eq!(split_scope("ns::Foo::operator<<"), ("ns::Foo", "operator<<"));
    }

    #[test]
    fn data_and_unmangled_names_are_not_declared() {
        assert_eq!(declared(&["_ZTVN10__cxxabiv117__class_type_infoE", "malloc"], Target::X86_64Gcc), [None, None]);
    }
}
