//! The tools that record what the caller has worked out: names, comments and data types.

use std::fmt::Write;

use anyhow::{Context, Result, bail, ensure};
use recore::program::{Pattern, matches};
use serde::Deserialize;

use crate::binary::Binary;
use crate::tools::{DEFAULT_LIMIT, addr_arg, describe, shown};

#[derive(Deserialize)]
struct Naming {
    addr: String,
    name: String,
}

#[derive(Deserialize)]
pub struct Rename {
    addr: Option<String>,
    name: Option<String>,
    #[serde(default)]
    names: Vec<Naming>,
}

/// Checks that `addr` can carry a name: a function entry, or data.
fn nameable(binary: &Binary, addr: u64) -> Result<()> {
    let program = &binary.program;
    ensure!(program.image.section_at(addr).is_some(), "{addr:#x} is not in any section of the file");
    if program.image.is_code(addr) && program.function(addr).is_none() {
        match program.function_at(addr) {
            Ok(entry) => bail!("{addr:#x} is inside function {}; name the function at its entry, or use `comment` for a place inside it", program.label(entry)),
            Err(_) => bail!("{addr:#x} is code in no function the analysis found"),
        }
    }
    Ok(())
}

pub fn rename(binary: &mut Binary, args: Rename) -> Result<String> {
    let mut namings = args.names;
    match (args.addr, args.name) {
        (Some(addr), Some(name)) => namings.push(Naming { addr, name }),
        (None, None) => {}
        _ => bail!("`rename` needs `addr` and `name` together"),
    }
    ensure!(!namings.is_empty(), "`rename` needs `addr` and `name`, or `names`");
    let mut changes = Vec::new();
    for naming in &namings {
        let addr = addr_arg(&naming.addr)?;
        nameable(binary, addr)?;
        let name = naming.name.trim();
        ensure!(!name.chars().any(char::is_control), "a name cannot contain control characters");
        changes.push((addr, name.to_string()));
    }
    binary.edit(|edits| {
        for (addr, name) in &changes {
            if name.is_empty() {
                edits.names.remove(addr);
            } else {
                edits.names.insert(*addr, name.clone());
            }
        }
    })?;
    let mut out = String::new();
    for (addr, name) in &changes {
        match name.as_str() {
            "" => writeln!(out, "{addr:#x} has the name the analysis gives it again: {}", describe(binary, *addr))?,
            name => writeln!(out, "{addr:#x} is now {name}")?,
        }
    }
    writeln!(out, "saved; the decompiler is starting again with the new names")?;
    Ok(out)
}

#[derive(Deserialize)]
pub struct Comment {
    addr: String,
    text: String,
}

pub fn comment(binary: &mut Binary, args: Comment) -> Result<String> {
    let addr = addr_arg(&args.addr)?;
    ensure!(binary.program.image.section_at(addr).is_some(), "{addr:#x} is not in any section of the file");
    let text = args.text.trim().replace('\n', " ");
    binary.edit(|edits| {
        if text.is_empty() {
            edits.comments.remove(&addr);
        } else {
            edits.comments.insert(addr, text.clone());
        }
    })?;
    Ok(if text.is_empty() { format!("comment at {addr:#x} removed\n") } else { format!("comment at {addr:#x} saved; `function`, `disassemble` and `decompile` show it\n") })
}

#[derive(Deserialize)]
pub struct Declare {
    code: Option<String>,
    addr: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

pub fn declare(binary: &mut Binary, args: Declare) -> Result<String> {
    match (args.code, args.addr, args.kind) {
        (Some(code), None, None) => {
            let code = code.trim().to_string();
            ensure!(!code.is_empty(), "`code` is empty");
            binary.check_declaration(&code).context("the decompiler does not take this declaration")?;
            binary.edit(|edits| {
                // Declared again, a struct or prototype replaces what was said before.
                edits.declarations.retain(|earlier| *earlier != code);
                edits.declarations.push(code.clone());
            })?;
            Ok("declared and saved; the decompiler is starting again with it\n".into())
        }
        (None, Some(addr), Some(kind)) => {
            let addr = addr_arg(&addr)?;
            ensure!(binary.program.image.section_at(addr).is_some_and(|section| !section.executable), "{addr:#x} is not data; a function gets its type from an `extern` declaration in `code`");
            let kind = kind.trim().to_string();
            if kind.is_empty() {
                binary.edit(|edits| drop(edits.types.remove(&addr)))?;
                return Ok(format!("{addr:#x} has no declared type any more\n"));
            }
            let layout = binary.type_layout(&kind).with_context(|| format!("the decompiler knows no type `{kind}`; declare it with `code` first"))?;
            binary.edit(|edits| drop(edits.types.insert(addr, kind.clone())))?;
            Ok(format!("{addr:#x} is now a {}saved; the decompiler is starting again with it\n", layout.lines().next().map_or_else(String::new, |line| format!("{line}\n"))))
        }
        _ => bail!("`declare` needs either `code`, or `addr` and `type`"),
    }
}

#[derive(Deserialize)]
pub struct Type {
    name: Option<String>,
}

pub fn type_(binary: &mut Binary, args: Type) -> Result<String> {
    if let Some(name) = args.name {
        return binary.type_layout(name.trim()).with_context(|| format!("the decompiler knows no type `{name}`"));
    }
    let mut out = String::new();
    writeln!(out, "{} declarations made with `declare`:", binary.edits.declarations.len())?;
    for declaration in &binary.edits.declarations {
        writeln!(out, "{declaration}\n")?;
    }
    writeln!(out, "{} data addresses with a declared type:", binary.edits.types.len())?;
    for (addr, kind) in &binary.edits.types {
        writeln!(out, "{addr:#x} {kind}")?;
    }
    writeln!(out, "Give `name` to see the layout of one type, declared or built in.")?;
    Ok(out)
}

#[derive(Deserialize)]
pub struct Symbols {
    pattern: Option<String>,
    limit: Option<usize>,
}

/// Every address that has a name, whoever gave it: the file, the analysis, or an edit.
pub fn symbols(binary: &mut Binary, args: Symbols) -> Result<String> {
    let pattern = args.pattern.as_deref().map(Pattern::new);
    let program = &binary.program;
    let mut rows: Vec<(u64, &str, String)> = Vec::new();
    for function in program.functions() {
        if let Some(name) = &function.name {
            let kind = if binary.edits.names.contains_key(&function.addr) { "function, renamed" } else if function.thunk { "thunk" } else { "function" };
            rows.push((function.addr, kind, name.clone()));
        }
    }
    rows.extend(program.analysis.imports.iter().map(|import| (import.slot, "import slot", import.name.clone())));
    rows.extend(program.analysis.classes.iter().map(|class| (class.vtable, "vtable", format!("{}::vftable", class.name))));
    rows.extend(binary.edits.globals(&program.analysis).into_iter().map(|(addr, name, kind)| (addr, if kind.is_some() { "data, typed" } else { "data, named" }, name)));
    // A name the file carries for something that is not a function: an exported variable.
    rows.extend(program.image.symbol_names.iter().filter(|(addr, _)| program.function(**addr).is_none() && !binary.edits.names.contains_key(addr)).map(|(&addr, name)| (addr, "exported", name.clone())));
    rows.retain(|(_, _, name)| matches(name, pattern.as_ref()));
    rows.sort();
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = String::new();
    writeln!(out, "{} names{}", rows.len(), shown(rows.len(), limit))?;
    for (addr, kind, name) in rows.iter().take(limit) {
        writeln!(out, "{addr:#x} {kind}: {name}")?;
    }
    Ok(out)
}
