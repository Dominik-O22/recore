//! The tools: what each takes, and the text it answers with.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use recore::image::{Format, Machine};
use recore::program::{Program, matches, parse_addr};
use recore::report::CallTarget;
use recore_decomp::isolate::Status;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::binary::{Binary, Cache};

/// Rows a listing shows unless the caller sets `limit`.
const DEFAULT_LIMIT: usize = 100;
/// Functions named on one line before the rest are counted.
const USERS_SHOWN: usize = 12;
/// Characters of a string shown in a listing.
const TEXT_SHOWN: usize = 200;
const MAX_BYTES: usize = 4096;

/// One tool as `tools/list` describes it. Every tool takes `path`.
fn tool(name: &str, description: &str, mut properties: Value, required: &[&str]) -> Value {
    properties["path"] = json!({ "type": "string", "description": "Path of the binary to analyze (ELF or Windows PE)." });
    let required: Vec<&str> = ["path"].into_iter().chain(required.iter().copied()).collect();
    json!({ "name": name, "description": description, "inputSchema": { "type": "object", "properties": properties, "required": required } })
}

pub fn list() -> Value {
    let pattern = |of: &str| json!({ "type": "string", "description": format!("Case-insensitive substring of the {of}.") });
    let limit = json!({ "type": "integer", "minimum": 1, "description": format!("Most rows to return (default {DEFAULT_LIMIT}).") });
    let addr = |what: &str| json!({ "type": "string", "description": format!("{what}, in hex with or without 0x.") });
    json!([
        tool("summary", "What the binary is: format, machine, sections, and how many functions, imports, strings and jump tables were recovered. Analysis is cached, so call this first.", json!({}), &[]),
        tool(
            "strings",
            "Strings the code or relocated pointers refer to, each with its address and the functions that use it. `used by: none` means only a pointer in data refers to it; `xrefs` finds that pointer.",
            json!({ "pattern": pattern("text"), "limit": limit }),
            &[],
        ),
        tool("imports", "Imported functions the code calls, each with the functions that call it.", json!({ "pattern": pattern("import name") }), &[]),
        tool(
            "functions",
            "Lists functions: address, size in bytes, number of calling functions, and name if the binary carries one.",
            json!({
                "pattern": pattern("function name"),
                "limit": limit,
                "sort": { "type": "string", "enum": ["address", "size"], "description": "Ascending address (default) or largest first." },
            }),
            &[],
        ),
        tool(
            "function",
            "One function: its extent, callers, the calls it makes (imports by name), and the strings and globals it refers to. Give `addr` or `name`.",
            json!({
                "addr": addr("Any address inside the function"),
                "name": { "type": "string", "description": "The function's name, or a part of it that only one function has." },
            }),
            &[],
        ),
        tool(
            "xrefs",
            "What refers to an address: call sites if it is a function or an import slot, and the instructions that read or write it or take its address, with the function each is in. If the address holds pointers, such as a vtable or a table of strings, lists what each entry points to.",
            json!({ "addr": addr("The function entry or data address") }),
            &["addr"],
        ),
        tool(
            "decompile",
            "Decompiles functions to C with Ghidra's decompiler. A function that crashes the decompiler or runs out of time is reported and the others still come back.",
            json!({
                "functions": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Hex addresses (anywhere inside a function) or function names." },
                "timeout": { "type": "number", "description": "Seconds each function may take (default 30)." },
            }),
            &["functions"],
        ),
        tool(
            "bytes",
            "Hex dump of bytes as mapped in the image, for reading tables, keys and other data out of its sections.",
            json!({
                "addr": addr("Address of the first byte"),
                "len": { "type": "integer", "minimum": 1, "maximum": MAX_BYTES, "description": "Number of bytes (default 256)." },
            }),
            &["addr"],
        ),
        tool(
            "addr",
            "Converts between an address in the image and an offset in the file, and says what is there. Give `addr` or `offset`.",
            json!({ "addr": addr("Address in the image"), "offset": addr("Offset in the file") }),
            &[],
        ),
    ])
}

/// Runs the tool `name`, or says `None` if there is no such tool. An `Err` is a message for the
/// caller of the tool.
pub fn call(cache: &mut Cache, name: &str, arguments: Value) -> Option<Result<String>> {
    fn run<T: DeserializeOwned>(cache: &mut Cache, name: &str, arguments: Value, tool: fn(&mut Binary, T) -> Result<String>) -> Result<String> {
        let path: PathBuf = arguments.get("path").and_then(Value::as_str).with_context(|| format!("`{name}` needs `path`, the binary to analyze"))?.into();
        let arguments = serde_json::from_value(arguments).map_err(|error| anyhow!("invalid arguments for `{name}`: {error}"))?;
        tool(cache.get(&path)?, arguments)
    }
    Some(match name {
        "summary" => run(cache, name, arguments, summary),
        "strings" => run(cache, name, arguments, strings),
        "imports" => run(cache, name, arguments, imports),
        "functions" => run(cache, name, arguments, functions),
        "function" => run(cache, name, arguments, function),
        "xrefs" => run(cache, name, arguments, xrefs),
        "decompile" => run(cache, name, arguments, decompile),
        "bytes" => run(cache, name, arguments, bytes),
        "addr" => run(cache, name, arguments, addr),
        _ => return None,
    })
}

fn addr_arg(text: &str) -> Result<u64> {
    parse_addr(text).with_context(|| format!("`{text}` is not a hex address"))
}

/// A string's text quoted, cut short if it is long.
fn quoted(text: &str) -> String {
    match text.char_indices().nth(TEXT_SHOWN) {
        Some((cut, _)) => format!("{:?}...(+{} chars)", &text[..cut], text.chars().count() - TEXT_SHOWN),
        None => format!("{text:?}"),
    }
}

/// Function labels on one line, the first few and a count of the rest.
fn labels(binary: &Binary, entries: &BTreeSet<u64>) -> String {
    if entries.is_empty() {
        return "none".into();
    }
    let mut line = entries.iter().take(USERS_SHOWN).map(|&entry| binary.program.label(entry)).collect::<Vec<_>>().join(" ");
    if entries.len() > USERS_SHOWN {
        write!(line, " (+{} more)", entries.len() - USERS_SHOWN).unwrap();
    }
    line
}

/// What lies at a data address, as far as the analysis knows.
fn describe(binary: &Binary, addr: u64) -> String {
    if let Some(string) = binary.program.string_at(addr) {
        return format!("string {}", quoted(&string.text));
    }
    if let Some(name) = binary.program.import_name(addr) {
        return format!("import slot of {name}");
    }
    if binary.program.function(addr).is_some() {
        return format!("function {}", binary.program.label(addr));
    }
    match binary.program.image.section_at(addr) {
        Some(section) if section.executable => format!("code in {}", binary.program.site_label(addr)),
        Some(section) => section.name.clone(),
        None => "not in the file (uninitialized data or unmapped)".into(),
    }
}

/// The run of pointers stored from the data address `addr` on, as `(slot, target)`: a vtable,
/// or a table of strings or handlers. A slot counts while it holds an address inside the image,
/// and is relocated if the image relocates its pointers. The run ends where pointers to code
/// give way to pointers to data or the reverse, which is where one vtable ends and the type
/// information of the next begins.
fn pointer_table(binary: &Binary, addr: u64) -> Vec<(u64, u64)> {
    /// Entries shown. Longer tables can be read on from the last slot.
    const LONGEST: usize = 64;
    let image = &binary.program.image;
    if image.section_at(addr).is_none_or(|section| section.executable) {
        return Vec::new();
    }
    let size = if image.machine == Machine::X86 { 4 } else { 8 };
    let relocated: BTreeSet<u64> = image.relative_targets.iter().map(|&(slot, _)| slot).collect();
    let mut to_code = None;
    (0..LONGEST as u64)
        .map(|index| addr + index * size)
        .map_while(|slot| {
            let bytes = image.bytes_from(slot)?.get(..size as usize)?;
            let target = bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte));
            let section = image.section_at(target).filter(|_| relocated.is_empty() || relocated.contains(&slot))?;
            (*to_code.get_or_insert(section.executable) == section.executable).then_some((slot, target))
        })
        .collect()
}

#[derive(Deserialize)]
struct Summary {}

fn summary(binary: &mut Binary, _: Summary) -> Result<String> {
    let Program { image, analysis, .. } = &binary.program;
    let format = match image.format {
        Format::Elf => "ELF",
        Format::Pe => "PE",
    };
    let machine = match image.machine {
        Machine::X86 => "x86 (32-bit)",
        Machine::X86_64 => "x86-64",
        Machine::Aarch64 => "AArch64",
    };
    let mut out = String::new();
    writeln!(out, "{}: {format}, {machine}, image base {:#x}, entry {:#x}", image.name, image.base, image.entry)?;
    writeln!(
        out,
        "{} functions ({} never return), {} instructions, {} calls, {} imports, {} strings, {} jump tables",
        binary.program.functions().count(),
        binary.program.functions().filter(|f| f.noreturn).count(),
        analysis.instructions,
        analysis.calls.len(),
        analysis.imports.len(),
        analysis.strings.len(),
        analysis.jump_tables.len(),
    )?;
    writeln!(out, "analyzed in {:.0} ms, kept until the file changes", binary.analysis_ms)?;
    writeln!(out, "sections:")?;
    for section in &image.sections {
        let kind = if section.executable { "code" } else if section.writable { "data" } else { "read-only data" };
        let stored = section.file_offset.map_or_else(String::new, |offset| format!(", file offset {offset:#x}"));
        writeln!(out, "  {:#x}-{:#x} {} ({kind}{stored})", section.addr, section.end(), section.name)?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Strings {
    pattern: Option<String>,
    limit: Option<usize>,
}

fn strings(binary: &mut Binary, args: Strings) -> Result<String> {
    let found: Vec<_> = binary.program.analysis.strings.iter().filter(|s| matches(&s.text, args.pattern.as_deref())).collect();
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = String::new();
    writeln!(out, "{} strings{}", found.len(), if found.len() > limit { format!(", first {limit} shown") } else { String::new() })?;
    for string in found.iter().take(limit) {
        let users = binary.program.users(binary.program.refs_to(string.addr).map(|r| r.from));
        // A string no instruction refers to is reached through a pointer in data, which `xrefs` shows.
        writeln!(out, "{:#x} {}{} used by: {}", string.addr, quoted(&string.text), if string.wide { " (UTF-16)" } else { "" }, labels(binary, &users))?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Imports {
    pattern: Option<String>,
}

fn imports(binary: &mut Binary, args: Imports) -> Result<String> {
    let found: Vec<_> = binary.program.analysis.imports.iter().filter(|i| matches(&i.name, args.pattern.as_deref())).collect();
    let mut out = String::new();
    writeln!(out, "{} imports", found.len())?;
    for import in found {
        let callers = binary.program.users(binary.program.calls_to(import.slot).map(|call| call.at));
        writeln!(out, "{} (slot {:#x}){} called by: {}", import.name, import.slot, if import.noreturn { ", never returns" } else { "" }, labels(binary, &callers))?;
    }
    Ok(out)
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Sort {
    #[default]
    Address,
    Size,
}

#[derive(Deserialize)]
struct Functions {
    pattern: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    sort: Sort,
}

fn functions(binary: &mut Binary, args: Functions) -> Result<String> {
    let sizes = binary.program.sizes();
    let size = |entry: u64| sizes.get(&entry).copied().unwrap_or(0);
    // Without a pattern every function is listed; with one, only functions that have a name.
    let mut found: Vec<_> = binary.program.functions().filter(|f| args.pattern.is_none() || f.name.as_deref().is_some_and(|name| matches(name, args.pattern.as_deref()))).collect();
    if let Sort::Size = args.sort {
        found.sort_by_key(|f| std::cmp::Reverse(size(f.addr)));
    }
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = String::new();
    writeln!(out, "{} functions{}", found.len(), if found.len() > limit { format!(", first {limit} shown") } else { String::new() })?;
    writeln!(out, "address size callers name")?;
    for function in found.iter().take(limit) {
        let callers = binary.program.users(binary.program.calls_to(function.addr).map(|call| call.at)).len();
        writeln!(out, "{:#x} {} {callers} {}", function.addr, size(function.addr), function.name.as_deref().unwrap_or("-"))?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Function {
    addr: Option<String>,
    name: Option<String>,
}

fn function(binary: &mut Binary, args: Function) -> Result<String> {
    let entry = match (&args.addr, &args.name) {
        (Some(addr), None) => binary.program.function_at(addr_arg(addr)?)?,
        (None, Some(name)) => binary.program.function_named(name)?,
        _ => bail!("`function` needs either `addr` or `name`"),
    };
    let body = binary.program.body(entry);
    let mut out = String::new();
    let extent: Vec<String> = body.iter().map(|(start, end)| format!("{start:#x}-{end:#x}")).collect();
    let noreturn = binary.program.function(entry).is_some_and(|f| f.noreturn);
    let size: u64 = body.iter().map(|(start, end)| end - start).sum();
    writeln!(out, "function {}: {size} bytes at {}{}", binary.program.label(entry), extent.join(" "), if noreturn { ", never returns" } else { "" })?;

    let callers = binary.program.users(binary.program.calls_to(entry).map(|call| call.at));
    writeln!(out, "called by ({}): {}", callers.len(), labels(binary, &callers))?;

    writeln!(out, "calls:")?;
    for call in body.iter().flat_map(|&(start, end)| binary.program.calls_in(start, end)) {
        let target = match call.target {
            CallTarget::Function(target) => binary.program.label(target),
            CallTarget::Import(slot) => binary.program.import_name(slot).unwrap_or("?").to_string(),
        };
        writeln!(out, "  {:#x} {} {target}", call.at, if call.tail { "tail-calls" } else { "calls" })?;
    }

    // Per address referred to: the instructions that read or write it, and those that take it.
    let mut targets: BTreeMap<u64, [Vec<u64>; 2]> = BTreeMap::new();
    for reference in body.iter().flat_map(|&(start, end)| binary.program.refs_in(start, end)) {
        targets.entry(reference.to).or_default()[usize::from(reference.access)].push(reference.from);
    }
    let sites = |sites: &[u64]| sites.iter().map(|site| format!("{site:#x}")).collect::<Vec<_>>().join(" ");
    let (strings, globals): (Vec<_>, Vec<_>) = targets.iter().partition(|(addr, _)| binary.program.string_at(**addr).is_some());
    writeln!(out, "strings:")?;
    for (addr, [taken, _]) in strings {
        writeln!(out, "  {addr:#x} {} at {}", quoted(&binary.program.string_at(*addr).expect("partitioned on it").text), sites(taken))?;
    }
    writeln!(out, "globals:")?;
    for (addr, [taken, accessed]) in globals {
        let uses: Vec<String> = [("read or written at", accessed), ("address taken at", taken)]
            .into_iter()
            .filter(|(_, at)| !at.is_empty())
            .map(|(how, at)| format!("{how} {}", sites(at)))
            .collect();
        writeln!(out, "  {addr:#x} {}: {}", describe(binary, *addr), uses.join("; "))?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Xrefs {
    addr: String,
}

fn xrefs(binary: &mut Binary, args: Xrefs) -> Result<String> {
    let addr = addr_arg(&args.addr)?;
    let mut out = String::new();
    writeln!(out, "{addr:#x}: {}", describe(binary, addr))?;
    let mut count = 0;
    for call in binary.program.calls_to(addr) {
        writeln!(out, "{:#x} in {} {} it", call.at, binary.program.site_label(call.at), if call.tail { "tail-calls" } else { "calls" })?;
        count += 1;
    }
    for reference in binary.program.refs_to(addr) {
        let how = if reference.access { "reads or writes it" } else { "takes its address" };
        writeln!(out, "{:#x} in {} {how}", reference.from, binary.program.site_label(reference.from))?;
        count += 1;
    }
    // Relocated pointers in data: tables of strings, of functions, of methods. Those inside
    // instructions are the references above.
    for &(slot, _) in binary.program.image.relative_targets.iter().filter(|&&(_, target)| target == addr) {
        if let Some(section) = binary.program.image.section_at(slot).filter(|section| !section.executable) {
            writeln!(out, "{slot:#x} in {} holds a pointer to it", section.name)?;
            count += 1;
        }
    }
    let table = pointer_table(binary, addr);
    if !table.is_empty() {
        writeln!(out, "it holds {} pointer{}:", table.len(), if table.len() == 1 { "" } else { "s" })?;
        for (slot, target) in table {
            writeln!(out, "  {slot:#x} -> {target:#x} {}", describe(binary, target))?;
        }
    }
    if count == 0 {
        writeln!(out, "nothing refers to it directly")?;
        if let Some(entry) = binary.program.owners(addr).first().filter(|&&entry| entry != addr) {
            writeln!(out, "it is inside function {}; references are recorded to function entries and data addresses", binary.program.label(*entry))?;
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Decompile {
    functions: Vec<String>,
    timeout: Option<f64>,
}

fn decompile(binary: &mut Binary, args: Decompile) -> Result<String> {
    ensure!(!args.functions.is_empty(), "`decompile` needs at least one function");
    let timeout = Duration::try_from_secs_f64(args.timeout.unwrap_or(30.0)).map_err(|_| anyhow!("`timeout` must be a positive number of seconds"))?;
    // A name first: `add` is a hex number too. An address in no function is decompiled as it
    // is, for code the analysis did not make a function of.
    let resolve = |text: &String| match (binary.program.function_named(text), parse_addr(text)) {
        (Ok(entry), _) => Ok(entry),
        (Err(_), Some(addr)) if binary.program.image.is_code(addr) => Ok(binary.program.function_at(addr).unwrap_or(addr)),
        (Err(_), Some(addr)) => bail!("{addr:#x} is not code"),
        (Err(error), None) => Err(error),
    };
    let entries: Vec<Result<u64>> = args.functions.iter().map(resolve).collect();

    let mut out = String::new();
    let mut failed = 0;
    for (asked, entry) in args.functions.iter().zip(entries) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failed += 1;
                writeln!(out, "// {asked}: {error:#}\n")?;
                continue;
            }
        };
        let (record, c_text) = binary.decompile(entry, timeout);
        let label = binary.program.label(entry);
        match (record.status, c_text) {
            (Status::Ok, Some(text)) => writeln!(out, "// {label} ({:.0} ms)\n{}\n", record.ms, text.trim())?,
            (status, _) => {
                failed += 1;
                let how = match status {
                    Status::Timeout => "timed out; the decompiler process was replaced",
                    Status::Crash => "crashed the decompiler; its process was replaced",
                    Status::Ok | Status::Error => "failed",
                };
                writeln!(out, "// {label}: {how}: {}\n", record.message.as_deref().unwrap_or("no output"))?;
            }
        }
    }
    // Partial results are results; only a call with nothing to show is an error.
    ensure!(failed < args.functions.len(), "{}", out.trim());
    Ok(out)
}

#[derive(Deserialize)]
struct Bytes {
    addr: String,
    len: Option<usize>,
}

fn bytes(binary: &mut Binary, args: Bytes) -> Result<String> {
    let addr = addr_arg(&args.addr)?;
    let len = args.len.unwrap_or(256);
    ensure!((1..=MAX_BYTES).contains(&len), "`len` must be between 1 and {MAX_BYTES}");
    let image = &binary.program.image;
    let Some(section) = image.section_at(addr) else {
        let mapped: Vec<String> = image.sections.iter().map(|s| format!("{} {:#x}-{:#x}", s.name, s.addr, s.end())).collect();
        bail!("{addr:#x} has no bytes in the file (unmapped, or data that is only zero-filled at load). Mapped: {}", mapped.join(", "));
    };
    let available = image.bytes_from(addr).expect("inside a section");
    let data = &available[..len.min(available.len())];
    let mut out = String::new();
    let stored = section.file_offset.map_or_else(String::new, |offset| format!(", file offset {:#x}", offset + (addr - section.addr)));
    writeln!(out, "{} bytes at {addr:#x} in {}{stored}", data.len(), section.name)?;
    for (index, row) in data.chunks(16).enumerate() {
        let hex: Vec<String> = row.iter().map(|byte| format!("{byte:02x}")).collect();
        let text: String = row.iter().map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' }).collect();
        writeln!(out, "{:08x}  {:<47}  |{text}|", addr + 16 * index as u64, hex.join(" "))?;
    }
    if data.len() < len {
        writeln!(out, "{} ends at {:#x}", section.name, section.end())?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Addr {
    addr: Option<String>,
    offset: Option<String>,
}

fn addr(binary: &mut Binary, args: Addr) -> Result<String> {
    let image = &binary.program.image;
    let (section, addr) = match (&args.addr, &args.offset) {
        (Some(addr), None) => {
            let addr = addr_arg(addr)?;
            (image.section_at(addr).with_context(|| format!("{addr:#x} is not in any section stored in the file"))?, addr)
        }
        (None, Some(offset)) => {
            let offset = addr_arg(offset)?;
            let holds = |start: u64, len: usize| offset >= start && offset < start + len as u64;
            let (section, start) = image
                .sections
                .iter()
                .find_map(|section| Some((section, section.file_offset.filter(|&start| holds(start, section.data.len()))?)))
                .with_context(|| format!("file offset {offset:#x} is not in any mapped section (headers, or data the loader does not map)"))?;
            (section, section.addr + (offset - start))
        }
        _ => bail!("`addr` needs exactly one of `addr` and `offset`"),
    };
    let stored = match section.file_offset {
        Some(start) => format!("file offset {:#x}", start + (addr - section.addr)),
        None => "not stored in the file as mapped".into(),
    };
    Ok(format!("address {addr:#x}, {stored}, in {}: {}\n", section.name, describe(binary, addr)))
}
