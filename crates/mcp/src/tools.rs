//! The tools: what each takes, and the text it answers with.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use recore::image::{Format, Machine};
use recore::program::{Pattern, Program, matches, parse_addr};
use recore::FxHashMap;
use recore::diff::{Change, Evidence};
use recore::report::CallTarget;
use recore_decomp::isolate::Status;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::binary::{Binary, Cache};
use crate::{code, edit};

/// Rows a listing shows unless the caller sets `limit`.
pub(crate) const DEFAULT_LIMIT: usize = 100;
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
    let pattern = |of: &str| json!({ "type": "string", "description": format!("Regular expression matched anywhere in the {of}, ignoring case. Plain text works as a substring.") });
    let function = json!({ "type": "string", "description": "The function: its name, or a hex address anywhere inside it." });
    let timeout = json!({ "type": "number", "description": "Seconds each decompilation may take (default 30)." });
    let limit = json!({ "type": "integer", "minimum": 1, "description": format!("Most rows to return (default {DEFAULT_LIMIT}).") });
    let addr = |what: &str| json!({ "type": "string", "description": format!("{what}, in hex with or without 0x.") });
    json!([
        tool("summary", "What the binary is: format, machine, sections, and how many functions, imports, strings and jump tables were recovered. Analysis is cached, so call this first.", json!({}), &[]),
        tool(
            "strings",
            "Strings the code or relocated pointers refer to, each with its address and the functions that use it. `used by: none` means only a pointer in data refers to it; `xrefs` finds that pointer. C++ class names appear here mangled; `classes` lists them with their vtables.",
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
            "classes",
            "C++ classes recovered from the type information that MSVC, GCC and Clang emit: each with its base classes, its vtable address and its virtual functions in vtable order. A virtual call through slot N of an object goes to entry N here. A class with several vtables is listed once per vtable. Also the Objective-C classes and categories of a Mach-O binary with their methods, and its Swift classes, structs and enums with their fields, the protocols they conform to, and a class's methods in vtable order followed by its overrides.",
            json!({ "pattern": pattern("class name") }),
            &[],
        ),
        tool(
            "addr",
            "Converts between an address in the image and an offset in the file, and says what is there. Give `addr` or `offset`.",
            json!({ "addr": addr("Address in the image"), "offset": addr("Offset in the file") }),
            &[],
        ),
        tool(
            "disassemble",
            "Instructions as Ghidra's listing prints them, grouped into basic blocks with where each block goes next. Each line carries the instruction's bytes and what the analysis knows about it: the function it calls, the string or data it refers to, a switch's targets, a comment. Give `function` for a whole function, or `addr` to start anywhere in code.",
            json!({
                "function": function,
                "addr": addr("Where to start; inside a function this snaps to the instruction it is in"),
                "count": { "type": "integer", "minimum": 1, "description": "Instructions to show (default 500 for a function, 32 from an address)." },
                "pcode": { "type": "boolean", "description": "Also show each instruction's raw p-code: what it does to registers and memory, one operation per line." },
            }),
            &[],
        ),
        tool(
            "pcode",
            "A function's data flow after the decompiler has simplified it: basic blocks, and operations over values that are each assigned once (SSA). Shows exactly what feeds every call, store, branch and return, where the C leaves it implicit.",
            json!({ "function": function, "limit": limit, "timeout": timeout }),
            &["function"],
        ),
        tool(
            "trace",
            "Follows one value through the code, across calls. `param` follows a parameter forward to everything computed from it, into the functions it is passed to. `returns`, or `call` with `arg`, follows a returned value or a call's argument back to the constants, parameters, memory and call results it comes from, out into callers. Values that pass through memory are not followed.",
            json!({
                "function": function,
                "param": { "type": "integer", "minimum": 1, "description": "Parameter to follow forward, from 1: param_1 is 1." },
                "returns": { "type": "boolean", "description": "Follow the returned value backward." },
                "call": addr("A call instruction in the function, to follow one of its arguments backward"),
                "arg": { "type": "integer", "minimum": 1, "description": "Which argument of `call`, from 1." },
                "depth": { "type": "integer", "minimum": 0, "description": "Calls to follow into callees and out to callers (default 2)." },
                "timeout": timeout,
            }),
            &["function"],
        ),
        tool(
            "symbols",
            "Every address that has a name: functions, import slots, vtables, exported data, and the names given with `rename`.",
            json!({ "pattern": pattern("name"), "limit": limit }),
            &[],
        ),
        tool(
            "diff",
            "Compares two builds of one program, such as before and after a patch: which functions changed, which are new and which are gone. Functions are paired by name, by code and by their place among callers and callees, so it works on stripped binaries. With `function`, compares the decompiled C of that one function in the two builds, line by line. `path` is the earlier build.",
            json!({
                "to": { "type": "string", "description": "Path of the later build." },
                "function": { "type": "string", "description": "A function, by its name or address in either build. Shows the lines of its C that the later build dropped and added." },
                "limit": limit,
                "timeout": timeout,
            }),
            &["to"],
        ),
        tool(
            "rename",
            "Names a function (at its entry address), a data address, or with `var` a variable inside a function. The name is saved for this binary and used everywhere from then on, the decompiler's C included. An empty name removes it. Give `addr` and `name`, or several in `names`.",
            json!({
                "addr": addr("A function entry or a data address; with `var`, the function, by address or name"),
                "var": { "type": "string", "description": "A parameter or local variable of the function, as `decompile` spells it now: `param_1`, `local_18`, `uVar3`." },
                "name": { "type": "string", "description": "The new name; empty to remove." },
                "names": { "type": "array", "items": { "type": "object", "properties": { "addr": { "type": "string" }, "var": { "type": "string" }, "name": { "type": "string" } }, "required": ["addr", "name"] }, "description": "Several renames at once, which restarts the decompiler only once." },
            }),
            &[],
        ),
        tool(
            "comment",
            "Attaches a note to an address, saved for this binary and shown by `function`, `disassemble` and `decompile`. Empty text removes it.",
            json!({ "addr": addr("Any address in the image"), "text": { "type": "string", "description": "The note; empty to remove." } }),
            &["addr", "text"],
        ),
        tool(
            "declare",
            "Tells the decompiler about data types, saved for this binary. `code` takes C: `struct`, `union`, `enum` and `typedef` declarations, and `extern` prototypes that set the parameters and return type of a named function, such as `extern int parse(Request *req, char *text);`. A calling convention goes before the return type: `extern __stdcall int f(void);`. `addr` with `type` says what the data at an address is, such as `Config` or `char *`. Sizes are spelled int1, int2, int4, int8, uint1 to uint8, float4, float8; char and void also work.",
            json!({
                "code": { "type": "string", "description": "One or more C declarations." },
                "addr": addr("A data address"),
                "type": { "type": "string", "description": "A type name the decompiler knows; empty to remove." },
            }),
            &[],
        ),
        tool(
            "type",
            "The layout of a data type: size, alignment, and each field of a struct or union with its offset, or the values of an enum. Without `name`, lists what `declare` has recorded.",
            json!({ "name": { "type": "string", "description": "A type name, declared or built in." } }),
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
        "classes" => run(cache, name, arguments, classes),
        "addr" => run(cache, name, arguments, addr),
        "disassemble" => run(cache, name, arguments, code::disassemble),
        "pcode" => run(cache, name, arguments, code::pcode),
        "trace" => run(cache, name, arguments, code::trace),
        "symbols" => run(cache, name, arguments, edit::symbols),
        "diff" => diff(cache, arguments),
        "rename" => run(cache, name, arguments, edit::rename),
        "comment" => run(cache, name, arguments, edit::comment),
        "declare" => run(cache, name, arguments, edit::declare),
        "type" => run(cache, name, arguments, edit::type_),
        _ => return None,
    })
}

#[derive(Deserialize)]
struct Diff {
    path: PathBuf,
    to: PathBuf,
    function: Option<String>,
    limit: Option<usize>,
    timeout: Option<f64>,
}

/// The lines of a function's C with what differs between two builds for no reason of the
/// function's own taken out, so that equal lines compare equal: the numbers the decompiler
/// gives its variables, and addresses. An address of a function becomes the function's entry in
/// the later build, which `in_new` gives, and any other address in the image only says it is one.
fn comparable(c_text: &str, program: &Program, in_new: &dyn Fn(u64) -> Option<u64>) -> Vec<String> {
    let numbered = regex::Regex::new(r"\b(?:[a-z]{1,3}Var\d+|local_[0-9a-f]+|[a-z]+Stack_[0-9a-f]+|extraout_\w+|in_\w+|unaff_\w+)\b").expect("a valid expression");
    let address = regex::Regex::new(r"(0x|_)(?:r0x)?([0-9a-f]{4,16})\b").expect("a valid expression");
    // A bare number is an address only if the code refers to what is there: in an image
    // loaded at zero, a line number or a size is inside some section too.
    let referred_to = |addr: u64| program.refs_to(addr).next().is_some() || program.string_at(addr).is_some();
    let line_key = |line: &str| {
        // `iVar3` and `iVar5` are both an `iVar`: which number a variable got says nothing.
        let line = numbered.replace_all(line.trim(), |found: &regex::Captures| found[0].trim_end_matches(|c: char| c.is_ascii_hexdigit() || c == '_').to_string());
        address
            .replace_all(&line, |found: &regex::Captures| match u64::from_str_radix(&found[2], 16) {
                Ok(addr) if program.function(addr).is_some() => in_new(addr).map_or_else(|| "<function>".to_string(), |entry| format!("<function {entry:#x}>")),
                Ok(addr) if (&found[1] == "_" || referred_to(addr)) && (program.image.section_at(addr).is_some() || program.image.is_zero_filled(addr)) => "<address>".to_string(),
                _ => found[0].to_string(),
            })
            .into_owned()
    };
    // The first line is the tool's own, with the address and the time taken.
    c_text.lines().skip(1).map(line_key).collect()
}

/// For each line of `before` and of `after`, whether the other has it too, in a longest run of
/// lines the two have in common and in the same order.
fn common_lines(before: &[String], after: &[String]) -> (Vec<bool>, Vec<bool>) {
    let (rows, columns) = (before.len(), after.len());
    // lengths[i][j] is the longest common run of before[i..] and after[j..].
    let mut lengths = vec![0u32; (rows + 1) * (columns + 1)];
    let at = |i: usize, j: usize| i * (columns + 1) + j;
    for i in (0..rows).rev() {
        for j in (0..columns).rev() {
            lengths[at(i, j)] = if before[i] == after[j] { lengths[at(i + 1, j + 1)] + 1 } else { lengths[at(i + 1, j)].max(lengths[at(i, j + 1)]) };
        }
    }
    let (mut kept_before, mut kept_after) = (vec![false; rows], vec![false; columns]);
    let (mut i, mut j) = (0, 0);
    while i < rows && j < columns {
        if before[i] == after[j] {
            (kept_before[i], kept_after[j]) = (true, true);
            (i, j) = (i + 1, j + 1);
        } else if lengths[at(i + 1, j)] >= lengths[at(i, j + 1)] {
            i += 1;
        } else {
            j += 1;
        }
    }
    (kept_before, kept_after)
}

/// The C of one function before and after, as the lines that went and the lines that came.
fn diff_function(old: &mut Binary, new: &mut Binary, function: &str, timeout: Duration) -> Result<String> {
    /// Unchanged lines shown around a change.
    const CONTEXT: usize = 2;
    let found = recore::diff::diff(&old.program, &new.program);
    // The function is named as either build knows it.
    let pair = match resolve_function(old, function) {
        Ok(entry) => found.pairs.iter().find(|pair| pair.old == entry).with_context(|| format!("{} has no counterpart in the later build", old.program.label(entry)))?,
        Err(_) => {
            let entry = resolve_function(new, function)?;
            found.pairs.iter().find(|pair| pair.new == entry).with_context(|| format!("{} has no counterpart in the earlier build", new.program.label(entry)))?
        }
    };
    let c_text = |binary: &mut Binary, entry: u64| match binary.decompile(entry, timeout) {
        (_, Some(text)) => Ok(text),
        (record, None) => bail!("{} was not decompiled: {}", binary.program.label(entry), record.message.unwrap_or_default()),
    };
    let (before, after) = (c_text(old, pair.old)?, c_text(new, pair.new)?);
    let paired: FxHashMap<u64, u64> = found.pairs.iter().map(|pair| (pair.old, pair.new)).collect();
    let before_keys = comparable(&before, &old.program, &|entry| paired.get(&entry).copied());
    let after_keys = comparable(&after, &new.program, &|entry| Some(entry));
    ensure!(before_keys.len() * after_keys.len() <= 16_000_000, "the function is too long to compare line by line; `decompile` shows each build's");
    let (kept_before, kept_after) = common_lines(&before_keys, &after_keys);

    // Both texts in one sequence: a line both have, a line only before has, a line only after has.
    let (before_lines, after_lines): (Vec<&str>, Vec<&str>) = (before.lines().skip(1).collect(), after.lines().skip(1).collect());
    let mut merged: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < before_lines.len() || j < after_lines.len() {
        if i < before_lines.len() && !kept_before[i] {
            merged.push(('-', before_lines[i]));
            i += 1;
        } else if j < after_lines.len() && !kept_after[j] {
            merged.push(('+', after_lines[j]));
            j += 1;
        } else {
            merged.push((' ', after_lines[j]));
            (i, j) = (i + 1, j + 1);
        }
    }
    let mut out = String::new();
    writeln!(out, "{} -> {}", old.program.label(pair.old), new.program.label(pair.new))?;
    let changed: Vec<usize> = merged.iter().enumerate().filter(|(_, line)| line.0 != ' ').map(|(index, _)| index).collect();
    if changed.is_empty() {
        let how = match pair.change {
            None => "and so is its code",
            Some(Change::Numbers) => "though numbers in its code differ that the C does not show, such as the line number an assertion reports",
            Some(Change::Code) => "though its instructions differ: the compiler arranged them otherwise",
        };
        writeln!(out, "the C is the same line for line, {how}")?;
        return Ok(out);
    }
    writeln!(out, "- is a line only the earlier build has, + one only the later has; names of variables and addresses that merely moved are not counted as a difference")?;
    let near = |index: usize| changed.iter().any(|&at| at.abs_diff(index) <= CONTEXT);
    let mut skipping = false;
    for (index, (sign, line)) in merged.iter().enumerate() {
        if near(index) {
            writeln!(out, "{sign} {line}")?;
            skipping = false;
        } else if !skipping {
            writeln!(out, "  ...")?;
            skipping = true;
        }
    }
    Ok(out)
}

/// What changed between the build at `path` and the one at `to`.
fn diff(cache: &mut Cache, arguments: Value) -> Result<String> {
    let args: Diff = serde_json::from_value(arguments).map_err(|error| anyhow!("invalid arguments for `diff`: {error}"))?;
    let (old, new) = cache.pair(&args.path, &args.to)?;
    ensure!(old.program.image.machine == new.program.image.machine, "the two are built for different processors, which leaves no code in common");
    if let Some(function) = &args.function {
        let timeout = Duration::try_from_secs_f64(args.timeout.unwrap_or(30.0)).map_err(|_| anyhow!("`timeout` must be a positive number of seconds"))?;
        return diff_function(old, new, function, timeout);
    }
    let (old, new) = (&old.program, &new.program);
    let found = recore::diff::diff(old, new);
    let (old_sizes, new_sizes) = (old.sizes(), new.sizes());
    let size = |sizes: &FxHashMap<u64, u64>, entry: &u64| sizes.get(entry).copied().unwrap_or_default();
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let changed: Vec<_> = found.pairs.iter().filter(|pair| pair.change == Some(Change::Code)).collect();
    let renumbered: Vec<_> = found.pairs.iter().filter(|pair| pair.change == Some(Change::Numbers)).collect();
    let mut out = String::new();
    writeln!(out, "{} functions before, {} after: {} the same, {} changed, {} removed, {} added", old.functions().count(), new.functions().count(), found.pairs.len() - changed.len() - renumbered.len(), changed.len() + renumbered.len(), found.removed.len(), found.added.len())?;
    // What a function refers to, in terms the two builds share: the functions it calls, as
    // the after build knows them, and the strings it uses.
    let paired: FxHashMap<u64, u64> = found.pairs.iter().map(|pair| (pair.old, pair.new)).collect();
    let refers = |program: &Program, entry: u64, in_new: &dyn Fn(u64) -> Option<u64>| -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let body = program.body(entry);
        // A function both builds have is told by its address in each: before, then after.
        let both = |callee: u64, after: u64| if std::ptr::eq(program, new) { new.label(after) } else { format!("{} (after: {})", program.label(callee), new.label(after)) };
        // What each is told apart by, and how it is shown.
        let calls = body.iter().flat_map(|&(start, end)| program.calls_in(start, end)).filter_map(|call| match call.target {
            CallTarget::Import(slot) => program.import_name(slot).map(|name| (name.to_string(), name.to_string())),
            CallTarget::Function(callee) => Some((new.label(in_new(callee)?), both(callee, in_new(callee)?))),
        });
        let strings = body.iter().flat_map(|&(start, end)| program.refs_in(start, end)).filter_map(|reference| Some(quoted(&program.string_at(reference.to)?.text))).map(|text| (text.clone(), text));
        (calls.collect(), strings.collect())
    };
    writeln!(out, "\nchanged, as before -> after with bytes of code{}; `function` with one of them shows how its C differs", shown(changed.len(), limit))?;
    for pair in changed.iter().take(limit) {
        let how = match pair.evidence {
            Evidence::Name => "same name",
            Evidence::Body => "same code",
            Evidence::Callee => "called from the same place",
            Evidence::Callers => "same callers",
            Evidence::Order => "same place among its neighbours",
        };
        let listed = table_names(new, pair.new).first().map_or_else(String::new, |(_, name)| format!(", listed as {name:?}"));
        writeln!(out, "{} {} -> {} {}  ({how}{listed})", old.label(pair.old), size(&old_sizes, &pair.old), new.label(pair.new), size(&new_sizes, &pair.new))?;
        let (calls_before, strings_before) = refers(old, pair.old, &|callee| paired.get(&callee).copied());
        let (calls_after, strings_after) = refers(new, pair.new, &|callee| Some(callee));
        for (what, before, after) in [("calls", &calls_before, &calls_after), ("uses", &strings_before, &strings_after)] {
            for (sign, here, there) in [("no longer", before, after), ("now", after, before)] {
                let listed: Vec<&str> = here.iter().filter(|(key, _)| !there.contains_key(*key)).map(|(_, shown)| shown.as_str()).collect();
                if !listed.is_empty() {
                    writeln!(out, "    {sign} {what} {}", listed.join(", "))?;
                }
            }
        }
    }
    if !renumbered.is_empty() {
        writeln!(out, "\nchanged in numbers only, {}: the same instructions with other constants or offsets, as when a structure gained a field or an assertion moved to another line of the source", renumbered.len())?;
        let pairs: Vec<String> = renumbered.iter().take(limit).map(|pair| format!("{} -> {}", old.label(pair.old), new.label(pair.new))).collect();
        writeln!(out, "{}{}", pairs.join(", "), if renumbered.len() > limit { " ..." } else { "" })?;
    }
    for (title, entries, program, sizes) in [("removed", &found.removed, old, &old_sizes), ("added", &found.added, new, &new_sizes)] {
        writeln!(out, "\n{title}{}{}", shown(entries.len(), limit), if entries.is_empty() { ": none" } else { "" })?;
        for entry in entries.iter().take(limit) {
            writeln!(out, "{} {}", program.label(*entry), size(sizes, entry))?;
        }
    }
    Ok(out)
}

pub(crate) fn addr_arg(text: &str) -> Result<u64> {
    parse_addr(text).with_context(|| format!("`{text}` is not a hex address"))
}

/// The entry of the function `text` names or points into. A name first: `add` is a hex number
/// too.
pub(crate) fn resolve_function(binary: &Binary, text: &str) -> Result<u64> {
    match (binary.program.function_named(text), parse_addr(text)) {
        (Ok(entry), _) => Ok(entry),
        (Err(_), Some(addr)) => binary.program.function_at(addr),
        (Err(error), None) => Err(error),
    }
}

/// The names a function is listed under in tables of the program's data: for each slot that
/// holds a pointer to it, the text the slot before points to. A scripting language's library
/// and a command table pair each function with its name this way.
pub(crate) fn table_names(program: &Program, entry: u64) -> Vec<(u64, String)> {
    let image = &program.image;
    let pointer = if image.machine == Machine::X86 { 4 } else { 8 };
    let target_of = |slot: u64| image.relative_targets.iter().find(|&&(at, _)| at == slot).map(|&(_, target)| target);
    // Read as it lies: a name of two or three letters is too short for `strings` to take.
    let text = |addr: u64| {
        let bytes = image.bytes_from(addr).filter(|_| image.section_at(addr).is_some_and(|section| !section.executable))?;
        let end = bytes.iter().take(64).position(|&byte| byte == 0).filter(|&length| length > 0)?;
        std::str::from_utf8(&bytes[..end]).ok().filter(|text| text.chars().all(|c| c.is_ascii_graphic())).map(str::to_string)
    };
    let slots = image.relative_targets.iter().filter(|&&(slot, target)| target == entry && image.section_at(slot).is_some_and(|section| !section.executable));
    slots.filter_map(|&(slot, _)| Some((slot, text(target_of(slot.checked_sub(pointer)?)?)?))).collect()
}

/// The end of a listing's first line when it has more rows than it shows.
pub(crate) fn shown(found: usize, limit: usize) -> String {
    if found > limit { format!(", first {limit} shown") } else { String::new() }
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

/// The comments on addresses inside `body`, in address order.
fn comments<'a>(binary: &'a Binary, body: &[(u64, u64)]) -> Vec<(u64, &'a str)> {
    let mut found: Vec<(u64, &str)> = body.iter().flat_map(|&(start, end)| binary.edits.comments.range(start..end)).map(|(&addr, text)| (addr, text.as_str())).collect();
    found.sort_unstable();
    found
}

/// What lies at a data address, as far as the analysis knows.
pub(crate) fn describe(binary: &Binary, addr: u64) -> String {
    if let Some((_, name, kind)) = binary.edits.globals(&binary.program.analysis).into_iter().find(|global| global.0 == addr) {
        return format!("{name}{}", kind.map_or_else(String::new, |kind| format!(" ({kind})")));
    }
    if let Some(string) = binary.program.string_at(addr) {
        return format!("string {}", quoted(&string.text));
    }
    if let Some(name) = binary.program.import_name(addr) {
        return format!("import slot of {name}");
    }
    if binary.program.function(addr).is_some() {
        return format!("function {}", binary.program.label(addr));
    }
    if let Some(class) = binary.program.analysis.classes.iter().find(|class| class.vtable == addr) {
        return format!("vtable of {}", class.name);
    }
    match binary.program.image.section_at(addr) {
        Some(section) if section.executable => format!("code in {}", binary.program.site_label(addr)),
        Some(section) => section.name.clone(),
        None if binary.program.image.is_zero_filled(addr) => "uninitialized data".into(),
        None => "not mapped".into(),
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
        Format::MachO => "Mach-O",
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
    let edits = &binary.edits;
    writeln!(out, "edits: {} names, {} named variables, {} comments, {} declarations, {} typed data, saved in {}", edits.names.len(), edits.locals.values().map(|names| names.len()).sum::<usize>(), edits.comments.len(), edits.declarations.len(), edits.types.len(), binary.edits_file()?.display())?;
    writeln!(out, "sections:")?;
    for section in &image.sections {
        let kind = if section.executable { "code" } else if section.writable { "data" } else { "read-only data" };
        let stored = section.file_offset.map_or_else(String::new, |offset| format!(", file offset {offset:#x}"));
        writeln!(out, "  {:#x}-{:#x} {} ({kind}{stored})", section.addr, section.end(), section.name)?;
    }
    for (start, end) in &image.zero_filled {
        writeln!(out, "  {start:#x}-{end:#x} uninitialized data (zero-filled at load, not in the file)")?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Strings {
    pattern: Option<String>,
    limit: Option<usize>,
}

fn strings(binary: &mut Binary, args: Strings) -> Result<String> {
    let pattern = args.pattern.as_deref().map(Pattern::new);
    let found: Vec<_> = binary.program.analysis.strings.iter().filter(|s| matches(&s.text, pattern.as_ref())).collect();
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = String::new();
    writeln!(out, "{} strings{}", found.len(), shown(found.len(), limit))?;
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
    let pattern = args.pattern.as_deref().map(Pattern::new);
    let found: Vec<_> = binary.program.analysis.imports.iter().filter(|i| matches(&i.name, pattern.as_ref())).collect();
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
    let pattern = args.pattern.as_deref().map(Pattern::new);
    let mut found: Vec<_> = binary.program.functions().filter(|f| pattern.is_none() || f.name.as_deref().is_some_and(|name| matches(name, pattern.as_ref()))).collect();
    if let Sort::Size = args.sort {
        found.sort_by_key(|f| std::cmp::Reverse(size(f.addr)));
    }
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = String::new();
    writeln!(out, "{} functions{}", found.len(), shown(found.len(), limit))?;
    writeln!(out, "address size callers name")?;
    for function in found.iter().take(limit) {
        let callers = binary.program.users(binary.program.sites_reaching(function.addr)).len();
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
    if let Some(inside) = args.addr.as_deref().and_then(parse_addr).filter(|&addr| addr != entry) {
        writeln!(out, "{inside:#x} is inside it, not a function of its own")?;
    }

    for (slot, name) in table_names(&binary.program, entry) {
        writeln!(out, "listed as {name:?} in the table at {slot:#x}")?;
    }
    for class in binary.program.analysis.classes.iter().filter(|class| !class.objc) {
        for (index, _) in class.methods.iter().enumerate().filter(|&(_, &method)| method == entry) {
            writeln!(out, "virtual function {index} of {} (vtable {:#x})", class.name, class.vtable)?;
        }
    }
    for (addr, comment) in comments(binary, &body) {
        writeln!(out, "// {addr:#x}: {comment}")?;
    }
    let graph = recore::cfg::cfg(&binary.program.image, &binary.program.analysis, &body);
    writeln!(out, "{} basic blocks, {} instructions; `disassemble` lists them", graph.blocks.len(), graph.instructions.len())?;
    let callers = binary.program.users(binary.program.sites_reaching(entry));
    let by_message = binary.program.sends_to(entry).count();
    let how = if by_message == 0 { String::new() } else { format!(", {by_message} of the call sites by message send") };
    writeln!(out, "called by ({}{how}): {}", callers.len(), labels(binary, &callers))?;

    writeln!(out, "calls:")?;
    for site in &graph.unresolved_calls {
        writeln!(out, "  {site:#x} calls through a register or pointer the analysis could not resolve")?;
    }
    for call in body.iter().flat_map(|&(start, end)| binary.program.calls_in(start, end)) {
        let target = match call.target {
            CallTarget::Function(target) => binary.program.label(target),
            CallTarget::Import(slot) => binary.program.import_name(slot).unwrap_or("?").to_string(),
        };
        // A message send names its selector, and the one method this binary has for it.
        let target = match recore::objc::send_at(&binary.program.analysis, call.at) {
            Some(send) => format!("{}{}", send.label(), send.implementation.map_or_else(String::new, |method| format!(", implemented only by {}", binary.program.label(method)))),
            None => target,
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
    for send in binary.program.sends_to(addr) {
        writeln!(out, "{:#x} in {} sends {}, which only it implements", send.at, binary.program.site_label(send.at), send.label())?;
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
            let named = table_names(&binary.program, addr).into_iter().find(|listed| listed.0 == slot).map_or_else(String::new, |(_, name)| format!(", next to the name {name:?}"));
            writeln!(out, "{slot:#x} in {} holds a pointer to it{named}", section.name)?;
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
            (Status::Ok, Some(text)) => {
                writeln!(out, "// {label} ({:.0} ms)", record.ms)?;
                // The decompiler prints a comment beside the code of its instruction. One on
                // an instruction that left no code of its own is listed here instead.
                for (addr, comment) in comments(binary, &binary.program.body(entry)).into_iter().filter(|(_, comment)| !text.contains(comment)) {
                    writeln!(out, "// {addr:#x}: {comment}")?;
                }
                writeln!(out, "{}\n", text.trim())?;
            }
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

#[derive(Deserialize)]
struct Classes {
    pattern: Option<String>,
}

fn classes(binary: &mut Binary, args: Classes) -> Result<String> {
    let pattern = args.pattern.as_deref().map(Pattern::new);
    let found: Vec<_> = binary.program.analysis.classes.iter().filter(|class| matches(&class.name, pattern.as_ref())).collect();
    let types: Vec<_> = binary.program.analysis.types.iter().filter(|class| matches(&class.name, pattern.as_ref())).collect();
    let mut out = String::new();
    writeln!(out, "{} classes", found.len() + types.len())?;
    for class in found {
        let bases = if class.bases.is_empty() { String::new() } else { format!(" : {}", class.bases.join(", ")) };
        writeln!(out, "{}{bases}, {} {:#x}", class.name, if class.objc { "Objective-C class at" } else { "vtable" }, class.vtable)?;
        for (index, &method) in class.methods.iter().enumerate() {
            // A C++ slot bound to another image's function is listed by the slot's address.
            match binary.program.import_name(method).filter(|_| !class.objc) {
                Some(import) => writeln!(out, "  {index} import {import}")?,
                None if method == 0 => writeln!(out, "  {index} null")?,
                None => writeln!(out, "  {index} {}", binary.program.label(method))?,
            }
        }
    }
    for class in types {
        let bases: Vec<&str> = class.bases.iter().chain(&class.conformances).map(String::as_str).collect();
        let bases = if bases.is_empty() { String::new() } else { format!(" : {}", bases.join(", ")) };
        writeln!(out, "{}{bases}, Swift {} described at {:#x}", class.name, class.kind, class.descriptor)?;
        for field in &class.fields {
            let type_name = field.type_name.as_ref().map_or_else(String::new, |type_name| format!(": {type_name}"));
            writeln!(out, "  {} {}{type_name}", if class.kind == "enum" { "case" } else { "var" }, field.name)?;
        }
        for (index, &method) in class.methods.iter().enumerate().filter(|&(_, &method)| method != 0) {
            writeln!(out, "  {index} {}", binary.program.label(method))?;
        }
    }
    Ok(out)
}
