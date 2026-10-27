//! The tools: what each takes, and the text it answers with.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use recore::image::{Format, Machine};
use recore::program::{Pattern, Program, matches, parse_addr};
use recore::FxHashMap;
use recore::arch::FieldUse;
use recore::diff::{Change, Evidence, Pair};
use recore::report::CallTarget;
use recore::structs::Refusal;
use recore_decomp::ObjectReport;
use recore_decomp::isolate::Status;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::binary::{Binary, Cache};
use crate::{code, edit, emulate};

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
            json!({ "pattern": pattern("text"), "limit": limit, "full": { "type": "boolean", "description": "Print long strings whole. They are cut to 200 characters otherwise." } }),
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
            "What refers to an address, or with `offset` what uses a field of a structure. For an address: call sites if it is a function or an import slot, and the instructions that read or write it or take its address, with the function each is in. If the address holds pointers, such as a vtable or a table of strings, lists what each entry points to.",
            json!({
                "addr": addr("The function entry or data address"),
                "offset": addr("Instead of `addr`: the offset of a field in a structure. Lists the functions that read or write memory at that offset from a register, which is how to find who sets or uses a field"),
                "function": { "type": "string", "description": "With `offset`, look in this function only." },
                "limit": limit,
            }),
            &[],
        ),
        tool(
            "decompile",
            "Decompiles functions to C with Ghidra's decompiler. A function that crashes the decompiler or runs out of time is reported and the others still come back.",
            json!({
                "functions": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Hex addresses (anywhere inside a function) or function names. From a shell, several separated by spaces or commas." },
                "addresses": { "type": "boolean", "description": "Print before each line of C the address of the instruction it came from, to match a line with what `xrefs`, `disassemble` and `comment` say about an address." },
                "around": addr("Show only the lines of C that came from the instructions near this address, with their addresses. The function it is in need not be given"),
                "timeout": { "type": "number", "description": "Seconds each function may take (default 30)." },
            }),
            &[],
        ),
        tool(
            "unnamed",
            "The data addresses the code reads or writes that have no name, the most accessed first, with how many instructions read and write each and the functions they are in. In firmware these are the chip's registers and the program's variables: name the first few with `rename`, or in the names file of the layout, and the code that uses them reads by name.",
            json!({ "space": { "type": "string", "description": "Only the addresses in this memory of an 8051: `sfr`, `xdata` or `idata`." }, "limit": limit }),
            &[],
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
            "What is at an address: a string, a function, a name, or data told by what it holds, with each pointer in it followed to what it reaches. Also converts between the address and its offset in the file. Give `addr` or `offset`.",
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
            "structs",
            "The structs a function's pointers got: each parameter that points to one, and each struct field that points to another, with the struct's name and how much the code reads and writes through it. With `refused`, also each pointer the code reads fields through that got no struct, and why: so `*(int8 *)(param_1 + 0x28)` can be told from a struct that was never tried. Costs one decompilation.",
            json!({
                "function": function,
                "refused": { "type": "boolean", "description": "Also list the pointers that got no struct, with the reason." },
                "timeout": timeout,
            }),
            &["function"],
        ),
        tool(
            "run",
            "Runs a function of the binary as its processor would and answers what it did: the value it returned, the buffers it was given as it left them, and the memory it wrote. This is what the original does on inputs you choose, to check a rewrite against or to show a finding. It runs the function and everything it calls, not the program: imports such as memcpy and malloc run as stand-ins, as do the Windows functions the MSVC C runtime calls (the last error, TLS slots, the heap, critical sections, the version resource, and with `ticks` the clock), a call to any other import stops the run, and memory that nothing wrote and the file does not hold reads as zero, which the answer counts because on a chip that memory is the peripherals. With `snapshot`, memory starts as a live process had it.",
            json!({
                "function": function,
                "args": { "type": "array", "items": { "type": ["integer", "string"] }, "description": "The arguments in order, as the platform's calling convention passes them. A number, decimal or hex as 0x1f; `f32:1.5` or `f64:1.5` for a float, passed where the platform passes floats (the stack on x86-32, XMM registers on x86-64, d0 to d7 on AArch64); `hex:4142` for bytes put in memory and passed by their address; `str:text` for a string with its end; `buf:16` for 16 zero bytes. Buffers are shown as the function left them." },
                "set": { "type": "array", "items": { "type": "string" }, "description": "Registers and memory to set after the arguments are placed: `RDX=5`, `XMM0=f64:2.5` or `ST0=f64:2.5` for a float, which an x87 register holds as an extended float, `0x20000000=hex:0011` for bytes at an address, or `EXTMEM:0x100=hex:09` for bytes in a memory of the processor other than the one the code is in (an 8051 has CODE, INTMEM, EXTMEM, SFR and BITS)." },
                "read": { "type": "array", "items": { "type": "string" }, "description": "Registers to show after the run, besides the one that holds the result. An x87 register, ST0 to ST7, shows as the extended float it holds; `XMM0:f64` or `ST0:f32` shows a float of that size. A float function returns in ST0 on x86-32, in XMM0 on x86-64 and in d0 on AArch64." },
                "dump": { "type": "array", "items": { "type": "string" }, "description": "Memory to show after the run, as ADDRESS:LENGTH or SPACE:ADDRESS:LENGTH, for what a returned pointer reaches." },
                "bits": { "type": "integer", "minimum": 1, "description": "Width of the result in bits, for a function that returns fewer than its register holds (32 for an int)." },
                "steps": { "type": "integer", "minimum": 1, "description": "Most instructions to run (default 10,000,000)." },
                "snapshot": { "type": "string", "description": "A directory holding the memory of a live process, which the run starts from where it holds any: a `snapshot.tsv` of `region START END PERMISSIONS NAME` rows, each region's bytes in `START.bin` with START spelled as the row spells it, and `teb ADDRESS` rows for the threads of a Windows process, the first of which the run is on unless `set` gives FS_OFFSET. `set` and `args` apply on top, and the run keeps its own stack." },
                "before": { "type": "array", "items": { "type": "string" }, "description": "Functions to run first, in order and with no arguments, as setup: their writes are not listed and their instructions not counted. For a C runtime whose startup has not run, such as MSVC's `_mtinit`, which sets up the locks and the thread data its string functions need." },
                "writes": { "type": "string", "description": "A file to write every range of memory the run wrote to, one per line as ADDRESS HEX, where the answer shows the first 16 cut at 64 bytes. For comparing two whole runs." },
                "entered": { "type": "string", "description": "A file to write the entry of every function the run entered to, one per line, in order of address." },
                "timeout": { "type": "number", "description": "Seconds the run may take before it stops, whatever `steps` allows (default 30)." },
                "skip": { "type": "array", "items": { "type": "string" }, "description": "Functions that return as soon as they are entered, as FUNCTION:BYTES with the bytes of arguments each takes off the stack, 0 unless it is stdcall: `0x401230:8`. The result register keeps what it held. For a function the run cannot or need not go through, such as one that draws." },
                "ticks": { "type": "integer", "minimum": 0, "description": "What `GetTickCount` returns, every time it is called, so that a run that reads the clock can be compared with another. Without it a call to GetTickCount stops the run." },
                "coverage": { "type": "boolean", "description": "Run nothing, and list what a run would stop on: the instructions it cannot run and the calls to imports with no stand-in, in `function` and every function it calls, or in the whole binary without `function`. A path that never reaches them still runs; calls through pointers are not followed, and `skip`, `ticks` and `args` are not read. x86 and x86-64 only." },
            }),
            &[],
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
            "Names a function (at its entry address), a data address, with `var` a variable inside a function, or a struct or one of its fields. The name is saved for this binary and used everywhere from then on, the decompiler's C included. An empty name removes it. Give `addr` and `name`, or several in `names`. A struct the decompiler recovered, such as `S_401a20_RDI`, is kept under the name given, with the structs it points to, and callers that pass the pointer on show it too. Giving a second struct a name already taken says the two are one type: their fields merge, or the rename is refused with the offsets that clash. `S_401a20_RDI.field_0x10` names a field.",
            json!({
                "addr": addr("A function entry or a data address; with `var`, the function, by address or name. Or a struct, `Struct.field` for one of its fields"),
                "var": { "type": "string", "description": "A parameter or local variable of the function, as `decompile` spells it now: `param_1`, `local_18`, `uVar3`." },
                "name": { "type": "string", "description": "The new name; empty to remove." },
                "names": { "type": "array", "items": { "type": "object", "properties": { "addr": { "type": "string" }, "var": { "type": "string" }, "name": { "type": "string" } }, "required": ["addr", "name"] }, "description": "Several renames at once." },
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
            "The layout of a data type: size, alignment, and each field of a struct or union with its offset, or the values of an enum. A struct kept with `rename` also lists the functions passed a pointer to it. Without `name`, lists what `declare` and `rename` have recorded.",
            json!({ "name": { "type": "string", "description": "A type name: declared, built in, a struct the decompiler recovered such as `S_401a20_RDI`, or one kept with `rename`." } }),
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
        "unnamed" => run(cache, name, arguments, unnamed),
        "classes" => run(cache, name, arguments, classes),
        "addr" => run(cache, name, arguments, addr),
        "disassemble" => run(cache, name, arguments, code::disassemble),
        "pcode" => run(cache, name, arguments, code::pcode),
        "trace" => run(cache, name, arguments, code::trace),
        "run" => run(cache, name, arguments, emulate::run),
        "symbols" => run(cache, name, arguments, edit::symbols),
        "diff" => diff(cache, arguments),
        "rename" => run(cache, name, arguments, edit::rename),
        "comment" => run(cache, name, arguments, edit::comment),
        "declare" => run(cache, name, arguments, edit::declare),
        "type" => run(cache, name, arguments, edit::type_),
        "structs" => run(cache, name, arguments, structs),
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
/// So does the function a recovered struct is named after, as in `S_88f0_RDI`.
fn comparable(c_text: &str, program: &Program, in_new: &dyn Fn(u64) -> Option<u64>) -> Vec<String> {
    let numbered = regex::Regex::new(r"\b(?:[a-z]{1,3}Var\d+|local_[0-9a-f]+|[a-z]+Stack_[0-9a-f]+|extraout_\w+|in_\w+|unaff_\w+)\b").expect("a valid expression");
    let address = regex::Regex::new(r"(0x|_)(?:r0x)?([0-9a-f]{4,16})\b").expect("a valid expression");
    // The form of `recore::structs::auto_name`.
    let recovered = regex::Regex::new(r"\bS_([0-9a-f]+)_").expect("a valid expression");
    // A bare number is an address only if the code refers to what is there: in an image
    // loaded at zero, a line number or a size is inside some section too.
    let referred_to = |addr: u64| program.refs_to(addr).next().is_some() || program.string_at(addr).is_some();
    let line_key = |line: &str| {
        // `iVar3` and `iVar5` are both an `iVar`: which number a variable got says nothing.
        let line = numbered.replace_all(line.trim(), |found: &regex::Captures| found[0].trim_end_matches(|c: char| c.is_ascii_hexdigit() || c == '_').to_string());
        let line = recovered.replace_all(&line, |found: &regex::Captures| match u64::from_str_radix(&found[1], 16) {
            Ok(addr) if program.function(addr).is_some() => in_new(addr).map_or_else(|| "S_<function>_".to_string(), |entry| format!("S_{entry:x}_")),
            _ => found[0].to_string(),
        });
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

/// The C of the two builds of a paired function as one sequence of lines: `' '` for a line
/// both have, `'-'` for one only the earlier build has, `'+'` for one only the later has.
fn changed_lines(old: &mut Binary, new: &mut Binary, pair: &Pair, paired: &FxHashMap<u64, u64>, timeout: Duration) -> Result<Vec<(char, String)>> {
    let c_text = |binary: &mut Binary, entry: u64| match binary.decompile(entry, timeout) {
        (_, Some(text)) => Ok(text),
        (record, None) => bail!("{} was not decompiled: {}", binary.program.label(entry), record.message.unwrap_or_default()),
    };
    let (before, after) = (c_text(old, pair.old)?, c_text(new, pair.new)?);
    let before_keys = comparable(&before, &old.program, &|entry| paired.get(&entry).copied());
    let after_keys = comparable(&after, &new.program, &|entry| Some(entry));
    ensure!(before_keys.len() * after_keys.len() <= 16_000_000, "the function is too long to compare line by line; `decompile` shows each build's");
    let (kept_before, kept_after) = common_lines(&before_keys, &after_keys);
    let (before_lines, after_lines): (Vec<&str>, Vec<&str>) = (before.lines().skip(1).collect(), after.lines().skip(1).collect());
    let mut merged = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < before_lines.len() || j < after_lines.len() {
        if i < before_lines.len() && !kept_before[i] {
            merged.push(('-', before_lines[i].to_string()));
            i += 1;
        } else if j < after_lines.len() && !kept_after[j] {
            merged.push(('+', after_lines[j].to_string()));
            j += 1;
        } else {
            merged.push((' ', after_lines[j].to_string()));
            (i, j) = (i + 1, j + 1);
        }
    }
    Ok(merged)
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
    let paired: FxHashMap<u64, u64> = found.pairs.iter().map(|pair| (pair.old, pair.new)).collect();
    let merged = changed_lines(old, new, pair, &paired, timeout)?;
    let mut out = String::new();
    writeln!(out, "{} -> {}", old.program.label(pair.old), new.program.label(pair.new))?;
    let changed: Vec<usize> = merged.iter().enumerate().filter(|(_, line)| line.0 != ' ').map(|(index, _)| index).collect();
    if changed.is_empty() {
        let how = match pair.change {
            Change::Same => "and so is its code",
            Change::Numbers => "though numbers in its code differ that the C does not show",
            Change::Code => "though its instructions differ: the compiler arranged them otherwise",
            Change::Unknown => "but whether its instructions differ is not known: recore could not compare them",
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
    let found = recore::diff::diff(&old.program, &new.program);
    let paired: FxHashMap<u64, u64> = found.pairs.iter().map(|pair| (pair.old, pair.new)).collect();
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    // What the C of each changed function lost and gained, for the first of them: the lines
    // of its body, without its header, whose types the decompiler guesses anew in each build.
    /// Changed functions whose C is compared, and lines shown of each.
    const COMPARED: usize = 12;
    const LINES: usize = 8;
    let timeout = Duration::try_from_secs_f64(args.timeout.unwrap_or(30.0)).map_err(|_| anyhow!("`timeout` must be a positive number of seconds"))?;
    let mut in_c: FxHashMap<u64, Vec<String>> = FxHashMap::default();
    for pair in found.pairs.iter().filter(|pair| pair.change == Change::Code).take(limit.min(COMPARED)) {
        let Ok(merged) = changed_lines(old, new, pair, &paired, timeout) else { continue };
        let body = merged.iter().position(|(_, line)| line.trim().is_empty() && merged.first().is_some()).map_or(0, |blank| merged[blank + 1..].iter().position(|(_, line)| line.trim().is_empty()).map_or(blank, |next| blank + 1 + next));
        let changed: Vec<String> = merged[body..].iter().filter(|(sign, line)| *sign != ' ' && !line.trim().is_empty()).map(|(sign, line)| format!("{sign} {}", line.trim())).collect();
        in_c.insert(pair.old, changed);
    }
    let (old, new) = (&old.program, &new.program);
    let (old_sizes, new_sizes) = (old.sizes(), new.sizes());
    let size = |sizes: &FxHashMap<u64, u64>, entry: &u64| sizes.get(entry).copied().unwrap_or_default();
    let changed: Vec<_> = found.pairs.iter().filter(|pair| pair.change == Change::Code).collect();
    let renumbered: Vec<_> = found.pairs.iter().filter(|pair| pair.change == Change::Numbers).collect();
    let count = |change: Change| found.pairs.iter().filter(|pair| pair.change == change).count();
    let (same, unknown) = (count(Change::Same), count(Change::Unknown));
    let mut out = String::new();
    let not_compared = if unknown == 0 { String::new() } else { format!(", {unknown} whose code could not be compared") };
    writeln!(out, "{} functions before, {} after: {same} the same, {} changed{not_compared}, {} removed, {} added", old.functions().count(), new.functions().count(), changed.len() + renumbered.len(), found.removed.len(), found.added.len())?;
    // What a function refers to, in terms the two builds share: the functions it calls, as
    // the after build knows them, and the strings it uses.
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
    writeln!(out, "\nchanged, as before -> after with bytes of code{}; under each, lines of C only the earlier (-) or the later (+) build has, which `function` shows in full", shown(changed.len(), limit))?;
    for pair in changed.iter().take(limit) {
        let how = match pair.evidence {
            Evidence::Name => "same name",
            Evidence::Body => "same code",
            Evidence::Callee => "called from the same place",
            // Being called from the same places does not make it the same function.
            Evidence::Callers => "same callers: this function changed, or another took its place",
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
        if let Some(lines) = in_c.get(&pair.old) {
            for line in lines.iter().take(LINES) {
                writeln!(out, "    {line}")?;
            }
            match lines.len() {
                0 => writeln!(out, "    the C reads the same")?,
                more if more > LINES => writeln!(out, "    ...{}", cut(LINES, more, "differing lines ", &format!("`function` {:#x} shows all", pair.old)))?,
                _ => {}
            }
        }
    }
    if !renumbered.is_empty() {
        /// Numbers shown for each function.
        const NUMBERS: usize = 6;
        writeln!(out, "\nchanged in numbers only, {}{}: the same instructions with other constants or offsets, as when a structure gained a field or an assertion moved to another line of the source; after each, the numbers that differ, before -> after", renumbered.len(), shown(renumbered.len(), limit))?;
        let slots = |program: &Program| -> FxHashMap<u64, u64> { program.image.relative_targets.iter().copied().collect() };
        let (old_slots, new_slots) = (slots(old), slots(new));
        // The numbers of a function's code, in order over all of its body.
        let numbers = |program: &Program, slots: &FxHashMap<u64, u64>, entry: u64| -> Vec<u64> {
            program.body(entry).into_iter().flat_map(|(start, end)| recore::signature::numbers(&program.image, slots, start, end)).collect()
        };
        for pair in renumbered.iter().take(limit) {
            let (before, after) = (numbers(old, &old_slots, pair.old), numbers(new, &new_slots, pair.new));
            let differ: Vec<String> = if before.len() == after.len() { before.iter().zip(&after).filter(|(a, b)| a != b).map(|(a, b)| format!("{a:#x} -> {b:#x}")).collect() } else { Vec::new() };
            let listed = differ.iter().take(NUMBERS).cloned().collect::<Vec<_>>().join(", ");
            writeln!(out, "{} -> {}  {listed}{}", old.label(pair.old), new.label(pair.new), cut(NUMBERS, differ.len(), "", &format!("`diff` with `function` {:#x} shows the C", pair.old)))?;
        }
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

/// How an address written with decimal digits only was read, for an error about it: addresses
/// are hex with or without `0x`, and `29760` is not the decimal number.
fn read_as_hex(text: &str) -> String {
    let text = text.trim();
    match text.parse::<u64>() {
        Ok(decimal) if decimal >= 10 => format!(" (`{text}` is read as hex, 0x{text}; decimal {text} is {decimal:#x})"),
        _ => String::new(),
    }
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

/// The names something is listed under in tables of the program's data: for each slot that
/// holds a pointer to it, the text its partner in the table points to. A scripting language's
/// library pairs each function with its name this way, and a table of types each type with
/// its. In a table of pairs, which neighbour is the partner shows from where the run of
/// pointers begins: the slots pair up from there, name first in one table and second in
/// another. A wider record, which may hold a number among its pointers, opens with its name,
/// as a Python module's list of functions does.
pub(crate) fn table_names(program: &Program, entry: u64) -> Vec<(u64, String)> {
    /// How many slots back from the slot the name that opens its record is looked for.
    const FIELDS: u64 = 8;
    let image = &program.image;
    let pointer = image.machine.pointer_size();
    let target_of = |slot: u64| image.relative_targets.iter().find(|&&(at, _)| at == slot).map(|&(_, target)| target);
    let name_at = |slot: u64| short_text(image, target_of(slot)?);
    let named = |slot: u64| name_at(slot).is_some();
    let partner = |slot: u64| {
        let mut neighbours = [slot.checked_sub(pointer), slot.checked_add(pointer)].into_iter().flatten().filter(|&at| named(at));
        let pairs = neighbours.any(|name| name.checked_sub(2 * pointer).is_some_and(named) || named(name + 2 * pointer));
        if pairs {
            let before = (1..).take_while(|back| slot.checked_sub(back * pointer).is_some_and(|earlier| target_of(earlier).is_some())).count() as u64;
            // An even number of pointers before it: the slot opens a pair, and its partner follows.
            let partner = if before.is_multiple_of(2) { slot + pointer } else { slot - pointer };
            name_at(partner)
        } else {
            (1..=FIELDS).map_while(|back| slot.checked_sub(back * pointer)).find_map(name_at)
        }
    };
    let slots = image.relative_targets.iter().filter(|&&(slot, target)| target == entry && image.section_at(slot).is_some_and(|section| !section.executable));
    slots.filter_map(|&(slot, _)| Some((slot, partner(slot)?))).collect()
}

/// The text at `addr` read as it lies in data, when it is a short run of printable characters
/// that ends in a zero: a name of two or three letters is too short for `strings` to take.
fn short_text(image: &recore::Image, addr: u64) -> Option<String> {
    let bytes = image.bytes_from(addr).filter(|_| image.section_at(addr).is_some_and(|section| !section.executable))?;
    let end = bytes.iter().take(64).position(|&byte| byte == 0).filter(|&length| length > 0)?;
    std::str::from_utf8(&bytes[..end]).ok().filter(|text| text.chars().all(|c| c.is_ascii_graphic())).map(str::to_string)
}

/// The function names a function's failed assertions would report: `assert` passes the name
/// of the function it was written in, and that text is in the program. It is the function's own
/// name unless the assertion came with a function the compiler inlined, so it is a hint.
pub(crate) fn asserted_names(program: &Program, entry: u64) -> BTreeSet<String> {
    /// How far before the call the instructions that load its arguments are looked for.
    const REACH: u64 = 0x28;
    let identifier = |text: &str| text.len() >= 3 && !text.starts_with(|c: char| c.is_ascii_digit()) && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    let body = program.body(entry);
    let asserts = body.iter().flat_map(|&(start, end)| program.calls_in(start, end)).filter(|call| matches!(call.target, CallTarget::Import(slot) if matches!(program.import_name(slot), Some("__assert_fail" | "__assert_rtn" | "__assert"))));
    asserts.flat_map(|call| program.refs_in(call.at.saturating_sub(REACH), call.at)).filter_map(|reference| Some(program.string_at(reference.to)?.text.clone())).filter(|text| identifier(text)).collect()
}

/// The end of a listing's first line when it has more rows than it shows.
pub(crate) fn shown(found: usize, limit: usize) -> String {
    cut(limit, found, "", &format!("`limit` {found} shows all"))
}

/// What an answer says wherever it leaves something out, so that a part is never taken for
/// the whole: how many of how many it shows, and what to ask to get the rest. Every tool that
/// shortens its answer says so through this. Empty when nothing is left out.
pub(crate) fn cut(shown: usize, total: usize, what: &str, rest: &str) -> String {
    if total > shown { format!(" ({shown} of {total} {what}shown; {rest})") } else { String::new() }
}

/// A string's text quoted, cut short if it is long.
fn quoted(text: &str) -> String {
    match text.char_indices().nth(TEXT_SHOWN) {
        Some((end, _)) => format!("{:?}...{}", &text[..end], cut(TEXT_SHOWN, text.chars().count(), "characters ", "`strings` with `full` shows it whole")),
        None => format!("{text:?}"),
    }
}

/// Function labels on one line, the first few and a count of the rest.
/// `rest` says what lists them all.
fn labels(binary: &Binary, entries: &BTreeSet<u64>, rest: &str) -> String {
    if entries.is_empty() {
        return "none".into();
    }
    let line = entries.iter().take(USERS_SHOWN).map(|&entry| binary.program.label(entry)).collect::<Vec<_>>().join(" ");
    line + &cut(USERS_SHOWN, entries.len(), "", rest)
}

/// The first slots at `addr` when one of them is a pointer, as `{"files", function 0x1402534f0,
/// 0x8}`: each pointer as what it reaches, followed `depth` pointers deep, and other values as
/// numbers. Numbers alone are raw data, which `bytes` shows.
fn holding(binary: &Binary, addr: u64, depth: usize) -> Option<String> {
    let table = pointer_table(binary, addr, RECORD, RECORD);
    if depth == 0 || !table.iter().any(|(_, held)| held.is_ok()) {
        return None;
    }
    let program = &binary.program;
    let brief = |text: &str| match text.char_indices().nth(BRIEF) {
        Some((end, _)) => format!("{:?}...", &text[..end]),
        None => format!("{text:?}"),
    };
    let slots: Vec<String> = table
        .iter()
        .map(|&(_, held)| match held {
            Ok(target) if program.function(target).is_some() => format!("function {}", program.label(target)),
            Ok(target) => match program.string_at(target).map(|string| string.text.clone()).or_else(|| short_text(&program.image, target)) {
                Some(text) => brief(&text),
                None => format!("{target:#x} {}", describe_to(binary, target, depth - 1)),
            },
            Err(value) => format!("{value:#x}"),
        })
        .collect();
    let more = if table.len() == RECORD { ", ..." } else { "" };
    Some(format!("{{{}{more}}}", slots.join(", ")))
}

/// The comments on addresses inside `body`, in address order.
fn comments<'a>(binary: &'a Binary, body: &[(u64, u64)]) -> Vec<(u64, &'a str)> {
    let mut found: Vec<(u64, &str)> = body.iter().flat_map(|&(start, end)| binary.edits.comments.range(start..end)).map(|(&addr, text)| (addr, text.as_str())).collect();
    found.sort_unstable();
    found
}

/// What lies at a data address, as far as the analysis knows. Data that has no name of its own
/// is told by what it holds, its pointers followed to what they reach.
pub(crate) fn describe(binary: &Binary, addr: u64) -> String {
    describe_to(binary, addr, FOLLOWED)
}

/// How many pointers deep `describe` follows data.
const FOLLOWED: usize = 2;
/// The slots of a record `describe` shows, and the characters of each string in it.
const RECORD: usize = 4;
const BRIEF: usize = 40;

fn describe_to(binary: &Binary, addr: u64, depth: usize) -> String {
    let held = || holding(binary, addr, depth).map_or_else(String::new, |record| format!(", holding {record}"));
    if let Some((_, name, kind)) = binary.edits.globals(&binary.program.analysis).into_iter().find(|global| global.0 == addr) {
        return format!("{name}{}{}", kind.map_or_else(String::new, |kind| format!(" ({kind})")), held());
    }
    if let Some(string) = binary.program.string_at(addr) {
        return format!("string {}", quoted(&string.text));
    }
    // Text too short to be among the strings, as `xrefs` shows it where a table points to it.
    let pointed_to = || binary.program.image.relative_targets.iter().any(|&(_, target)| target == addr);
    if let Some(text) = short_text(&binary.program.image, addr).filter(|_| pointed_to()) {
        return format!("text {text:?}");
    }
    if let Some(name) = binary.program.image.symbol_names.get(&addr).filter(|_| binary.program.function(addr).is_none()) {
        let image = &binary.program.image;
        // A raw image carries no names: its layout gives them, with its machine or in a names file.
        let source = if image.format == Format::Raw { "a name the layout gives" } else { "a name the file carries" };
        let bits: Vec<String> = recore::hardware::bits(image, addr).into_iter().map(|(bit, name)| format!("{name} is bit {bit:#x}")).collect();
        return format!("{name}, {source}{}{}", if bits.is_empty() { String::new() } else { format!(" ({})", bits.join(", ")) }, held());
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
        Some(section) => match holding(binary, addr, depth) {
            Some(record) => format!("{} holding {record}", section.name),
            None => section.name.clone(),
        },
        // On a machine with several memories, which one says more than that it holds no bytes.
        None if binary.program.image.is_zero_filled(addr) && recore::hardware::space(&binary.program.image, addr).is_some() => recore::hardware::place(&binary.program.image, addr),
        None if binary.program.image.is_zero_filled(addr) => "uninitialized data".into(),
        None => "not mapped".into(),
    }
}

/// What the data at `addr` holds, a pointer-sized slot at a time: `Ok` a pointer the loader
/// relocates and `Err` any other value, such as a count, a flag or the null that ends a list.
/// Stops at `longest` slots, after two that are not pointers in a row, or where something
/// else in the program begins. Empty when no slot is a pointer.
fn pointer_table(binary: &Binary, addr: u64, longest: usize, numbers: usize) -> Vec<(u64, Result<u64, u64>)> {
    let program = &binary.program;
    let image = &program.image;
    if image.section_at(addr).is_none_or(|section| section.executable) {
        return Vec::new();
    }
    let size = image.machine.pointer_size();
    let relocated: FxHashMap<u64, u64> = image.relative_targets.iter().copied().collect();
    let begins_another = |slot: u64| slot != addr && (program.refs_to(slot).next().is_some() || program.string_at(slot).is_some());
    let mut slots = Vec::new();
    for slot in (0..longest as u64).map(|index| addr + index * size) {
        let Some(bytes) = image.bytes_from(slot).and_then(|bytes| bytes.get(..size as usize)).filter(|_| !begins_another(slot)) else { break };
        let value = bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte));
        // Without relocations to say so, a value that lies in the image is taken for a pointer.
        let pointer = if relocated.is_empty() { image.section_at(value).is_some() } else { relocated.contains_key(&slot) };
        slots.push((slot, if pointer { Ok(value) } else { Err(value) }));
        if slots.len() >= numbers && slots[slots.len() - numbers..].iter().all(|(_, held)| held.is_err()) {
            break;
        }
    }
    while matches!(slots.last(), Some((_, Err(_)))) {
        slots.pop();
    }
    slots
}

#[derive(Deserialize)]
struct Unnamed {
    space: Option<String>,
    limit: Option<usize>,
}

fn unnamed(binary: &mut Binary, args: Unnamed) -> Result<String> {
    let program = &binary.program;
    let is_named = |addr: u64| program.image.symbol_names.contains_key(&addr) || binary.edits.names.contains_key(&addr);
    let space = |addr: u64| recore::hardware::space(&program.image, addr).map(|(space, _)| space);
    let mut found = recore::hardware::unnamed(program, is_named);
    let mut spaces: BTreeMap<&str, usize> = BTreeMap::new();
    found.iter().filter_map(|accessed| space(accessed.addr)).for_each(|space| *spaces.entry(space).or_default() += 1);
    if let Some(wanted) = &args.space {
        ensure!(spaces.contains_key(wanted.as_str()), "no unnamed address is in a space called `{wanted}`: the code reaches {}", if spaces.is_empty() { "one space only".to_string() } else { spaces.keys().copied().collect::<Vec<_>>().join(", ") });
        found.retain(|accessed| space(accessed.addr) == Some(wanted));
    }
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = String::new();
    let within = match &args.space {
        Some(space) => format!(" in {space}"),
        None if spaces.is_empty() => String::new(),
        None => format!(": {}", spaces.iter().map(|(space, count)| format!("{count} in {space}")).collect::<Vec<_>>().join(", ")),
    };
    writeln!(out, "{} data addresses without a name{within}{}", found.len(), shown(found.len(), limit))?;
    for accessed in found.iter().take(limit) {
        let place = recore::hardware::place(&program.image, accessed.addr);
        writeln!(out, "{:#x} {place}: {} reads, {} writes, in {} functions: {}", accessed.addr, accessed.reads, accessed.writes, accessed.functions.len(), labels(binary, &accessed.functions, &format!("xrefs {:#x}", accessed.addr)))?;
    }
    Ok(out)
}

#[derive(Deserialize)]
struct Summary {}

fn summary(binary: &mut Binary, _: Summary) -> Result<String> {
    let Program { image, analysis, .. } = &binary.program;
    let format = match image.format {
        Format::Elf => "ELF",
        Format::Pe => "PE",
        Format::MachO => "Mach-O",
        Format::Raw => "raw",
    };
    let machine = match image.machine {
        Machine::X86 => "x86 (32-bit)",
        Machine::X86_64 => "x86-64",
        Machine::Aarch64 => "AArch64",
        Machine::I8051 => "8051",
        Machine::Thumb => "Cortex-M (Thumb)",
        Machine::Arm => "ARM (32-bit, A32 and Thumb)",
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
    if let Some(banking) = recore::i8051::banking_summary(image, analysis) {
        writeln!(out, "{banking}")?;
    }
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
    #[serde(default)]
    full: bool,
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
        let text = if args.full { format!("{:?}", string.text) } else { quoted(&string.text) };
        writeln!(out, "{:#x} {text}{} used by: {}", string.addr, if string.wide { " (UTF-16)" } else { "" }, labels(binary, &users, &format!("`xrefs` of {:#x} lists all", string.addr)))?;
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
        writeln!(out, "{} (slot {:#x}){} called by: {}", import.name, import.slot, if import.noreturn { ", never returns" } else { "" }, labels(binary, &callers, &format!("`xrefs` of {:#x} lists all", import.slot)))?;
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
    let asserted = asserted_names(&binary.program, entry);
    if !asserted.is_empty() {
        writeln!(out, "its assertions name {}: its own name, or that of a function compiled into it", asserted.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", "))?;
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
    writeln!(out, "called by ({}{how}): {}", callers.len(), labels(binary, &callers, &format!("`xrefs` of {entry:#x} lists all")))?;

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
    if let Some(next) = binary.program.function(entry).and_then(|function| function.runs_on) {
        writeln!(out, "  runs on into {}, which returns for both", binary.program.label(next))?;
    }

    // Per address referred to: the instructions that read or write it, and those that take it.
    let mut targets: BTreeMap<u64, [Vec<u64>; 2]> = BTreeMap::new();
    for reference in body.iter().flat_map(|&(start, end)| binary.program.refs_in(start, end)) {
        targets.entry(reference.to).or_default()[usize::from(reference.access)].push(reference.from);
    }
    let sites = |sites: &[u64]| sites.iter().map(|site| format!("{site:#x}")).collect::<Vec<_>>().join(" ");
    let (mut strings, globals): (Vec<_>, Vec<_>) = targets.iter().partition(|(addr, _)| binary.program.string_at(**addr).is_some());
    // In the order the code comes to them, which for the messages of a function is their order.
    strings.sort_by_key(|(_, [taken, accessed])| taken.iter().chain(accessed).min().copied());
    writeln!(out, "strings, in the order the code uses them:")?;
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
    addr: Option<String>,
    offset: Option<String>,
    function: Option<String>,
    limit: Option<usize>,
}

/// The instructions that reach memory at `offset` from a register, by function: where code
/// uses the field at that offset of some structure.
fn field_xrefs(binary: &Binary, offset: u64, function: Option<&str>, limit: usize) -> Result<String> {
    let program = &binary.program;
    let only = function.map(|function| resolve_function(binary, function)).transpose()?;
    let mut rows: Vec<(u64, Vec<(u64, FieldUse)>)> = program
        .functions()
        .filter(|candidate| only.is_none_or(|entry| entry == candidate.addr))
        .map(|candidate| (candidate.addr, recore::cfg::field_uses(&program.image, &program.body(candidate.addr), offset)))
        .filter(|(_, uses)| !uses.is_empty())
        .collect();
    rows.sort_by_key(|(entry, _)| *entry);
    let mut out = String::new();
    writeln!(out, "{} functions reach memory at {offset:#x} from a register{}", rows.len(), shown(rows.len(), limit))?;
    writeln!(out, "these are the uses of a field at that offset of any structure; whether it is the same structure is for the code to show")?;
    for (entry, uses) in rows.iter().take(limit) {
        let by = |wanted: FieldUse| uses.iter().filter(|used| used.1 == wanted).map(|used| format!("{:#x}", used.0)).collect::<Vec<_>>().join(" ");
        let parts: Vec<String> = [("writes at", FieldUse::Write), ("reads at", FieldUse::Read), ("takes its address at", FieldUse::Address)].into_iter().filter(|(_, wanted)| uses.iter().any(|used| used.1 == *wanted)).map(|(how, wanted)| format!("{how} {}", by(wanted))).collect();
        writeln!(out, "{} {}", program.label(*entry), parts.join("; "))?;
    }
    Ok(out)
}

fn xrefs(binary: &mut Binary, args: Xrefs) -> Result<String> {
    let addr = match (&args.addr, &args.offset) {
        (Some(addr), None) => addr_arg(addr)?,
        (None, Some(offset)) => return field_xrefs(binary, addr_arg(offset)?, args.function.as_deref(), args.limit.unwrap_or(DEFAULT_LIMIT)),
        _ => bail!("`xrefs` needs either `addr` or `offset`"),
    };
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let program = &binary.program;
    // What refers to it, the fewest and most telling first: pointers in data, which are tables
    // of strings, of functions, of methods, then calls, then the instructions that use it.
    let mut lines = Vec::new();
    for &(slot, _) in program.image.relative_targets.iter().filter(|&&(_, target)| target == addr) {
        if let Some(section) = program.image.section_at(slot).filter(|section| !section.executable) {
            let named = table_names(program, addr).into_iter().find(|listed| listed.0 == slot).map_or_else(String::new, |(_, name)| format!(", paired with the name {name:?}"));
            lines.push(format!("{slot:#x} in {} holds a pointer to it{named}", section.name));
        }
    }
    lines.extend(program.calls_to(addr).map(|call| format!("{:#x} in {} {} it", call.at, program.site_label(call.at), if call.tail { "tail-calls" } else { "calls" })));
    lines.extend(program.functions().filter(|function| function.runs_on == Some(addr)).map(|function| format!("{} runs on into it", program.label(function.addr))));
    lines.extend(program.sends_to(addr).map(|send| format!("{:#x} in {} sends {}, which only it implements", send.at, program.site_label(send.at), send.label())));
    lines.extend(program.refs_to(addr).map(|reference| format!("{:#x} in {} {}", reference.from, program.site_label(reference.from), if reference.access { "reads or writes it" } else { "takes its address" })));
    let count = lines.len();
    let mut out = String::new();
    writeln!(out, "{addr:#x}: {}", describe(binary, addr))?;
    if count > 0 {
        writeln!(out, "{count} references{}", shown(count, limit))?;
    }
    for line in lines.iter().take(limit) {
        writeln!(out, "{line}")?;
    }
    let table = pointer_table(binary, addr, limit.min(64), 2);
    if !table.is_empty() {
        writeln!(out, "it holds, a slot at a time:")?;
        for (slot, held) in &table {
            match held {
                // A name too short to be among the strings is still read where a table points to it.
                Ok(target) => match short_text(&program.image, *target).filter(|_| program.string_at(*target).is_none() && program.function(*target).is_none()) {
                    Some(text) => writeln!(out, "  {slot:#x} -> {target:#x} text {text:?}")?,
                    None => writeln!(out, "  {slot:#x} -> {target:#x} {}", describe(binary, *target))?,
                },
                Err(value) => writeln!(out, "  {slot:#x} {value:#x}, not a pointer")?,
            }
        }
        if table.len() == limit.min(64) {
            let next = table.last().expect("not empty").0 + program.image.machine.pointer_size();
            writeln!(out, "  ... the table may go on; `xrefs` of {next:#x} reads on")?;
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
    #[serde(default)]
    functions: Vec<String>,
    #[serde(default)]
    addresses: bool,
    around: Option<String>,
    timeout: Option<f64>,
}

/// The lines of C printed with addresses that are nearest the instruction at `addr`: the line
/// that came from it or from the last instruction before it, and a few on each side.
fn around(c_text: &str, addr: u64) -> String {
    /// Lines shown on each side.
    const REACH: usize = 8;
    let lines: Vec<&str> = c_text.lines().collect();
    let at = |line: &&str| line.split_once('|').and_then(|(column, _)| u64::from_str_radix(column.trim(), 16).ok());
    let nearest = lines.iter().enumerate().filter_map(|(index, line)| Some((index, at(line)?))).filter(|&(_, from)| from <= addr).max_by_key(|&(index, from)| (from, std::cmp::Reverse(index)));
    let Some((index, _)) = nearest else { return c_text.to_string() };
    let (start, end) = (index.saturating_sub(REACH), (index + REACH + 1).min(lines.len()));
    let mut out = String::new();
    if start > 0 {
        // The function's own line says what the parameters in the lines shown are.
        let header = lines.iter().position(|line| line.contains('(')).unwrap_or(0);
        out += &format!("{}\n  ...\n", lines[header]);
    }
    out += &lines[start..end].join("\n");
    out + &format!("\n  ...{}", cut(end - start, lines.len(), "lines ", "`decompile` without `around` shows all"))
}

#[derive(Deserialize)]
struct Structs {
    function: String,
    #[serde(default)]
    refused: bool,
    timeout: Option<f64>,
}

fn structs(binary: &mut Binary, args: Structs) -> Result<String> {
    let function = resolve_function(binary, &args.function)?;
    let timeout = Duration::try_from_secs_f64(args.timeout.unwrap_or(30.0)).map_err(|_| anyhow!("`timeout` must be a positive number of seconds"))?;
    let report = binary.structs(function, timeout)?;
    // Nothing read or written through a pointer is no struct to miss.
    let shown: Vec<&ObjectReport> = report.objects.iter().filter(|object| object.decision.is_ok() || args.refused && object.decision != Err(Refusal::Unused)).collect();
    let given = report.objects.iter().filter(|object| object.decision.is_ok()).count();
    let refused = report.objects.iter().filter(|object| object.decision.is_err() && object.decision != Err(Refusal::Unused)).count();
    let pointers = if given == 1 { "pointer" } else { "pointers" };
    let mut out = format!("{}: {given} {pointers} with a struct, {refused} read through without one{}\n", binary.program.label(function), if args.refused || refused == 0 { "" } else { " (`refused` lists them)" });
    for object in shown {
        let place = match (object.slots.as_slice(), &object.field) {
            ([], Some((owner, offset))) => format!("{owner} +{offset:#x}"),
            ([], None) => "a pointer no parameter reaches".to_string(),
            (slots, _) => slots.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        };
        let low = object.accesses.iter().map(|&(offset, _)| offset).min().unwrap_or(0);
        let high = object.accesses.iter().map(|&(offset, size)| offset + i64::from(size)).max().unwrap_or(0);
        let count = object.accesses.len();
        let reach = format!("{count} {}, +{low:#x} to +{high:#x}", if count == 1 { "access" } else { "accesses" });
        match &object.decision {
            Ok(name) => writeln!(out, "{place}: {name}{}, {reach}", if object.named { " (named)" } else { "" })?,
            Err(refusal) => writeln!(out, "{place}: no struct, {}; {reach}", refusal.reason())?,
        }
    }
    for warning in &report.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(out)
}

fn decompile(binary: &mut Binary, args: Decompile) -> Result<String> {
    let near = args.around.as_deref().map(addr_arg).transpose()?;
    // The function an address is in need not be named as well.
    let functions = match (args.functions.is_empty(), &args.around) {
        (true, Some(around)) => vec![around.clone()],
        _ => args.functions,
    };
    ensure!(!functions.is_empty(), "`decompile` needs at least one function, or `around`");
    let args = Decompile { functions, ..args };
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
        // With addresses the C is printed again, which the function's first decompilation
        // has shown to work.
        let c_text = match c_text {
            Some(_) if args.addresses || near.is_some() => binary.addressed(entry, timeout).ok(),
            c_text => c_text,
        };
        let c_text = match near {
            Some(addr) => c_text.map(|text| around(&text, addr)),
            None => c_text,
        };
        let label = binary.program.label(entry);
        match (record.status, c_text) {
            (Status::Ok, Some(text)) => {
                writeln!(out, "// {label} ({:.0} ms)", record.ms)?;
                let asserted = asserted_names(&binary.program, entry);
                if !asserted.is_empty() {
                    writeln!(out, "// its assertions name {}: its own name, or that of a function compiled into it", asserted.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", "))?;
                }
                // The decompiler prints a comment beside the code of its instruction. One on
                // an instruction that left no code of its own is listed here instead.
                for (addr, comment) in comments(binary, &binary.program.body(entry)).into_iter().filter(|(_, comment)| !text.contains(comment)) {
                    writeln!(out, "// {addr:#x}: {comment}")?;
                }
                writeln!(out, "{}\n", text.trim_matches('\n'))?;
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
        bail!("{addr:#x}{} has no bytes in the file (unmapped, or data that is only zero-filled at load). Mapped: {}", read_as_hex(&args.addr), mapped.join(", "));
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
            match image.section_at(addr) {
                Some(section) => (section, addr),
                // Memory the loader zero-fills, as `.bss` is, has no bytes in the file but is
                // data all the same.
                None if image.is_zero_filled(addr) => return Ok(format!("address {addr:#x}, not stored in the file: {}\n", describe(binary, addr))),
                None => bail!("{addr:#x} is in no section of the file, nor in memory the loader fills with zeros"),
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A recovered struct is named after the function it was recovered in. In a later build
    /// where that function moved, the line that names it is the same line.
    #[test]
    fn a_recovered_struct_named_after_a_function_that_moved_compares_equal() {
        // `total` is at 0x40100b in this build; say it was at 0x401000 in the earlier one.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/types-patched.elf");
        let image = recore::Image::load(std::path::Path::new(path)).unwrap();
        let analysis = recore::analyze(&image);
        let program = Program::new(image, analysis);
        let before = comparable("// header\nif (param_1 == (S_401000_RDI_8 *)0x0) {", &program, &|entry| (entry == 0x401000).then_some(0x40100b));
        let after = comparable("// header\nif (param_1 == (S_40100b_RDI_8 *)0x0) {", &program, &Some);
        assert_eq!(before, ["if (param_1 == (S_40100b_RDI_8 *)0x0) {"]);
        assert_eq!(after, before);
        // A name that leads to no function is left as it is.
        assert_eq!(comparable("// header\nS_dead_RDI *p;", &program, &Some), ["S_dead_RDI *p;"]);
    }
}
