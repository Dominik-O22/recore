//! Decompiling in a child process, so that a crash or an endless function costs one function.
//!
//! The engine cannot be cancelled and a C++ fault kills its process. A [`Worker`] is a child
//! process holding one [`Session`]; the parent sends it one address at a time and enforces a
//! wall-clock limit. The child side is [`serve`], which the program reaches through a
//! subcommand of its own executable.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use recore::image::{Format, Machine};
use recore::report::{Analysis, CallTarget};
use serde::{Deserialize, Serialize};

use recore::edits::Edits;
use recore::structs::{Recovered, auto_function};

use crate::{Converged, Facts, Flow, Instruction, Local, Session, StructReport, Style};

/// Where switch targets come from.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JumpTables {
    /// recore's for PE images, which keep tables among the code, for 8051 code, whose tables
    /// the engine does not find, and for Cortex-M code, some of whose tables the engine reads
    /// past their end; the engine's own otherwise.
    #[default]
    Auto,
    Recore,
    Engine,
}

/// What a worker is told to do.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Options {
    pub style: Style,
    /// Send the C text back, not only its length.
    pub emit_c: bool,
    pub jump_tables: JumpTables,
    /// Address-space limit in GiB. Past it the engine's allocations fail and the function is
    /// reported as an error, instead of the machine going into swap.
    pub memory_gb: u64,
    /// Decompile the functions a function calls before the function itself, so that its calls
    /// pass at least the parameters those were found to take. Only done for 32-bit x86, where a
    /// call shows what it pushes but not which registers the callee reads. Elsewhere it costs
    /// time and recovers parameters worse.
    pub callees_first: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options { style: Style::Decompile, emit_c: true, jump_tables: JumpTables::Auto, memory_gb: 4, callees_first: true }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    /// The engine reported a failure for this function and carried on.
    Error,
    /// The function ran past the wall-clock limit and its worker was killed.
    Timeout,
    /// The worker died while decompiling this function.
    Crash,
}

/// The outcome for one function.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionRecord {
    pub addr: u64,
    pub status: Status,
    /// The engine's error, or how the worker died.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Time inside the decompiler; for a timeout or crash, the time until it was noticed.
    pub ms: f64,
    pub params: usize,
    /// Where each parameter lives: a register name or `stack:<offset>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<String>,
    pub returns_value: bool,
    pub c_len: usize,
}

impl FunctionRecord {
    /// A record for a function that produced no result.
    pub fn failed(addr: u64, status: Status, message: String, ms: f64) -> FunctionRecord {
        FunctionRecord { addr, status, message: Some(message), ms, params: 0, storage: Vec::new(), returns_value: false, c_len: 0 }
    }
}

/// One line of a worker's stdout.
#[derive(Serialize, Deserialize)]
enum Event {
    /// The binary is loaded and the session is set up.
    Ready,
    Done { record: FunctionRecord, c_text: Option<String> },
    /// The functions a function calls whose parameters the session does not hold yet.
    Callees(Vec<u64>),
    Listing(Result<Vec<Instruction>, String>),
    Register(Result<(String, u64, u32), String>),
    Flow(Result<Flow, String>),
    Locals(Result<Vec<Local>, String>),
    /// The answer to [`Request::Declare`], empty, or to [`Request::Type`].
    Text(Result<String, String>),
    /// Whether the session took [`Request::Edit`] in place.
    Edited(bool),
    Recovered(Result<Recovered, String>),
    Structs(Result<StructReport, String>),
}

/// One line of a worker's stdin.
#[derive(Serialize, Deserialize, Clone)]
enum Request {
    Decompile(u64),
    /// Decompile the function for its parameters only, which the session keeps for its callers.
    Parameters(u64),
    /// List the function's callees not decompiled yet.
    Callees(u64),
    /// Disassemble `[start, end)`.
    Listing { start: u64, end: u64, pcode: bool },
    /// Lift `[start, end)` to raw p-code for a program to run.
    Lift { start: u64, end: u64 },
    /// Where a register is.
    Register(String),
    /// Decompile the function for its data flow.
    Flow(u64),
    /// Decompile the function for its variables.
    Locals(u64),
    /// Decompile the function with the address of its instruction before each line of C.
    Addressed(u64),
    /// Parse a C declaration, to learn whether the engine takes it.
    Declare(String),
    /// Describe a data type.
    Type(String),
    /// Take the binary's edits as they are now, in place if the session can.
    Edit(Edits),
    /// The recovered struct of this name and those it points to, decompiling the function its
    /// name says if the session has not.
    Recovered(String),
    /// Decompile the function for what struct recovery made of its objects.
    Structs(u64),
}

/// Callees with more code than this, in bytes, are not decompiled ahead of their callers. The few
/// large functions take most of the time, and leaving them out costs no measurable accuracy.
const CALLEE_LIMIT: u64 = 4096;

/// The child side: loads `binary`, then answers each request on stdin with one line on stdout,
/// until stdin closes. `options` is the JSON that [`Worker::new`] passed along.
pub fn serve(binary: &Path, options: &str) -> Result<()> {
    let options: Options = serde_json::from_str(options)?;
    let bytes = options.memory_gb << 30;
    // Failing to set the limit only loses the protection.
    unsafe { libc::setrlimit(libc::RLIMIT_AS, &libc::rlimit { rlim_cur: bytes, rlim_max: bytes }) };

    let image = recore::Image::load(binary)?;
    // The engine reads its language files, and debug information is read if there is any,
    // while the analysis runs.
    let (session, mut analysis, debug) = std::thread::scope(|scope| {
        let session = scope.spawn(|| Session::load(&image));
        let debug = scope.spawn(|| crate::types::load(binary, &image));
        let analysis = recore::analyze(&image);
        (session.join().expect("loading does not panic"), analysis, debug.join().ok().flatten())
    });
    let mut session = session?;
    let mut edits = Edits::load(binary)?;
    session.add_imports(&image, &analysis)?;
    // What is known of a library routine goes by the name the analysis found, so renaming one
    // changes its name and no more, as it does in a running session.
    let mut facts = Facts::derive(&image, &analysis);
    edits.apply(&mut analysis);
    facts.names = crate::facts::function_names(&analysis);
    let aliases: HashSet<u64> = facts.import_aliases.iter().map(|alias| alias.0).collect();
    // A function that only jumps to another, as an incremental linker's stub does, is described
    // by what that one's debug information says.
    let importer = debug.as_ref().map(|debug| {
        let jumps = callees_of(&analysis, true);
        let stub = |f: &recore::report::AnalyzedFunction| match jumps.get(&f.addr)?.as_slice() {
            [CallTarget::Function(target)] if f.thunk && f.fragment_of.is_none() => Some((f.addr, *target)),
            _ => None,
        };
        crate::types::Importer::new(debug, analysis.functions.iter().filter_map(stub).collect())
    });
    if let Some(importer) = &importer {
        // A function the binary has no name for takes the one its debug information gives it.
        let named: HashSet<u64> = facts.names.iter().map(|name| name.0).collect();
        let unnamed = analysis.functions.iter().filter(|f| f.fragment_of.is_none() && !named.contains(&f.addr));
        facts.names.extend(unnamed.filter_map(|f| Some((f.addr, importer.describes(f.addr).filter(|described| !described.name.is_empty())?.name.clone()))));
    }
    let mut importer = importer;
    session.add_functions(&facts)?;
    session.add_strings(&analysis)?;
    session.add_classes(&analysis)?;
    session.add_objc(&image)?;
    let recores = image.format == Format::Pe || matches!(image.machine, Machine::I8051 | Machine::Thumb);
    if options.jump_tables == JumpTables::Recore || (options.jump_tables == JumpTables::Auto && recores) {
        session.override_jump_tables(&analysis, &facts)?;
    }

    // Types from debug information go in before the edits, which have the last word and may
    // name them. The prototypes follow as functions are asked for.
    if let Some(importer) = &mut importer {
        importer.globals(&mut session);
        for text in edits.declarations.iter().chain(edits.types.values()) {
            importer.mentioned(&mut session, text);
        }
    }

    // Named structs go in before declarations, which may mention them.
    session.set_structs(&edits.structs, &edits.holders)?;
    // Each edit was accepted by a session when it was made. One that no longer is, after a
    // change to an earlier declaration, is reported and costs only itself.
    for declaration in &edits.declarations {
        if let Err(error) = session.declare(declaration) {
            eprintln!("declaration `{declaration}`: {error}");
        }
    }
    // Data the image has a name for, such as a variable a library exports, goes by that name
    // in the C. An edit, which follows, has the last word.
    let is_function = |addr: u64| analysis.functions.binary_search_by_key(&addr, |function| function.addr).is_ok();
    // A Cortex-M's registers, the system's and a device's, are words.
    let register = (image.machine == Machine::Thumb).then_some("uint");
    for (&addr, name) in image.symbol_names.iter().filter(|(addr, _)| !is_function(**addr) && !image.is_code(**addr)) {
        // One the engine does not take is only left without its name.
        let _ = session.add_global(addr, name, register.filter(|_| image.is_zero_filled(addr)));
    }
    // An import the code reads and does not call, such as `stderr` or `environ`, has a slot in the
    // GOT that holds its address: declared, the C reads `*__imp_stderr` and not a raw address. A
    // variable the loader copies into the program itself, in memory it zero-fills, already goes
    // by its own name above.
    let called: recore::FxHashSet<u64> = analysis.imports.iter().map(|import| import.slot).collect();
    for (&slot, name) in image.import_slots.iter().filter(|&(slot, _)| !called.contains(slot) && !image.is_zero_filled(*slot)) {
        let _ = session.add_global(slot, &format!("__imp_{name}"), Some("void *"));
    }
    for (addr, name, kind) in edits.globals(&analysis) {
        if let Err(error) = session.add_global(addr, &name, kind) {
            eprintln!("global {name} at {addr:#x}: {error}");
        }
    }

    for (&addr, text) in &edits.comments {
        if let Some(function) = comment_owner(&analysis, addr) {
            session.add_comment(function, addr, text)?;
        }
    }
    for (&function, names) in &edits.locals {
        for (place, name) in names {
            session.name_local(function, place, name)?;
        }
    }

    // The calls in the function at `entry` that pass text `is_text` accepts, as `(call, callee,
    // position, text)`: the first argument of each that is such text.
    let text_calls = |entry: u64, is_text: &dyn Fn(u64) -> bool| -> Vec<(u64, CallTarget, usize, u64)> {
        let body: Vec<(u64, u64)> = analysis.functions.iter().filter(|function| function.fragment_of.unwrap_or(function.addr) == entry).flat_map(|function| function.ranges.iter().copied()).collect();
        let calls: Vec<&recore::report::CallSite> = analysis.calls.iter().filter(|call| body.iter().any(|&(start, end)| (start..end).contains(&call.at))).collect();
        let sites: Vec<u64> = calls.iter().map(|call| call.at).collect();
        recore::cfg::text_arguments(&image, &body, &sites, is_text)
            .into_iter()
            .map(|(at, position, text)| (at, calls[sites.binary_search(&at).expect("one of the sites asked about")].target, position, text))
            .collect()
    };
    let conversions: HashSet<u64> = analysis.strings.iter().filter(|string| !string.wide && string.text.contains('%')).map(|string| string.addr).collect();
    // Raw firmware imports nothing: its C library is linked in, and nothing names its `printf`.
    // There a function takes a format when some call passes it text with a conversion in it.
    let raw = image.format == Format::Raw;
    let passed_formats: HashSet<u64> = analysis
        .functions
        .iter()
        .filter(|function| raw && function.fragment_of.is_none())
        .flat_map(|function| text_calls(function.addr, &|addr| conversions.contains(&addr)))
        .filter_map(|(_, callee, _, _)| match callee {
            CallTarget::Function(entry) => Some(entry),
            CallTarget::Import(_) => None,
        })
        .collect();
    // The functions of the program that take a format and the arguments it asks for: those that
    // set up to read a variable number of arguments, and hand them to the C library's routine
    // for formats in an argument list, themselves or through a function or two, or in raw
    // firmware are passed a format. Taking a variable number alone does not make a string with
    // a `%` in it a format: a list of words ended by a null is passed the same way.
    let hands_on_formats = {
        /// Functions between one that takes a format and the library routine it ends in.
        const DEPTH: usize = 3;
        let library = |slot: &u64| analysis.imports.iter().find(|import| import.slot == *slot).is_some_and(|import| takes_argument_list(&import.name));
        let calls = callees_of(&analysis, false);
        fn reaches(calls: &HashMap<u64, Vec<CallTarget>>, library: &dyn Fn(&u64) -> bool, entry: u64, depth: usize) -> bool {
            calls.get(&entry).into_iter().flatten().any(|target| match target {
                CallTarget::Import(slot) => library(slot),
                CallTarget::Function(callee) => depth > 0 && reaches(calls, library, *callee, depth - 1),
            })
        }
        move |entry: u64| passed_formats.contains(&entry) || reaches(&calls, &library, entry, DEPTH)
    };
    for function in analysis.functions.iter().filter(|function| function.fragment_of.is_none()) {
        let variadic = function.ranges.first().is_some_and(|&(start, end)| recore::cfg::takes_variable_arguments(&image, start, end));
        if variadic && hands_on_formats(function.addr) {
            session.takes_variable_arguments(function.addr);
        }
    }

    session.set_style(options.style)?;
    // An 8051 function hands the registers it was passed on to the functions it calls without
    // reading them. Decompiled with those unknown it seems to take fewer parameters than it
    // does, and a call to it then lists what it passes out of order. So there no function's
    // parameters are kept for its callers.
    let hands_on_registers = image.machine == Machine::I8051;
    let callees_first = options.callees_first && !hands_on_registers;
    session.keep_prototypes(callees_first);
    // What each function calls: with debug information, the functions whose prototypes its
    // calls need.
    let called = if callees_first || importer.is_some() { callees(&analysis, false) } else { HashMap::new() };
    let callees = if callees_first { called.clone() } else { HashMap::new() };
    // A function that ends by jumping to another returns what that one returns, which the
    // engine only learns if the other is decompiled first.
    let tail_callees = callees_of(&analysis, true);
    // A function jumped to takes its parameters from the function that jumps, which therefore
    // takes them too. Its parameters are kept so that the jump is seen to pass them.
    let jumped_to: HashSet<u64> = tail_callees.values().flatten().filter_map(|target| if let CallTarget::Function(entry) = target { Some(*entry) } else { None }).collect();
    // Functions decompiled so far, whose parameters the session holds if it could recover them.
    let mut known: HashSet<u64> = HashSet::new();
    // Bytes of code per function, fragments included.
    let mut sizes: HashMap<u64, u64> = HashMap::new();
    for function in &analysis.functions {
        *sizes.entry(function.fragment_of.unwrap_or(function.addr)).or_default() += function.ranges.iter().map(|range| range.1 - range.0).sum::<u64>();
    }
    // Before a function is decompiled, each call in it that passes a format is given the
    // arguments the format asks for. Told beforehand it costs nothing; the engine left to find
    // out for itself gets a good many wrong, and correcting one means decompiling again.
    // In raw firmware a function known to take a format is called with text that has no `%`
    // too, where a hosted program calls `puts`; only such a function's calls are given any.
    let texts: HashSet<u64> = analysis.strings.iter().filter(|string| raw && !string.wide).map(|string| string.addr).collect();
    let formats = if raw { &texts } else { &conversions };
    let mut formatted: HashSet<u64> = HashSet::new();
    let mut settle_formats = |session: &mut Session, entry: u64| {
        if !formatted.insert(entry) {
            return;
        }
        for (at, target, position, format) in text_calls(entry, &|addr| formats.contains(&addr)) {
            // One the engine does not take leaves the call to be worked out as before.
            let _ = session.format_call(entry, at, target, position, format);
        }
    };
    // Results of functions decompiled ahead of a caller that are as good as asked for.
    let mut ready: HashMap<u64, Event> = HashMap::new();

    let mut out = std::io::stdout().lock();
    let mut send = |event: &Event| -> Result<()> {
        serde_json::to_writer(&mut out, event)?;
        out.write_all(b"\n")?;
        Ok(out.flush()?)
    };
    send(&Event::Ready)?;
    for line in std::io::stdin().lock().lines() {
        let request: Request = serde_json::from_str(&line?)?;
        let small = |callee: &u64| !known.contains(callee) && sizes.get(callee).is_some_and(|&size| size <= CALLEE_LIMIT);
        let unknown = |addr: u64| {
            let mut pending: Vec<u64> = callees.get(&addr).into_iter().flatten().copied().filter(small).collect();
            pending.sort_unstable();
            pending.dedup();
            // Then the functions it jumps to, each after the ones that one jumps to in turn.
            let mut chain = Vec::new();
            tail_chain(&tail_callees, addr, &small, TAIL_DEPTH, &mut chain);
            pending.retain(|callee| !chain.contains(callee));
            pending.extend(chain);
            pending
        };
        let text = |result: Result<String>| Event::Text(result.map_err(|error| error.to_string()));
        let addr = match request {
            Request::Callees(addr) => {
                // A function ready to be handed over has nothing left to wait for.
                send(&Event::Callees(if ready.contains_key(&addr) { Vec::new() } else { unknown(addr) }))?;
                continue;
            }
            Request::Listing { start, end, pcode } => {
                send(&Event::Listing(session.listing(start, end, pcode).map_err(|error| error.to_string())))?;
                continue;
            }
            Request::Lift { start, end } => {
                send(&Event::Listing(session.lift(start, end).map_err(|error| error.to_string())))?;
                continue;
            }
            Request::Register(name) => {
                send(&Event::Register(session.register(&name).map_err(|error| error.to_string())))?;
                continue;
            }
            Request::Flow(addr) => {
                if let Some(importer) = &mut importer {
                    importer.functions(&mut session, std::iter::once(addr).chain(called.get(&addr).into_iter().flatten().copied()));
                }
                settle_formats(&mut session, addr);
                session.keep_flow(true);
                let flow = session.decompile(addr).map(|function| function.flow.unwrap_or_default());
                session.keep_flow(false);
                send(&Event::Flow(flow.map_err(|error| error.to_string())))?;
                continue;
            }
            Request::Addressed(addr) => {
                if let Some(importer) = &mut importer {
                    importer.functions(&mut session, std::iter::once(addr).chain(called.get(&addr).into_iter().flatten().copied()));
                }
                settle_formats(&mut session, addr);
                session.keep_addresses(true);
                let c_text = session.decompile(addr).map(|function| function.c_text);
                session.keep_addresses(false);
                send(&text(c_text))?;
                continue;
            }
            Request::Locals(addr) => {
                if let Some(importer) = &mut importer {
                    importer.functions(&mut session, std::iter::once(addr).chain(called.get(&addr).into_iter().flatten().copied()));
                }
                settle_formats(&mut session, addr);
                send(&Event::Locals(session.decompile(addr).map(|function| function.locals).map_err(|error| error.to_string())))?;
                continue;
            }
            Request::Recovered(ref name) => {
                let found = match session.recovered(name) {
                    Some(found) => Some(found),
                    None => match auto_function(name) {
                        Some(function) => {
                            if let Some(importer) = &mut importer {
                                importer.functions(&mut session, std::iter::once(function).chain(called.get(&function).into_iter().flatten().copied()));
                            }
                            settle_formats(&mut session, function);
                            let _ = session.decompile(function);
                            session.recovered(name)
                        }
                        None => None,
                    },
                };
                send(&Event::Recovered(found.ok_or_else(|| format!("no struct `{name}` was recovered; decompile the function it comes from to see the names its structs have now"))))?;
                continue;
            }
            Request::Structs(addr) => {
                if let Some(importer) = &mut importer {
                    importer.functions(&mut session, std::iter::once(addr).chain(called.get(&addr).into_iter().flatten().copied()));
                }
                settle_formats(&mut session, addr);
                let report = session.decompile(addr).map_err(|error| error.to_string()).map(|_| session.structs_of(addr).unwrap_or_default());
                send(&Event::Structs(report))?;
                continue;
            }
            Request::Declare(ref declaration) => {
                if let Some(importer) = &mut importer {
                    importer.mentioned(&mut session, declaration);
                }
                send(&text(session.declare(declaration).map(|()| String::new())))?;
                continue;
            }
            Request::Type(ref name) => {
                if let Some(importer) = &mut importer {
                    importer.mentioned(&mut session, name);
                }
                send(&text(session.type_layout(name)))?;
                continue;
            }
            Request::Edit(changed) => {
                let done = edit_in_place(&mut session, &analysis, &aliases, &edits, &changed).unwrap_or(false);
                // Results kept for later show the names as they were.
                ready.clear();
                edits = changed;
                send(&Event::Edited(done))?;
                continue;
            }
            Request::Decompile(addr) | Request::Parameters(addr) => addr,
        };
        if let (Request::Decompile(_), Some(event)) = (&request, ready.remove(&addr)) {
            send(&event)?;
            continue;
        }
        // A function that ends by jumping to another passes on what that one takes, and with
        // that one unknown it seems to pass on every register. So before a function is
        // decompiled for a caller's sake, the functions it jumps to are, last in the chain first.
        let mut jumped_first = Vec::new();
        if matches!(request, Request::Parameters(_)) && callees_first {
            tail_chain(&tail_callees, addr, &small, TAIL_DEPTH, &mut jumped_first);
        }
        // Decompiled for a caller's sake with every callee of its own known, a function comes
        // out as it would when asked for, so the result is kept for then.
        let keep = matches!(request, Request::Parameters(_)) && unknown(addr).iter().all(|callee| jumped_first.contains(callee));
        for target in jumped_first {
            session.keep_prototypes(!hands_on_registers);
            if let Some(importer) = &mut importer {
                importer.functions(&mut session, std::iter::once(target));
            }
            // A failure here only leaves the caller as well off as it was.
            settle_formats(&mut session, target);
            let _ = session.decompile(target);
            known.insert(target);
        }
        for &callee in tail_callees.get(&addr).into_iter().flatten() {
            if session.returns_like(addr, callee) {
                break;
            }
        }
        session.keep_prototypes(callees_first || (jumped_to.contains(&addr) && !hands_on_registers));
        if let Some(importer) = &mut importer {
            importer.functions(&mut session, std::iter::once(addr).chain(called.get(&addr).into_iter().flatten().copied()));
        }
        let start = Instant::now();
        settle_formats(&mut session, addr);
        let result = session.decompile(addr);
        known.insert(addr);
        let ms = start.elapsed().as_secs_f64() * 1e3;
        let event = match result {
            Ok(function) => Event::Done {
                record: FunctionRecord {
                    addr,
                    status: Status::Ok,
                    message: None,
                    ms,
                    params: function.param_count(),
                    storage: function.params.iter().map(|p| p.storage.clone()).collect(),
                    returns_value: function.returns_value,
                    c_len: function.c_text.len(),
                },
                c_text: (options.emit_c && (keep || matches!(request, Request::Decompile(_)))).then_some(function.c_text),
            },
            Err(error) => Event::Done { record: FunctionRecord::failed(addr, Status::Error, error.to_string(), ms), c_text: None },
        };
        if keep {
            // The caller only waits for this to finish.
            send(&Event::Callees(Vec::new()))?;
            ready.insert(addr, event);
        } else {
            send(&event)?;
        }
    }
    Ok(())
}

/// The function a comment at `addr` goes to: the one its address is in, by where that starts.
fn comment_owner(analysis: &Analysis, addr: u64) -> Option<u64> {
    let function = analysis.functions.iter().find(|function| function.ranges.iter().any(|&(start, end)| (start..end).contains(&addr)))?;
    Some(function.fragment_of.unwrap_or(function.addr))
}

/// Brings `session` from the edits `before` to `after` without a new process, and says whether
/// it could. It cannot for a change to declarations or types, for a name taken away, or for a
/// function's name that a declaration mentions, since a declared prototype finds its function
/// by name as the session starts. Having said no, it may have made part of the change.
fn edit_in_place(session: &mut Session, analysis: &Analysis, aliases: &HashSet<u64>, before: &Edits, after: &Edits) -> Result<bool> {
    if before.declarations != after.declarations || before.types != after.types || before.names.keys().any(|addr| !after.names.contains_key(addr)) {
        return Ok(false);
    }
    if (before.structs != after.structs || before.holders != after.holders) && session.set_structs(&after.structs, &after.holders)? == Converged::Restart {
        return Ok(false);
    }
    let declared: HashSet<&str> = after.declarations.iter().flat_map(|text| text.split(|c: char| !(c.is_alphanumeric() || c == '_'))).collect();
    let is_function = |addr: u64| analysis.functions.binary_search_by_key(&addr, |f| f.addr).is_ok_and(|index| analysis.functions[index].fragment_of.is_none());
    for (&addr, name) in after.names.iter().filter(|&(addr, name)| before.names.get(addr) != Some(name)) {
        if !is_function(addr) {
            session.add_global(addr, name, after.types.get(&addr).map(String::as_str))?;
        } else if !aliases.contains(&addr) {
            // A stub of an import keeps the import's name, as it does in a new session.
            let old = session.rename_function(addr, name)?;
            if declared.contains(name.as_str()) || declared.contains(old.as_str()) {
                return Ok(false);
            }
        }
    }
    // A function's comments and variable names are set afresh wherever one of them changed.
    let commented: BTreeSet<u64> = before.comments.keys().chain(after.comments.keys()).filter(|&addr| before.comments.get(addr) != after.comments.get(addr)).filter_map(|&addr| comment_owner(analysis, addr)).collect();
    for function in commented {
        session.forget_comments(function);
        for (&addr, text) in after.comments.iter().filter(|&(&addr, _)| comment_owner(analysis, addr) == Some(function)) {
            session.add_comment(function, addr, text)?;
        }
    }
    let named: BTreeSet<u64> = before.locals.keys().chain(after.locals.keys()).filter(|&function| before.locals.get(function) != after.locals.get(function)).copied().collect();
    for function in named {
        session.forget_local_names(function);
        for (place, name) in after.locals.get(&function).into_iter().flatten() {
            session.name_local(function, place, name)?;
        }
    }
    Ok(true)
}

/// Whether an imported function formats or scans with arguments it is handed as a list, as
/// `vsnprintf` and `vfscanf` do, under any of the names the C libraries give such routines.
fn takes_argument_list(import: &str) -> bool {
    let name = import.trim_start_matches('_');
    // `vprintf`, `vsnprintf`, `vasprintf`, `vfwprintf`, `vsscanf`; glibc's checked `vsnprintf_chk`;
    // the Microsoft runtime's `stdio_common_vfprintf`; and `vsyslog`, `verr`, `vwarn` and kin.
    let formatted = ["printf", "scanf"].iter().any(|family| name.split(family).next().is_some_and(|before| before.len() < name.len() && before.rsplit('_').next().is_some_and(|prefix| prefix.starts_with('v'))));
    formatted || matches!(name, "vsyslog" | "vsyslog_chk" | "verr" | "verrx" | "vwarn" | "vwarnx")
}

/// How many jumps from function to function are followed to learn what the first returns.
const TAIL_DEPTH: usize = 8;

/// Appends to `chain` the functions `addr` jumps to that pass `wanted`, each after the ones it
/// jumps to itself, so that decompiling them in this order tells each what it returns.
fn tail_chain(tail_callees: &HashMap<u64, Vec<CallTarget>>, addr: u64, wanted: &impl Fn(&u64) -> bool, depth: usize, chain: &mut Vec<u64>) {
    for target in tail_callees.get(&addr).into_iter().flatten() {
        let CallTarget::Function(callee) = *target else { continue };
        if depth > 0 && callee != addr && wanted(&callee) && !chain.contains(&callee) {
            tail_chain(tail_callees, callee, wanted, depth - 1, chain);
            chain.push(callee);
        }
    }
}

/// The functions each function calls or tail-calls, by entry point.
fn callees(analysis: &Analysis, tail_only: bool) -> HashMap<u64, Vec<u64>> {
    let functions = |targets: Vec<CallTarget>| targets.into_iter().filter_map(|target| if let CallTarget::Function(entry) = target { Some(entry) } else { None }).collect();
    callees_of(analysis, tail_only).into_iter().map(|(owner, targets)| (owner, functions(targets))).collect()
}

/// What each function calls, by entry point, imports included: every call, or with `tail_only`
/// just the jumps that leave the function for good.
fn callees_of(analysis: &Analysis, tail_only: bool) -> HashMap<u64, Vec<CallTarget>> {
    let mut extents: Vec<(u64, u64, u64)> =
        analysis.functions.iter().flat_map(|f| f.ranges.iter().map(move |&(start, end)| (start, end, f.fragment_of.unwrap_or(f.addr)))).collect();
    extents.sort_unstable();
    let mut callees: HashMap<u64, Vec<CallTarget>> = HashMap::new();
    for call in analysis.calls.iter().filter(|call| !tail_only || (call.tail && !call.conditional)) {
        let index = extents.partition_point(|extent| extent.0 <= call.at);
        if let Some(&(_, end, owner)) = index.checked_sub(1).map(|i| &extents[i])
            && call.at < end
            && call.target != CallTarget::Function(owner)
        {
            callees.entry(owner).or_default().push(call.target);
        }
    }
    callees
}

/// A worker gets this long to load its binary and declare every function.
const SETUP_LIMIT: Duration = Duration::from_secs(300);

/// A running child and the pipes to it. Dropping it kills the child.
struct Process {
    child: Child,
    stdin: ChildStdin,
    events: Receiver<Event>,
    stderr: Option<JoinHandle<String>>,
    /// The child has reported that its session is set up.
    ready: bool,
}

/// How a request went wrong, with the child gone.
struct Failure {
    status: Status,
    message: String,
}

impl Process {
    fn start(mut command: Command) -> Result<Process> {
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("spawning worker")?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let (sender, events) = mpsc::channel();
        // Reading and draining each get a thread, so the caller only ever waits on a channel
        // with a timeout and a full pipe never blocks the child.
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let Ok(event) = serde_json::from_str(&line) else { break };
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        let drain = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        Ok(Process { child, stdin, events, stderr: Some(drain), ready: false })
    }

    /// Waits for the child to finish setting up.
    fn wait_ready(&mut self) -> Result<(), Failure> {
        if self.ready {
            return Ok(());
        }
        match self.events.recv_timeout(SETUP_LIMIT) {
            Ok(Event::Ready) => {
                self.ready = true;
                Ok(())
            }
            Ok(_) => Err(Failure { status: Status::Crash, message: "worker answered before it was asked".into() }),
            Err(error) => {
                let how = self.end(error == RecvTimeoutError::Timeout);
                Err(Failure { status: Status::Crash, message: format!("worker stopped during setup: {how}") })
            }
        }
    }

    /// Sends one request and waits up to `timeout` for the answer. Setup still under way does
    /// not count towards `timeout`.
    fn ask(&mut self, request: Request, timeout: Duration) -> Result<Event, Failure> {
        self.wait_ready()?;
        // A failed write means the child is gone, which the receive below reports.
        let _ = writeln!(self.stdin, "{}", serde_json::to_string(&request).expect("plain data")).and_then(|()| self.stdin.flush());
        match self.events.recv_timeout(timeout) {
            Ok(Event::Ready) | Err(RecvTimeoutError::Disconnected) => Err(Failure { status: Status::Crash, message: self.end(false) }),
            Ok(event) => Ok(event),
            // The child is still busy; dropping this process kills it.
            Err(RecvTimeoutError::Timeout) => Err(Failure { status: Status::Timeout, message: format!("no result after {timeout:.0?}") }),
        }
    }

    /// Kills the child if it is still running and describes how it ended.
    fn end(&mut self, kill: bool) -> String {
        if kill {
            let _ = self.child.kill();
        }
        let how = match self.child.wait() {
            Ok(status) => status.signal().map_or_else(|| format!("exited with {status}"), |signal| format!("killed by signal {signal}")),
            Err(error) => error.to_string(),
        };
        // The end of stderr usually names the cause: an assertion, a panic, an abort message.
        let stderr = self.stderr.take().and_then(|drain| drain.join().ok()).unwrap_or_default();
        let tail: String = stderr.trim().chars().rev().take(300).collect::<Vec<_>>().into_iter().rev().collect();
        if tail.is_empty() { how } else { format!("{how}: {tail}") }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Why a request got no answer of the kind it asks for.
fn unexpected(answer: Result<Event, Failure>) -> String {
    match answer {
        Ok(_) => "the decompiler process answered something else".into(),
        Err(failure) => format!("the decompiler process failed and was replaced: {}", failure.message),
    }
}

/// A child process with a warm session for one binary. A child that dies or stalls is replaced
/// by a new one, so a failure costs the one function and the parameters kept so far.
pub struct Worker {
    command: Box<dyn Fn() -> Command + Send>,
    options: Options,
    process: Option<Process>,
    /// Callees that took a child down. They are no longer decompiled ahead of their callers.
    avoid: HashSet<u64>,
}

impl Worker {
    /// Starts a child without waiting for it, so that it sets up while the caller does other
    /// work. `command` must build a program that ends up calling [`serve`] with the two arguments
    /// appended here: the binary's path and the options as JSON.
    pub fn new(command: impl Fn() -> Command + Send + 'static, binary: &Path, options: &Options) -> Worker {
        let (binary, json) = (binary.to_path_buf(), serde_json::to_string(options).expect("plain data"));
        let command = move || {
            let mut command = command();
            command.arg(&binary).arg(&json);
            command
        };
        let process = Process::start(command()).ok();
        Worker { command: Box::new(command), options: options.clone(), process, avoid: HashSet::new() }
    }

    /// Decompiles one function. If the child dies or exceeds `timeout`, the record says so.
    /// With [`Options::callees_first`] the function's callees are decompiled before it, each
    /// within `timeout` of its own.
    pub fn decompile(&mut self, addr: u64, timeout: Duration) -> (FunctionRecord, Option<String>) {
        let ahead = self.callees_first(addr, timeout);
        let start = Instant::now();
        let mut result = self.ask(Request::Decompile(addr), timeout);
        if result.is_err() && ahead > 0 {
            // Known parameters at its calls can send a function astray that decompiles well
            // without them. The new child knows none.
            result = self.ask(Request::Decompile(addr), timeout);
        }
        match result {
            Ok(Event::Done { record, c_text }) => (record, c_text),
            Ok(_) => (FunctionRecord::failed(addr, Status::Crash, "worker answered something else".into(), 0.0), None),
            Err(failure) => (FunctionRecord::failed(addr, failure.status, failure.message, start.elapsed().as_secs_f64() * 1e3), None),
        }
    }

    /// With [`Options::callees_first`], decompiles the callees of the function at `addr` whose
    /// parameters the child does not hold yet, each within `timeout`. Returns how many it did
    /// since the child last started.
    fn callees_first(&mut self, addr: u64, timeout: Duration) -> usize {
        let mut ahead = 0;
        if self.options.callees_first
            && let Ok(Event::Callees(callees)) = self.ask(Request::Callees(addr), timeout)
        {
            for callee in callees {
                if self.avoid.contains(&callee) {
                    continue;
                }
                match self.ask(Request::Parameters(callee), timeout) {
                    Ok(_) => ahead += 1,
                    // The new child starts without the parameters of the callees before this one.
                    Err(_) => {
                        self.avoid.insert(callee);
                        ahead = 0;
                    }
                }
            }
        }
        ahead
    }

    /// Disassembles `[start, end)`, with raw p-code per instruction if `pcode`.
    pub fn listing(&mut self, start: u64, end: u64, pcode: bool, timeout: Duration) -> Result<Vec<Instruction>, String> {
        match self.ask(Request::Listing { start, end, pcode }, timeout) {
            Ok(Event::Listing(listing)) => listing,
            other => Err(unexpected(other)),
        }
    }

    /// Lifts `[start, end)` to raw p-code for a program to run: see [`Session::lift`].
    pub fn lift(&mut self, start: u64, end: u64, timeout: Duration) -> Result<Vec<Instruction>, String> {
        match self.ask(Request::Lift { start, end }, timeout) {
            Ok(Event::Listing(listing)) => listing,
            other => Err(unexpected(other)),
        }
    }

    /// The space, offset and size of the register `name`: see [`Session::register`].
    pub fn register(&mut self, name: &str, timeout: Duration) -> Result<(String, u64, u32), String> {
        match self.ask(Request::Register(name.to_string()), timeout) {
            Ok(Event::Register(place)) => place,
            other => Err(unexpected(other)),
        }
    }

    /// The data flow of the function at `addr`, which costs one decompilation.
    pub fn flow(&mut self, addr: u64, timeout: Duration) -> Result<Flow, String> {
        self.callees_first(addr, timeout);
        match self.ask(Request::Flow(addr), timeout) {
            Ok(Event::Flow(flow)) => flow,
            other => Err(unexpected(other)),
        }
    }

    /// The C of the function at `addr` with the address of its instruction before each line.
    pub fn addressed(&mut self, addr: u64, timeout: Duration) -> Result<String, String> {
        self.callees_first(addr, timeout);
        match self.ask(Request::Addressed(addr), timeout) {
            Ok(Event::Text(text)) => text,
            other => Err(unexpected(other)),
        }
    }

    /// The variables of the function at `addr`, which costs one decompilation.
    pub fn locals(&mut self, addr: u64, timeout: Duration) -> Result<Vec<Local>, String> {
        self.callees_first(addr, timeout);
        match self.ask(Request::Locals(addr), timeout) {
            Ok(Event::Locals(locals)) => locals,
            other => Err(unexpected(other)),
        }
    }

    /// The recovered struct `name` and those it points to: see [`Session::recovered`]. Its
    /// function is decompiled first if the child has not.
    pub fn recovered(&mut self, name: &str, timeout: Duration) -> Result<Recovered, String> {
        if let Some(function) = auto_function(name) {
            self.callees_first(function, timeout);
        }
        match self.ask(Request::Recovered(name.to_string()), timeout) {
            Ok(Event::Recovered(found)) => found,
            other => Err(unexpected(other)),
        }
    }

    /// What struct recovery made of the objects of the function at `addr`, which costs one
    /// decompilation: see [`Session::structs_of`].
    pub fn structs(&mut self, addr: u64, timeout: Duration) -> Result<StructReport, String> {
        self.callees_first(addr, timeout);
        match self.ask(Request::Structs(addr), timeout) {
            Ok(Event::Structs(report)) => report,
            other => Err(unexpected(other)),
        }
    }

    /// Checks that the engine takes a C declaration. The child's session keeps it, but only a
    /// declaration among the binary's edits is there again after [`Worker::update`].
    pub fn declare(&mut self, declaration: &str, timeout: Duration) -> Result<(), String> {
        match self.ask(Request::Declare(declaration.to_string()), timeout) {
            Ok(Event::Text(result)) => result.map(drop),
            other => Err(unexpected(other)),
        }
    }

    /// Describes a data type: see [`Session::type_layout`].
    pub fn type_layout(&mut self, name: &str, timeout: Duration) -> Result<String, String> {
        match self.ask(Request::Type(name.to_string()), timeout) {
            Ok(Event::Text(result)) => result,
            other => Err(unexpected(other)),
        }
    }

    /// Brings the child up to `edits`, the binary's edits as just saved, and says whether it
    /// took them in place. The child takes names, comments, variable names, new structs and
    /// names of fields in place and keeps the parameters it has found. Any other change
    /// replaces it with a new child, which reads the edits from their file and sets up before
    /// the next request.
    pub fn update(&mut self, edits: &Edits, timeout: Duration) -> bool {
        // With no child, the next one reads the file.
        let in_place = self.process.is_some() && matches!(self.ask(Request::Edit(edits.clone()), timeout), Ok(Event::Edited(true)));
        if self.process.is_some() && !in_place {
            self.process = Process::start((self.command)()).ok();
        }
        in_place
    }

    /// Waits until a child is set up, so that what is timed next is the decompiler alone.
    pub fn ready(&mut self) -> bool {
        let ready = self.process().and_then(Process::wait_ready).is_ok();
        if !ready {
            self.process = None;
        }
        ready
    }

    /// The child, started now if the last one is gone. A child can also have died while idle,
    /// which is not the doing of the function asked for next.
    fn process(&mut self) -> Result<&mut Process, Failure> {
        if self.process.as_mut().is_none_or(|process| !matches!(process.child.try_wait(), Ok(None))) {
            let started = Process::start((self.command)());
            self.process = Some(started.map_err(|error| Failure { status: Status::Error, message: format!("{error:#}") })?);
        }
        Ok(self.process.as_mut().expect("started above"))
    }

    /// Asks the child, starting one if the last one is gone.
    fn ask(&mut self, request: Request, timeout: Duration) -> Result<Event, Failure> {
        let result = self.process()?.ask(request, timeout);
        if result.is_err() {
            self.process = None;
        }
        result
    }
}
