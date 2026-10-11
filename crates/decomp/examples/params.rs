//! Compares the decompiler's parameter count for each function with the debug info.
//!
//! DWARF gives the source-level count: `DW_TAG_formal_parameter` children of every
//! `DW_TAG_subprogram` that has a `DW_AT_low_pc`.
//!
//! `cargo run --release -p recore-decomp --example params -- corpus/bin/NAME corpus/debug/NAME.debug [--style=decompile] [--passes=2] [--list=40]`

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, bail};
use recore_decomp::dwarf::DebugInfo;
use recore_decomp::{Decompiled, Facts, Session, Style};

const THREADS: usize = 6;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let [binary, debug] = positional[..] else { bail!("usage: params <binary> <debug file> [--style=...] [--list=N]") };
    let style = match args.iter().find_map(|a| a.strip_prefix("--style=")) {
        None | Some("paramid") => Style::ParamId,
        Some("decompile") => Style::Decompile,
        Some(other) => bail!("unknown style {other}"),
    };
    let passes: usize = args.iter().find_map(|a| a.strip_prefix("--passes=")).map_or(Ok(1), str::parse)?;
    let list: usize = args.iter().find_map(|a| a.strip_prefix("--list=")).map_or(Ok(30), str::parse)?;

    let DebugInfo { functions: truth, symbols } = DebugInfo::load(Path::new(debug))?;
    let image = recore::Image::load(Path::new(binary))?;
    let analysis = recore::analyze(&image);
    let facts = Facts::derive(&image, &analysis);
    let found = analysis.functions.iter().filter(|f| truth.contains_key(&f.addr)).count();
    println!("{}: {} functions with DWARF parameters, recore found {found} of them", image.name, truth.len());

    // Every pass decompiles all functions. From the second pass on, callers see the parameters
    // their callees were found to have in the pass before.
    let all: Vec<u64> = analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| f.addr).collect();
    let results: BTreeMap<u64, Result<Decompiled>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|worker| {
                let (image, analysis, facts, all) = (&image, &analysis, &facts, &all);
                scope.spawn(move || -> Result<Vec<_>> {
                    let mut session = Session::from_image(image, analysis)?;
                    session.add_functions(facts)?;
                    session.set_style(style)?;
                    session.keep_prototypes(passes > 1);
                    // Every session needs every prototype, so all but the last pass cover all
                    // functions; only the last one is shared out between the threads.
                    for _ in 1..passes {
                        all.iter().for_each(|&addr| drop(session.decompile(addr)));
                    }
                    Ok(all.iter().skip(worker).step_by(THREADS).map(|&addr| (addr, session.decompile(addr))).collect())
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().expect("worker panicked")).collect::<Result<Vec<_>>>()
    })?
    .into_iter()
    .flatten()
    .filter(|(addr, _)| truth.contains_key(addr))
    .collect();

    // Difference `decompiler - DWARF` to number of functions.
    let mut differences: BTreeMap<i64, usize> = BTreeMap::new();
    let (mut failed, mut variadic) = (0, 0);
    let mut mismatches = Vec::new();
    for (addr, result) in &results {
        let expected = &truth[addr];
        match result {
            Err(_) => failed += 1,
            // The fixed parameters of a variadic function say little about the registers it reads.
            Ok(_) if expected.variadic => variadic += 1,
            Ok(function) => {
                let difference = function.param_count() as i64 - expected.params as i64;
                *differences.entry(difference).or_default() += 1;
                if difference != 0 {
                    let storage: Vec<&str> = function.params.iter().map(|p| p.storage.as_str()).collect();
                    mismatches.push(format!(
                        "  {addr:#x} {}: DWARF {}, decompiler {} [{}]",
                        symbols.get(addr).map_or("", String::as_str),
                        expected.params,
                        function.param_count(),
                        storage.join(" ")
                    ));
                }
            }
        }
    }
    let compared: usize = differences.values().sum();
    let matched = differences.get(&0).copied().unwrap_or(0);
    println!(
        "{style:?}, {passes} pass(es): {matched} of {compared} parameter counts match ({:.1}%); {failed} failed to decompile, {variadic} variadic skipped",
        100.0 * matched as f64 / compared.max(1) as f64
    );
    println!("decompiler minus DWARF: {differences:?}");
    for line in mismatches.iter().take(list) {
        println!("{line}");
    }
    Ok(())
}
