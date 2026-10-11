//! Decompiles a few functions of a binary and prints the C with the recovered parameters.
//!
//! `cargo run --release -p recore-decomp --example demo -- corpus/bin/coreutils__install [count | 0xADDR...]`

use std::path::PathBuf;

use anyhow::{Context, Result};
use recore_decomp::{Facts, Session};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let binary = PathBuf::from(args.next().context("usage: demo <binary> [count | 0xADDR...]")?);
    let rest: Vec<String> = args.collect();
    let chosen: Vec<u64> = rest.iter().filter_map(|a| u64::from_str_radix(a.strip_prefix("0x")?, 16).ok()).collect();
    let count: usize = rest.first().and_then(|n| n.parse().ok()).unwrap_or(5);

    let image = recore::Image::load(&binary)?;
    let analysis = recore::analyze(&image);
    let mut session = Session::from_image(&image, &analysis)?;
    session.add_functions(&Facts::derive(&image, &analysis))?;

    // Spread the picks over the text section instead of taking the startup stubs at its head.
    let text = image.text().context("no .text")?;
    let functions: Vec<u64> = analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| f.addr).filter(|&addr| text.contains(addr)).collect();
    let spread: Vec<u64> = functions.iter().copied().step_by((functions.len() / count.max(1)).max(1)).take(count).collect();
    for addr in if chosen.is_empty() { spread } else { chosen } {
        let start = std::time::Instant::now();
        let result = session.decompile(addr);
        let elapsed = start.elapsed();
        match result {
            Ok(function) => {
                let params: Vec<String> = function.params.iter().map(|p| format!("{} in {}", p.type_name, p.storage)).collect();
                println!(
                    "// {addr:#x} in {elapsed:.1?}: {} parameters [{}], returns {}",
                    function.param_count(),
                    params.join(", "),
                    function.return_type
                );
                println!("{}", function.c_text);
            }
            Err(error) => println!("// {addr:#x}: failed: {error}\n"),
        }
    }
    Ok(())
}
