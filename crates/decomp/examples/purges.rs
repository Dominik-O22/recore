//! Counts the 32-bit x86 functions whose decompiled stack parameters disagree with the bytes
//! they pop as they return, `RET n`, in a report of `recore-decompile corpus`.
//!
//! `cargo run --release -p recore-decomp --example purges -- <binary> <out-dir>/<name>.json [--list=20]`

use std::path::Path;

use anyhow::{Result, bail};
use recore_decomp::Facts;
use serde::Deserialize;

#[derive(Deserialize)]
struct Record {
    addr: u64,
    status: String,
    #[serde(default)]
    storage: Vec<String>,
}

#[derive(Deserialize)]
struct Report {
    functions: Vec<Record>,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let [binary, report] = positional[..] else { bail!("usage: purges <binary> <report.json> [--list=N]") };
    let list: usize = args.iter().find_map(|a| a.strip_prefix("--list=")).map_or(Ok(20), str::parse)?;

    let image = recore::Image::load(Path::new(binary))?;
    let analysis = recore::analyze(&image);
    let purges = Facts::derive(&image, &analysis).purges;
    let report: Report = serde_json::from_str(&std::fs::read_to_string(report)?)?;
    let (mut fewer, mut more, mut agree) = (Vec::new(), Vec::new(), 0);
    for record in report.functions.iter().filter(|record| record.status == "ok") {
        let Ok(index) = purges.binary_search_by_key(&record.addr, |purge| purge.0) else { continue };
        let popped = usize::from(purges[index].1);
        // Each stack parameter taken as one 4-byte slot.
        let taken = 4 * record.storage.iter().filter(|storage| storage.starts_with("stack:")).count();
        let line = format!("  {:#x}: pops {popped}, takes {taken} [{}]", record.addr, record.storage.join(" "));
        match taken.cmp(&popped) {
            std::cmp::Ordering::Less => fewer.push(line),
            std::cmp::Ordering::Greater => more.push(line),
            std::cmp::Ordering::Equal => agree += 1,
        }
    }
    println!("{} functions pop arguments as they return: {agree} take what they pop, {} take less, {} more", purges.len(), fewer.len(), more.len());
    for line in fewer.iter().chain(&more).take(list) {
        println!("{line}");
    }
    Ok(())
}
