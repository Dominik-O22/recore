//! Counts what makes the C of a corpus run hard to read.

use std::path::Path;

use anyhow::{Context, Result};
use recore_decomp::isolate::Status;

use crate::report::BinaryReport;

/// What is looked for in a function's C, by the name it is reported under. Each stands for a
/// value the engine could not explain: a flag kept as a bit of the status register, a wide value
/// seen only as its bytes, or a register a convention does not account for.
const MARKS: [(&str, fn(&str) -> bool); 8] = [
    ("flag arithmetic", |c| c.lines().any(|line| !declares(line) && words(line).any(is_flag))),
    ("carry call", |c| ["CARRY1(", "SCARRY1(", "SBORROW1("].iter().any(|call| c.contains(call))),
    ("CONCAT", |c| c.contains("CONCAT")),
    ("extraout_", |c| c.contains("extraout_")),
    ("in_ register", |c| words(c).any(|word| word.starts_with("in_"))),
    ("unaff_", |c| c.contains("unaff_")),
    ("bad instruction", |c| c.contains("Bad instruction") || c.contains("bad instruction")),
    ("unreachable block", |c| c.contains("Removing unreachable block")),
];

/// Whether a line of C only declares a variable, as `  char extraout_PSW;` does.
fn declares(line: &str) -> bool {
    let mut words = line.trim().strip_suffix(';').unwrap_or("=").split(' ');
    words.clone().count() == 2 && words.all(|word| word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Whether a word of C names the 8051's status register, or a flag of it that the function
/// did not compute itself: one it was entered with or a call left it.
fn is_flag(word: &str) -> bool {
    let unexplained = ["in_", "extraout_", "unaff_"].iter().find_map(|prefix| word.strip_prefix(prefix));
    word.contains("PSW") || unexplained.is_some_and(|register| ["CY", "AC", "OV", "F0", "F1", "RS0", "RS1"].iter().any(|flag| register.split('_').next() == Some(flag)))
}

fn words(c: &str) -> impl Iterator<Item = &str> {
    c.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).filter(|word| !word.is_empty())
}

/// Prints, for the run in `out_dir`, how many functions came back as C, how many of those
/// carry each of [`MARKS`], and how long a function took. With `list`, also the functions
/// that carry the mark of that name.
pub fn report(out_dir: &Path, list: Option<&str>) -> Result<()> {
    let (mut functions, mut with_c) = (0, 0);
    let mut marked = [0usize; MARKS.len()];
    let mut times = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(out_dir)?.filter_map(|entry| Some(entry.ok()?.path())).filter(|path| path.extension().is_some_and(|e| e == "c")).collect();
    paths.sort();
    for path in paths {
        let report: BinaryReport = serde_json::from_slice(&std::fs::read(path.with_extension("json"))?).with_context(|| format!("reading the report beside {path:?}"))?;
        functions += report.functions.len();
        with_c += report.functions.iter().filter(|record| record.status == Status::Ok && record.c_len > 0).count();
        times.extend(report.functions.iter().map(|record| record.ms));
        // `run::finish` puts `// <address>` before each function.
        let text = std::fs::read_to_string(&path)?;
        for function in text.split("\n// 0x").filter(|function| !function.trim().is_empty()) {
            for (count, (name, found)) in marked.iter_mut().zip(MARKS) {
                if found(function) {
                    *count += 1;
                    if list == Some(name) {
                        println!("{} 0x{}", report.name, function.trim_start_matches("// 0x").lines().next().unwrap_or_default());
                    }
                }
            }
        }
    }
    times.sort_by(f64::total_cmp);
    let p99 = times.get((times.len().max(1) - 1) * 99 / 100).copied().unwrap_or(0.0);
    println!("{:<20}{functions:>7}", "functions");
    println!("{:<20}{with_c:>7}", "returning C");
    for (count, (name, _)) in marked.iter().zip(MARKS) {
        println!("{name:<20}{count:>7}{:>7.1}%", 100.0 * *count as f64 / with_c.max(1) as f64);
    }
    println!("{:<20}{:>10.3}", "mean ms", times.iter().sum::<f64>() / times.len().max(1) as f64);
    println!("{:<20}{p99:>10.3}", "p99 ms");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_counts_where_it_is_computed_with_not_where_it_is_declared() {
        let found = MARKS[0].1;
        assert!(!found("  char extraout_PSW;\n  uint1 in_PSW;\n"));
        assert!(found("  uVar1 = in_PSW & 0x7f | 0x80;\n"));
        assert!(found("  if (-1 < extraout_PSW) break;\n"));
        assert!(found("  if (extraout_CY_00 != '\\0') {\n"));
        assert!(!found("  bool in_CY;\n  if (param_1 < 3) {\n"));
    }

    #[test]
    fn an_input_register_is_a_word_of_its_own() {
        let found = MARKS[4].1;
        assert!(found("  return in_DPL;\n"));
        assert!(!found("  main_loop();\n"));
    }
}
