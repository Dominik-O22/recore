//! The tools from a shell: `recore-mcp <tool> <binary> [arguments]` runs one and prints its answer.

use anyhow::{Result, bail};
use recore::program::parse_addr;
use serde_json::{Map, Value, json};

use crate::binary::Cache;
use crate::tools;

/// Options whose value is a number. Everything else, addresses included, stays text.
const NUMERIC: [&str; 7] = ["limit", "len", "timeout", "count", "param", "arg", "depth"];
/// Options that are on or off.
const FLAGS: [&str; 2] = ["pcode", "returns"];

pub fn usage() -> String {
    let mut text = String::from(
        "recore-mcp                               serve the Model Context Protocol on stdin and stdout\n\
         recore-mcp <tool> <binary> [arguments]   run one tool and print its answer\n\n\
         Plain arguments are what the tool looks up: a pattern, an address, a function name, or\n\
         several functions for `decompile`. Other arguments are options, such as --limit 20.\n\n",
    );
    for tool in tools::list().as_array().into_iter().flatten() {
        let options: Vec<String> = tool["inputSchema"]["properties"].as_object().into_iter().flatten().filter(|(name, _)| *name != "path").map(|(name, _)| format!("--{name}")).collect();
        text += &format!("{} ({})\n    {}\n", tool["name"].as_str().unwrap_or_default(), options.join(" "), tool["description"].as_str().unwrap_or_default());
    }
    text
}

/// Turns shell arguments into the tool's arguments: `--key value` pairs as they are, and plain
/// arguments under the name the tool's main argument has.
fn arguments(tool: &str, binary: &str, rest: &[String]) -> Result<Value> {
    let mut named = Map::from_iter([("path".to_string(), json!(binary))]);
    let mut plain = Vec::new();
    let mut rest = rest.iter();
    while let Some(argument) = rest.next() {
        let Some(key) = argument.strip_prefix("--") else {
            plain.push(argument.as_str());
            continue;
        };
        if FLAGS.contains(&key) {
            named.insert(key.to_string(), json!(true));
            continue;
        }
        let Some(value) = rest.next() else { bail!("--{key} needs a value") };
        let number = || value.parse::<u64>().map(Value::from).or_else(|_| value.parse::<f64>().map(Value::from));
        let value = if NUMERIC.contains(&key) { number()? } else { json!(value) };
        named.insert(key.to_string(), value);
    }
    match (tool, plain.as_slice()) {
        (_, []) => {}
        ("decompile", functions) => drop(named.insert("functions".into(), json!(functions))),
        ("strings" | "imports" | "functions" | "classes" | "symbols", [pattern]) => drop(named.insert("pattern".into(), json!(pattern))),
        ("disassemble" | "pcode" | "trace", [function]) => drop(named.insert("function".into(), json!(function))),
        ("rename", [addr, name]) => {
            named.insert("addr".into(), json!(addr));
            named.insert("name".into(), json!(name));
        }
        ("comment", [addr, text]) => {
            named.insert("addr".into(), json!(addr));
            named.insert("text".into(), json!(text));
        }
        ("declare", [code]) => drop(named.insert("code".into(), json!(code))),
        ("declare", [addr, kind]) => {
            named.insert("addr".into(), json!(addr));
            named.insert("type".into(), json!(kind));
        }
        ("type", [name]) => drop(named.insert("name".into(), json!(name))),
        // `add` is a name and a hex number; a function called that needs `--name add`.
        ("function", [which]) => drop(named.insert(if parse_addr(which).is_some() { "addr" } else { "name" }.into(), json!(which))),
        ("xrefs" | "addr", [addr]) => drop(named.insert("addr".into(), json!(addr))),
        ("bytes", [addr, len @ ..]) if len.len() <= 1 => {
            named.insert("addr".into(), json!(addr));
            if let [len] = len {
                named.insert("len".into(), json!(len.parse::<u64>()?));
            }
        }
        _ => bail!("`{tool}` does not take {} plain arguments; see recore-mcp --help", plain.len()),
    }
    Ok(Value::Object(named))
}

/// Runs one tool and returns what it answers.
pub fn run(tool: &str, binary: &str, rest: &[String]) -> Result<String> {
    let arguments = arguments(tool, binary, rest)?;
    match tools::call(&mut Cache::default(), tool, arguments) {
        Some(answer) => answer,
        None => bail!("there is no tool `{tool}`\n\n{}", usage()),
    }
}
