//! The tools from a shell: `recore-mcp <tool> <binary> [arguments]` runs one and prints its answer.

use anyhow::{Context, Result, bail};
use recore::program::parse_addr;
use serde_json::{Map, Value, json};

use crate::binary::Cache;
use crate::tools;

pub fn usage() -> String {
    let mut text = String::from(
        "recore-mcp                               serve the Model Context Protocol on stdin and stdout\n\
         recore-mcp <tool> <binary> [arguments]   run one tool and print its answer\n\
         recore-mcp lift --config <lift.toml> [--out <dir>]\n\
         \x20                                        lift a 32-bit x86 program to Rust, as a cargo workspace\n\n\
         Plain arguments are what the tool looks up: a pattern, an address, a function name, or\n\
         several functions for `decompile`. Other arguments are options, such as --limit 20.\n\
         `recore-mcp <tool> --help` describes one tool and each of its options.\n\n",
    );
    for tool in tools::list().as_array().into_iter().flatten() {
        let options: Vec<String> = tool["inputSchema"]["properties"].as_object().into_iter().flatten().filter(|(name, _)| *name != "path").map(|(name, _)| format!("--{name}")).collect();
        text += &format!("{} ({})\n    {}\n", tool["name"].as_str().unwrap_or_default(), options.join(" "), tool["description"].as_str().unwrap_or_default());
    }
    text
}

/// Turns shell arguments into the tool's arguments: `--key value` pairs as they are, and plain
/// arguments under the name the tool's main argument has. The schema of each option says how
/// its value is read: a boolean is a flag that takes none, a number is parsed, and an array may be
/// given again and again. Everything else, addresses included, stays text.
fn arguments(tool: &str, properties: &Map<String, Value>, binary: &str, rest: &[String]) -> Result<Value> {
    let mut named = Map::from_iter([("path".to_string(), json!(binary))]);
    let mut plain = Vec::new();
    let mut rest = rest.iter();
    while let Some(argument) = rest.next() {
        let Some(key) = argument.strip_prefix("--") else {
            plain.push(argument.as_str());
            continue;
        };
        // `path` is the binary, which comes first and plain.
        let Some(kind) = properties.get(key).filter(|_| key != "path").map(|property| &property["type"]) else {
            return Err(tools::unknown_options(tool, &[key], properties.keys().map(String::as_str).filter(|name| *name != "path"), "--"));
        };
        if kind == "boolean" {
            named.insert(key.to_string(), json!(true));
            continue;
        }
        // The functions of `decompile` are its plain arguments, with or without the option, and
        // so are the renames of `rename`: an address and a name, again and again.
        if key == "functions" || key == "names" {
            continue;
        }
        let Some(value) = rest.next() else { bail!("--{key} needs a value") };
        // A count in decimal or in hex with `0x`, or seconds with a fraction.
        let hex = || value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).and_then(|digits| u64::from_str_radix(digits, 16).ok()).map(Value::from);
        let number = || hex().map(Ok).unwrap_or_else(|| value.parse::<u64>().map(Value::from).or_else(|_| value.parse::<f64>().map(Value::from)));
        let value = if kind == "integer" || kind == "number" { number().with_context(|| format!("--{key} takes a number, in decimal or with 0x in hex, not `{value}`"))? } else { json!(value) };
        if kind == "array" {
            named.entry(key).or_insert_with(|| json!([])).as_array_mut().expect("a list").push(value);
        } else {
            named.insert(key.to_string(), value);
        }
    }
    match (tool, plain.as_slice()) {
        (_, []) => {}
        // Separated by spaces or by commas.
        ("decompile", functions) => drop(named.insert("functions".into(), json!(functions.iter().flat_map(|listed| listed.split(',')).filter(|function| !function.is_empty()).collect::<Vec<_>>()))),
        ("strings" | "imports" | "functions" | "classes" | "symbols", [pattern]) => drop(named.insert("pattern".into(), json!(pattern))),
        ("disassemble" | "pcode" | "trace" | "structs", [function]) => drop(named.insert("function".into(), json!(function))),
        // The function, then its arguments: numbers, or `hex:`, `str:` and `buf:` for memory.
        ("run", [function, args @ ..]) if !named.contains_key("function") => {
            named.insert("function".into(), json!(function));
            named.entry("args").or_insert_with(|| json!([])).as_array_mut().expect("a list").extend(args.iter().map(|arg| json!(arg)));
        }
        ("rename", [addr, name]) => {
            named.insert("addr".into(), json!(addr));
            named.insert("name".into(), json!(name));
        }
        // Several at once: address and name, again and again.
        ("rename", pairs) if pairs.len() >= 4 && pairs.len() % 2 == 0 => {
            let names: Vec<Value> = pairs.chunks(2).map(|pair| json!({ "addr": pair[0], "name": pair[1] })).collect();
            named.insert("names".into(), json!(names));
        }
        ("rename", [function, var, name]) => {
            named.insert("addr".into(), json!(function));
            named.insert("var".into(), json!(var));
            named.insert("name".into(), json!(name));
        }
        ("comment", [addr, text]) => {
            named.insert("addr".into(), json!(addr));
            named.insert("text".into(), json!(text));
        }
        ("diff", [to]) => drop(named.insert("to".into(), json!(to))),
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

/// What one tool takes, for `recore-mcp <tool> --help`.
fn tool_usage(tool: &str, described: &Value, properties: &Map<String, Value>) -> String {
    let mut text = format!("recore-mcp {tool} <binary> [arguments]\n\n{}\n\n<binary>\n    The file to analyze, called `path` above.\n", described["description"].as_str().unwrap_or_default());
    for (name, property) in properties.iter().filter(|(name, _)| *name != "path") {
        text += &format!("--{name}\n    {}\n", property["description"].as_str().unwrap_or_default());
    }
    text
}

/// Runs one tool and returns what it answers.
pub fn run(tool: &str, binary: &str, rest: &[String]) -> Result<String> {
    let Some(described) = tools::described(tool) else { bail!("there is no tool `{tool}`\n\n{}", usage()) };
    let properties = described["inputSchema"]["properties"].as_object().context("the tool's schema has no properties")?;
    if binary == "--help" || rest.iter().any(|argument| argument == "--help") {
        return Ok(tool_usage(tool, &described, properties));
    }
    let arguments = arguments(tool, properties, binary, rest)?;
    tools::call(&mut Cache::new(tool == "decompile"), tool, arguments).with_context(|| format!("there is no tool `{tool}`"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn several_renames_are_plain_pairs_with_or_without_the_option() {
        let tools = tools::list();
        let rename = tools.as_array().unwrap().iter().find(|tool| tool["name"] == "rename").unwrap();
        let properties = rename["inputSchema"]["properties"].as_object().unwrap();
        let pairs = json!({ "path": "bin", "names": [{ "addr": "0x10", "name": "first" }, { "addr": "0x20", "name": "second" }] });
        for given in [&["--names", "0x10", "first", "0x20", "second"][..], &["0x10", "first", "0x20", "second"]] {
            let given: Vec<String> = given.iter().map(|word| word.to_string()).collect();
            assert_eq!(arguments("rename", properties, "bin", &given).unwrap(), pairs);
        }
    }

    #[test]
    fn an_unknown_option_is_refused_from_a_shell() {
        let error = run("functions", "/nonexistent/binary", &["--limt".into(), "2".into()]).unwrap_err();
        assert_eq!(error.to_string(), "`functions` has no option `--limt` (did you mean `--limit`?). Its options: `--limit`, `--pattern`, `--sort`.");
    }

    /// The schema says how each option's value is read: a flag, a number, or a list.
    #[test]
    fn options_are_read_as_their_schema_says() {
        let tools = tools::list();
        let run = tools.as_array().unwrap().iter().find(|tool| tool["name"] == "run").unwrap();
        let given = ["f", "1", "--steps", "0x10", "--set", "A=1", "--set", "B=2", "--coverage", "--snapshot", "12"].map(String::from);
        let read = arguments("run", run["inputSchema"]["properties"].as_object().unwrap(), "bin", &given).unwrap();
        assert_eq!(read, json!({ "path": "bin", "function": "f", "args": ["1"], "steps": 16, "set": ["A=1", "B=2"], "coverage": true, "snapshot": "12" }));
    }
}
