//! A Model Context Protocol server over stdio: recore's analysis and the decompiler as tools.
//!
//! Given a tool name and a binary as arguments it runs that one tool and prints the answer; see
//! `cli`. Otherwise it serves. Messages are JSON-RPC 2.0, one per line. The server answers one request at a time and keeps
//! every binary it has analyzed, so a session pays for analysis once per binary.

mod binary;
mod cli;
mod code;
mod edit;
mod tools;

use std::io::{BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use binary::Cache;

/// This program is also its own decompiler process, which lives on small allocations.
#[global_allocator]
static ALLOCATOR: recore_decomp::MiMalloc = recore_decomp::MiMalloc;

/// First argument of the child processes that decompile: see `recore_decomp::isolate`.
const WORKER_ARG: &str = "decompile-worker";

/// Protocol revisions this server can speak. They do not differ in anything it uses.
const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [worker, binary, options] if worker == WORKER_ARG => return recore_decomp::isolate::serve(Path::new(binary), options),
        [tool, binary, rest @ ..] if !tool.starts_with('-') => {
            // A reader such as `head` may stop before the answer is all written.
            let _ = std::io::stdout().write_all(cli::run(tool, binary, rest)?.as_bytes());
            return Ok(());
        }
        _ => {
            print!("{}", cli::usage());
            return Ok(());
        }
    }

    let mut cache = Cache::default();
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handle(&mut cache, &line) {
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// Answers one message. Notifications and the client's own responses get no answer.
fn handle(cache: &mut Cache, line: &str) -> Option<Value> {
    let failure = |id: Value, code: i32, message: String| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } });
    let message: Value = match serde_json::from_str(line) {
        Ok(message) => message,
        Err(error) => return Some(failure(Value::Null, PARSE_ERROR, format!("not JSON: {error}"))),
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // A response to a request of ours would look like this, and this server sends none.
        return (!message.is_object()).then(|| failure(Value::Null, INVALID_REQUEST, "expected one JSON-RPC request object".into()));
    };
    let id = message.get("id")?.clone();
    let params = message.get("params");

    let result = match method {
        "initialize" => {
            let requested = params.and_then(|p| p.get("protocolVersion")).and_then(Value::as_str);
            let version = requested.filter(|v| PROTOCOL_VERSIONS.contains(v)).unwrap_or(PROTOCOL_VERSIONS[0]);
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "recore-mcp", "version": env!("CARGO_PKG_VERSION") },
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools::list() }),
        "tools/call" => {
            let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
                return Some(failure(id, INVALID_PARAMS, "tools/call needs a tool name".into()));
            };
            let arguments = params.and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
            // A panic in the analysis of one odd file must not end the session.
            let outcome = catch_unwind(AssertUnwindSafe(|| tools::call(cache, name, arguments)))
                .unwrap_or_else(|_| Some(Err(anyhow::anyhow!("internal error in `{name}`; the server is still running"))));
            match outcome {
                Some(Ok(text)) => json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
                Some(Err(error)) => json!({ "content": [{ "type": "text", "text": format!("{error:#}") }], "isError": true }),
                None => return Some(failure(id, INVALID_PARAMS, format!("unknown tool `{name}`"))),
            }
        }
        _ => return Some(failure(id, METHOD_NOT_FOUND, format!("unknown method `{method}`"))),
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}
