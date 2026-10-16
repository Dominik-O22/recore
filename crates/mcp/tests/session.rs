//! The server as a client sees it: spawned, and spoken to over its stdin and stdout.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

/// The server itself is the binary under analysis, so the tests need no corpus.
const SERVER: &str = env!("CARGO_BIN_EXE_recore-mcp");

struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

/// A directory of its own for a server's edits, so that no test writes to the user's.
fn edits_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!("recore-mcp-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)))
}

impl Client {
    fn start() -> Client {
        Client::start_in(&edits_dir())
    }

    /// Starts a server that keeps its edits in `edits`.
    fn start_in(edits: &Path) -> Client {
        let mut child = Command::new(SERVER).env(recore::edits::DIR_VAR, edits).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Client { child, stdin, stdout, next_id: 0 }
    }

    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
    }

    fn receive(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// Sends a request and returns the reply, which must be the next line the server writes.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params }).to_string());
        let reply = self.receive();
        assert_eq!(reply["id"], self.next_id, "{reply}");
        reply
    }

    /// Calls a tool on the server's own executable, or on the binary `arguments` names. `Err`
    /// is a tool error's message.
    fn tool(&mut self, name: &str, mut arguments: Value) -> Result<String, String> {
        if arguments["path"].is_null() {
            arguments["path"] = SERVER.into();
        }
        let reply = self.request("tools/call", json!({ "name": name, "arguments": arguments }));
        let text = reply["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("{reply}")).to_string();
        if reply["result"]["isError"] == true { Err(text) } else { Ok(text) }
    }

    fn entry(&mut self) -> String {
        let summary = self.tool("summary", json!({})).unwrap();
        summary.split("entry ").nth(1).unwrap().lines().next().unwrap().to_string()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn speaks_the_protocol() {
    let mut client = Client::start();
    let reply = client.request("initialize", json!({ "protocolVersion": "2024-11-05", "capabilities": {} }));
    assert_eq!(reply["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(reply["result"]["serverInfo"]["name"], "recore-mcp");
    // A notification gets no reply: the next line answers the ping.
    client.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));

    let tools = client.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|tool| tool["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["summary", "strings", "imports", "functions", "function", "xrefs", "decompile", "unnamed", "bytes", "classes", "addr", "disassemble", "pcode", "trace", "symbols", "diff", "rename", "comment", "declare", "type"]
    );

    assert_eq!(client.request("resources/list", json!({}))["error"]["code"], -32601);
    assert_eq!(client.request("tools/call", json!({ "name": "nope" }))["error"]["code"], -32602);
    client.send("not json");
    assert_eq!(client.receive()["error"]["code"], -32700);
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));
}

#[test]
fn answers_queries_and_reports_bad_input_as_tool_errors() {
    let mut client = Client::start();
    let summary = client.tool("summary", json!({})).unwrap();
    assert!(summary.contains("ELF, x86-64"), "{summary}");

    let entry = client.entry();
    let function = client.tool("function", json!({ "addr": entry })).unwrap();
    assert!(function.starts_with(&format!("function {entry}")), "{function}");
    // The same address without its prefix.
    assert_eq!(client.tool("function", json!({ "addr": entry.trim_start_matches("0x") })).unwrap(), function);
    assert!(client.tool("bytes", json!({ "addr": entry, "len": 16 })).unwrap().starts_with("16 bytes at"));
    let imports = client.tool("imports", json!({ "pattern": "MALLOC" })).unwrap();
    assert!(imports.lines().any(|line| line.starts_with("malloc ") && line.contains("called by: 0x")), "{imports}");

    assert!(client.tool("bytes", json!({ "addr": "0" })).unwrap_err().contains("has no bytes"));
    assert!(client.tool("xrefs", json!({ "addr": "main" })).unwrap_err().contains("not a hex address"));
    assert!(client.tool("xrefs", json!({})).unwrap_err().contains("needs either `addr` or `offset`"));
    let missing = client.request("tools/call", json!({ "name": "summary", "arguments": { "path": "/nonexistent/binary" } }));
    assert_eq!(missing["result"]["isError"], true);
    assert!(missing["result"]["content"][0]["text"].as_str().unwrap().contains("cannot read /nonexistent/binary"));
}

#[test]
fn decompiling_survives_a_timeout_and_a_dead_child() {
    let mut client = Client::start();
    let entry = client.entry();
    let decompile = |client: &mut Client, timeout: f64| client.tool("decompile", json!({ "functions": [entry], "timeout": timeout }));
    let c_text = decompile(&mut client, 60.0).unwrap();
    assert!(c_text.contains('{'), "{c_text}");

    // No function finishes in no time, so this one's child is killed and replaced.
    assert!(decompile(&mut client, 0.0).unwrap_err().contains("timed out"));
    assert_eq!(decompile(&mut client, 60.0).unwrap().lines().skip(1).collect::<Vec<_>>(), c_text.lines().skip(1).collect::<Vec<_>>());

    // The child dies between requests, as after a fault or the kernel reclaiming memory.
    let server = client.child.id().to_string();
    assert!(Command::new("pkill").args(["-KILL", "-P", &server]).status().unwrap().success());
    std::thread::sleep(Duration::from_millis(200));
    assert!(decompile(&mut client, 60.0).unwrap().contains('{'));
}

#[test]
fn edits_reach_every_view_and_outlive_the_server() {
    let edits = edits_dir();
    let mut client = Client::start_in(&edits);
    let entry = client.entry();
    client.tool("rename", json!({ "addr": entry, "name": "program_start" })).unwrap();
    client.tool("comment", json!({ "addr": entry, "text": "where the loader hands over" })).unwrap();
    client.tool("declare", json!({ "code": "struct Pair { int4 left; int8 right; };" })).unwrap();
    assert!(client.tool("declare", json!({ "code": "struct Bad { nosuchtype x; };" })).unwrap_err().contains("does not take this declaration"));

    let listing = client.tool("disassemble", json!({ "function": "program_start", "count": 4 })).unwrap();
    assert!(listing.starts_with(&format!("function {entry}(program_start):")), "{listing}");
    assert!(listing.contains("// where the loader hands over"), "{listing}");
    let c_text = client.tool("decompile", json!({ "functions": ["program_start"], "timeout": 60.0 })).unwrap();
    assert!(c_text.contains("program_start("), "{c_text}");
    assert_eq!(client.tool("type", json!({ "name": "Pair" })).unwrap(), "struct Pair, 16 bytes, alignment 8\n  +0x0 int4 left (4 bytes)\n  +0x8 int8 right (8 bytes)\n");

    // A new server finds the edits; one that keeps its edits elsewhere does not.
    drop(client);
    let function = Client::start_in(&edits).tool("function", json!({ "name": "program_start" })).unwrap();
    assert!(function.starts_with(&format!("function {entry}(program_start):")), "{function}");
    assert!(Client::start().tool("function", json!({ "name": "program_start" })).unwrap_err().contains("no function is named"));
}

#[test]
fn a_variable_keeps_the_name_it_is_given() {
    // `total` of the decompiler's fixture: a loop over a list that sums into one temporary.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/types.elf");
    let edits = edits_dir();
    let mut client = Client::start_in(&edits);
    let renamed = client.tool("rename", json!({ "path": path, "names": [{ "addr": "0x401000", "var": "iVar1", "name": "sum" }, { "addr": "0x401000", "var": "list", "name": "item" }] })).unwrap();
    assert!(renamed.starts_with("iVar1 in 0x401000 is now sum\nlist in 0x401000 is now item\n"), "{renamed}");
    assert!(client.tool("rename", json!({ "path": path, "addr": "0x401000", "var": "scale", "name": "sum" })).unwrap_err().contains("already has a variable `sum`"));
    assert!(client.tool("rename", json!({ "path": path, "addr": "0x401000", "var": "iVar1", "name": "x" })).unwrap_err().contains("it has sum, scale, item"));

    drop(client);
    let c_text = Client::start_in(&edits).tool("decompile", json!({ "path": path, "functions": ["0x401000"] })).unwrap();
    assert!(c_text.contains("int4 total(node *item,int4 scale)"), "{c_text}");
    assert!(c_text.contains("sum = sum + scale * item->value;"), "{c_text}");
}

#[test]
fn a_patch_shows_as_the_functions_it_touched() {
    // Two builds of the decompiler's fixture: the later one has a check in `total`, which
    // calls a new function, and neither has a name to go by.
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data");
    let mut client = Client::start();
    let diff = client.tool("diff", json!({ "path": format!("{data}/types.elf"), "to": format!("{data}/types-patched.elf") })).unwrap();
    assert!(diff.starts_with("3 functions before, 4 after: 2 the same, 1 changed, 0 removed, 1 added\n"), "{diff}");
    // The changed function with what it now calls and the lines its C gained, then the new one.
    assert!(diff.contains("\n0x401000 39 -> 0x40100b 47  (called from the same place)\n    now calls 0x401000\n"), "{diff}");
    assert!(diff.contains("\n    + if (100 < param_2) {\n"), "{diff}");
    assert!(diff.ends_with("\nremoved: none\n\nadded\n0x401000 11\n"), "{diff}");
    // The one function, line by line: the check is new, and the loop it guards is not. The
    // earlier build has debug information and the later has none, so the loop's body reads
    // differently in each.
    let lines = client.tool("diff", json!({ "path": format!("{data}/types.elf"), "to": format!("{data}/types-patched.elf"), "function": "0x401000" })).unwrap();
    assert!(lines.starts_with("0x401000 -> 0x40100b\n"), "{lines}");
    assert!(lines.contains("\n+   if (100 < param_2) {\n"), "{lines}");
    assert!(lines.contains("\n    do {\n"), "{lines}");
}

#[test]
fn a_line_of_c_is_found_by_the_address_of_its_instruction() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/types.elf");
    let mut client = Client::start();
    let c_text = client.tool("decompile", json!({ "path": path, "functions": ["0x401000"], "addresses": true })).unwrap();
    assert!(c_text.contains("\n401017|     list = list->next;\n"), "{c_text}");
    assert!(c_text.contains("\n      | {\n"), "{c_text}");
    // An address alone names its function, and the lines without one are left as they were.
    let near = client.tool("decompile", json!({ "path": path, "around": "0x401017" })).unwrap();
    assert!(near.contains("\n401017|     list = list->next;\n"), "{near}");
    let plain = client.tool("decompile", json!({ "path": path, "functions": ["0x401000"] })).unwrap();
    assert!(plain.contains("\n    list = list->next;\n"), "{plain}");
}

#[test]
fn a_format_says_what_a_call_passes() {
    // `report` of the fixture loads a value and looks at it before passing it on with a format,
    // which the decompiler by itself takes for a value the call does not pass.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/format.elf");
    let c_text = Client::start().tool("decompile", json!({ "path": path, "functions": ["0x1220"] })).unwrap();
    assert!(c_text.contains("func_0x00001180(param_1,\"built from commit: %s\\n\",(char *)*param_2);"), "{c_text}");
    assert!(c_text.contains("func_0x00001180(param_1,\"no commit\\n\");"), "{c_text}");
}

#[test]
fn a_pointer_in_a_table_is_paired_with_the_name_of_its_own_record() {
    // A list of functions with a number between a function and its documentation, and a list
    // of pairs that close with their name.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/tables.elf");
    let mut client = Client::start();
    let doc = client.tool("xrefs", json!({ "path": path, "addr": "0x2070" })).unwrap();
    assert!(doc.contains("\n0x3d98 in .data.rel.ro holds a pointer to it, paired with the name \"negate\"\n"), "{doc}");
    let function = client.tool("function", json!({ "path": path, "addr": "0x11d0" })).unwrap();
    assert!(function.contains("listed as \"negate\" in the table at 0x3d88"), "{function}");
    let first = client.tool("xrefs", json!({ "path": path, "addr": "0x2068" })).unwrap();
    assert!(first.contains("\n0x3d20 in .data.rel.ro holds a pointer to it, paired with the name \"ValueError\"\n"), "{first}");
}

#[test]
fn memory_the_file_has_no_bytes_for_takes_a_name() {
    // An 8051 program: SETB 0xAF; MOV DPTR, #0x8100; MOVX @DPTR, A; RET.
    let dir = edits_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("code.bin"), [0xD2, 0xAF, 0x90, 0x81, 0x00, 0xF0, 0x22]).unwrap();
    std::fs::write(dir.join("image.toml"), "machine = \"8051\"\nentry = [0]\n[[region]]\nfile = \"code.bin\"\noffset = 0\nlength = 7\naddress = 0\nexecutable = true\n").unwrap();
    let path = dir.join("image.toml");
    let mut client = Client::start_in(&dir.join("edits"));
    // A bit, and a byte of external memory.
    client.tool("rename", json!({ "path": path, "addr": "0x4000000af", "name": "IRQ_ON" })).unwrap();
    client.tool("rename", json!({ "path": path, "addr": "0x100008100", "name": "LCD" })).unwrap();
    assert!(client.tool("rename", json!({ "path": path, "addr": "0x900000000", "name": "NOWHERE" })).unwrap_err().contains("is not in any section"));
    let c_text = client.tool("decompile", json!({ "path": path, "functions": ["0x0"] })).unwrap();
    drop(client);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(c_text.contains("IRQ_ON = 1;") && c_text.contains("LCD"), "{c_text}");
}
