//! What the tests that speak to the server share: spawning it and calling its tools.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

/// The server itself is the binary under analysis, so the tests need no corpus.
pub const SERVER: &str = env!("CARGO_BIN_EXE_recore-mcp");

pub struct Client {
    pub child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

/// A directory of its own for a server's edits, so that no test writes to the user's.
pub fn edits_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!("recore-mcp-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)))
}

impl Client {
    pub fn start() -> Client {
        Client::start_in(&edits_dir())
    }

    /// Starts a server that keeps its edits in `edits`.
    pub fn start_in(edits: &Path) -> Client {
        let mut child = Command::new(SERVER).env(recore::edits::DIR_VAR, edits).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Client { child, stdin, stdout, next_id: 0 }
    }

    pub fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
    }

    pub fn receive(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// Sends a request and returns the reply, which must be the next line the server writes.
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params }).to_string());
        let reply = self.receive();
        assert_eq!(reply["id"], self.next_id, "{reply}");
        reply
    }

    /// Calls a tool on the server's own executable, or on the binary `arguments` names. `Err`
    /// is a tool error's message.
    pub fn tool(&mut self, name: &str, mut arguments: Value) -> Result<String, String> {
        if arguments["path"].is_null() {
            arguments["path"] = SERVER.into();
        }
        let reply = self.request("tools/call", json!({ "name": name, "arguments": arguments }));
        let text = reply["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("{reply}")).to_string();
        if reply["result"]["isError"] == true { Err(text) } else { Ok(text) }
    }

    pub fn entry(&mut self) -> String {
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
