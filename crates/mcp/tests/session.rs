//! The server as a client sees it: spawned, and spoken to over its stdin and stdout.

mod common;

use std::process::Command;
use std::time::Duration;

use common::{Client, SERVER, edits_dir};
use serde_json::{Value, json};

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
        ["summary", "strings", "imports", "functions", "function", "xrefs", "decompile", "unnamed", "bytes", "classes", "addr", "disassemble", "pcode", "trace", "run", "symbols", "diff", "rename", "comment", "declare", "type"]
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
fn a_function_changed_in_numbers_only_shows_the_numbers() {
    // The same function in two builds, with its assertion on line 1001 of the source in one
    // and on line 1009 in the other.
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data");
    let diff = Client::start().tool("diff", json!({ "path": format!("{data}/lines.elf"), "to": format!("{data}/lines-moved.elf") })).unwrap();
    assert!(diff.contains("\n0x1160 -> 0x1160  0x3e9 -> 0x3f1\n"), "{diff}");
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
fn data_is_told_by_what_its_pointers_reach() {
    // The fixture's first method record: its name, its function, a number and its documentation.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/tables.elf");
    let record = Client::start().tool("addr", json!({ "path": path, "addr": "0x3d60" })).unwrap();
    assert_eq!(record, "address 0x3d60, file offset 0x2d60, in .data.rel.ro: .data.rel.ro holding {\"twice\", function 0x11b0, 0x8, \"Return the value doubled.\", ...}\n");
}

#[test]
fn a_structure_passed_on_the_stack_reaches_the_call() {
    // `use` passes a 40-byte structure by value with two registers still free, so it goes on the
    // stack: its five fields are arguments of the call, and the callee reads them as parameters.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/aggregate.elf");
    let c_text = Client::start().tool("decompile", json!({ "path": path, "functions": ["0x112e", "0x1119"] })).unwrap();
    assert!(c_text.contains("func_0x00001119(param_1,7,param_1,2,3,4,param_1 * 2);"), "{c_text}");
    assert!(c_text.contains("return (param_2 * param_3 + param_1 + param_5) - param_7;"), "{c_text}");
}

#[test]
fn short_strings_a_table_points_to_read_as_text() {
    // One-character strings back to back read as UTF-16 too; pointers into them say otherwise.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/short.elf");
    let mut client = Client::start();
    assert_eq!(client.tool("strings", json!({ "path": path })).unwrap(), "0 strings\n");
    let text = client.tool("addr", json!({ "path": path, "addr": "0x2008" })).unwrap();
    assert_eq!(text, "address 0x2008, file offset 0x2008, in .rodata: text \"<\"\n");
}

#[test]
fn the_command_line_takes_counts_in_hex_and_says_how_it_read_an_address() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/short.elf");
    let run = |args: &[&str]| {
        let out = Command::new(SERVER).env(recore::edits::DIR_VAR, edits_dir()).args(args).output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    };
    let dump = run(&["bytes", path, "0x2008", "--len", "0x10"]);
    assert!(dump.starts_with("16 bytes at 0x2008 in .rodata"), "{dump}");
    let error = run(&["bytes", path, "29760"]);
    assert!(error.contains("0x29760 (`29760` is read as hex, 0x29760; decimal 29760 is 0x7440) has no bytes in the file"), "{error}");
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

/// The fixtures that `run` runs functions of, and the address each function has in them.
const ORACLE_ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/oracle.elf");
const ORACLE_THUMB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../decomp/tests/data/oracle-thumb.toml");

#[test]
fn a_function_runs_on_the_arguments_it_is_given() {
    let mut client = Client::start();
    let run = |client: &mut Client, function: &str, args: Value| client.tool("run", json!({ "path": ORACLE_ELF, "function": function, "args": args }));
    // weigh(1, ..., 8) sums i * i, and its last two arguments are on the stack.
    assert_eq!(run(&mut client, "0x1180", json!([1, 2, 3, 4, 5, 6, 7, 8])).unwrap(), "0x1180 returned RAX = 0xcc (204) after 17 instructions\n");
    // checksum reads a buffer and calls nothing. ends calls memcpy, whose stand-in runs.
    assert_eq!(run(&mut client, "0x11c1", json!(["hex:0102030405", 5])).unwrap(), "0x11c1 returned RAX = 0xf0c03 (986115) after 49 instructions\nargument 1, a buffer at 0x7ee01000, unchanged: 01 02 03 04 05\n");
    assert_eq!(
        run(&mut client, "0x129a", json!(["hex:4142434445", 5])).unwrap(),
        "0x129a returned RAX = 0x86 (134) after 13 instructions\nargument 1, a buffer at 0x7ee01000, unchanged: 41 42 43 44 45\nran stand-ins for: memcpy x1\n"
    );
    // reverse changes its buffer in place.
    assert!(run(&mut client, "0x1254", json!(["str:hello"])).unwrap().contains("argument 1, a buffer at 0x7ee01000, now: 6f 6c 6c 65 68 00\n"));
    // A jump table, and a global the function writes.
    assert!(run(&mut client, "0x12c1", json!([3])).unwrap().starts_with("0x12c1 returned RAX = 0x30 (48)"));
    assert!(run(&mut client, "0x1302", json!([5])).unwrap().ends_with("wrote 4 bytes at 0x4034: 05 00 00 00\n"));
    // x86 stops at a division by zero, and the answer says where.
    assert_eq!(run(&mut client, "0x11f9", json!([7, 0])).unwrap(), "0x11f9 stopped after 3 instructions: division by zero at 0x11fc\n");
    // A function that never ends in the steps it gets.
    let limited = client.tool("run", json!({ "path": ORACLE_ELF, "function": "0x11ff", "args": [27], "steps": 50 })).unwrap();
    assert_eq!(limited, "0x11ff did not return in 50 instructions; RAX holds 0x1f\n");
    // fill writes 40 bytes through a buffer of 8: the 8 show in the buffer, and the 32 past its end
    // are reported as the memory they landed in.
    let overrun = run(&mut client, "0x1400", json!(["buf:8", 40])).unwrap();
    assert!(overrun.contains("argument 1, a buffer at 0x7ee01000, now: 07 07 07 07 07 07 07 07\nwrote 32 bytes at 0x7ee01008: 07"), "{overrun}");
    // A lock prefix and a float in an SSE register: 2.5 cuts to 2, and not a number to the lowest integer.
    assert_eq!(run(&mut client, "0x1416", json!(["hex:0a000000"])).unwrap(), "0x1416 returned RAX = 0xa (10) after 3 instructions\nargument 1, a buffer at 0x7ee01000, now: 0d 00 00 00\n");
    let truncate = |client: &mut Client, bits: &str| client.tool("run", json!({ "path": ORACLE_ELF, "function": "0x1420", "set": [format!("XMM0={bits}")], "bits": 32 })).unwrap();
    assert_eq!(truncate(&mut client, "0x4004000000000000"), "0x1420(truncate) returned RAX = 0x2 (2) after 2 instructions\n");
    assert_eq!(truncate(&mut client, "0x7ff8000000000000"), "0x1420(truncate) returned RAX = 0x80000000 (2147483648, -2147483648 signed) after 2 instructions\n");
    // Sizes the oracle cannot give, and a memory the processor does not have, are refused.
    assert!(run(&mut client, "0x11c1", json!(["buf:0xffffffffff", 1])).unwrap_err().contains("more than the 16777216 that fit a block"));
    assert!(client.tool("run", json!({ "path": ORACLE_ELF, "function": "0x1302", "set": ["xdata:0x100=hex:00"] })).unwrap_err().contains("this processor has no memory called xdata"));
    // malloc is a stand-in whose block can be read after the run.
    let table = client.tool("run", json!({ "path": ORACLE_ELF, "function": "0x1311", "args": [4], "dump": ["0x7ee01000:16"] })).unwrap();
    assert!(table.contains("16 bytes at 0x7ee01000: 00 00 00 00 01 00 00 00 04 00 00 00 09 00 00 00\n"), "{table}");
}

#[test]
fn a_firmware_function_reports_the_memory_nothing_gave_it() {
    let mut client = Client::start();
    let run = |client: &mut Client, function: &str, args: Value, set: Value| client.tool("run", json!({ "path": ORACLE_THUMB, "function": function, "args": args, "set": set }));
    assert_eq!(run(&mut client, "0x2c", json!([1, 2, 3, 4, 5, 6]), json!([])).unwrap(), "0x2c returned r0 = 0x5b (91) after 11 instructions\n");
    // A Cortex-M divides by zero to zero.
    assert_eq!(run(&mut client, "0x24", json!([7, 0]), json!([])).unwrap(), "0x24 returned r0 = 0x0 (0) after 2 instructions\n");
    // A UART's status register is nothing the function wrote, and the answer says so.
    assert_eq!(
        run(&mut client, "0x60", json!([]), json!([])).unwrap(),
        "0x60 returned r0 = 0x0 (0) after 4 instructions\nread memory that nothing had written and the file does not hold 1x, as zeros: the first at 0x40004000 (peripherals)\n"
    );
    // The counter in RAM is a global the caller seeds.
    let bumped = run(&mut client, "0x50", json!([5]), json!(["0x20000000=hex:0a000000"])).unwrap();
    assert_eq!(bumped, "0x50 returned r0 = 0xf (15) after 6 instructions\nwrote 4 bytes at 0x20000000: 0f 00 00 00\n");
}

#[test]
fn an_8051_function_runs_on_the_registers_and_memory_it_is_given() {
    // start: MOV SP,#0x2c; SJMP start.
    // add5 (5): MOV A,DPL; ADD A,#5; MOV DPL,A; RET.
    // bump (0xc): MOV DPTR,#0x100; MOVX A,@DPTR; INC A; MOVX @DPTR,A; MOV DPL,A; RET.
    // port (0x15): MOV A,P1; MOV DPL,A; RET.
    // poke (0x1a): MOV 0x60,#0x55; RET.
    // banks (0x1e): MOV R3,#0x11; SETB RS0; MOV R3,#0x55; CLR RS0; MOV DPL,R3; MOV R0,#3; MOV A,@R0;
    //   MOV DPTR,#0; MOVX @DPTR,A; MOV A,0x0B; INC DPTR; MOVX @DPTR,A; RET.
    let code = [
        0x75, 0x81, 0x2C, 0x80, 0xFE, 0xE5, 0x82, 0x24, 0x05, 0xF5, 0x82, 0x22, 0x90, 0x01, 0x00, 0xE0, 0x04, 0xF0, 0xF5, 0x82, 0x22, 0xE5, 0x90, 0xF5, 0x82, 0x22, 0x75, 0x60, 0x55, 0x22,
        0x7B, 0x11, 0xD2, 0xD3, 0x7B, 0x55, 0xC2, 0xD3, 0x8B, 0x82, 0x78, 0x03, 0xE6, 0x90, 0x00, 0x00, 0xF0, 0xE5, 0x0B, 0xA3, 0xF0, 0x22,
    ];
    let dir = edits_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("code.bin"), code).unwrap();
    std::fs::write(dir.join("image.toml"), format!("machine = \"8051\"\ncompiler = \"sdcc\"\nentry = [0]\n[[region]]\nfile = \"code.bin\"\noffset = 0\nlength = {}\naddress = 0\nexecutable = true\n", code.len())).unwrap();
    let path = dir.join("image.toml");
    let mut client = Client::start_in(&dir.join("edits"));
    let mut run = |function: &str, set: Value| client.tool("run", json!({ "path": path, "function": function, "set": set }));
    // A result is DPL, then DPH, B and A for a wider one. The stack begins where the startup code puts it.
    let rest = "DPH = 0x0 (0)\nB = 0x0 (0)\nACC = 0xc (12)\nthe internal stack began at SP = 0x2c, as the startup code sets it\n";
    assert_eq!(run("0x5", json!(["DPL=7"])).unwrap(), format!("0x5 returned DPL = 0xc (12) after 4 instructions\n{rest}"));
    let bumped = run("0xc", json!(["EXTMEM:0x100=hex:09"])).unwrap();
    assert!(bumped.starts_with("0xc returned DPL = 0xa (10) after 6 instructions\n") && bumped.contains("wrote 1 byte at EXTMEM:0x100: 0a\n"), "{bumped}");
    // An unwritten special function register is a read of the chip.
    let port = run("0x15", json!([])).unwrap();
    assert!(port.contains("read memory that nothing had written and the file does not hold 1x, as zeros: the first at SFR:0x90\n"), "{port}");
    // Data above the stack pointer is the program's, and the stack the call pushed is not.
    let poke = run("0x1a", json!([])).unwrap();
    assert!(poke.contains("wrote 1 byte at INTMEM:0x60: 55\n") && !poke.contains("INTMEM:0x2d"), "{poke}");
    // R0 to R7 are the bytes of the register bank PSW selects. Bank 1's R3 is at 0x0B, the bank 0 R3 is
    // what @R0 reaches at 3, and the answer is what µCsim, a simulator of the chip, leaves in memory.
    let banks = run("0x1e", json!([])).unwrap();
    assert!(banks.contains("wrote 1 byte at INTMEM:0xb: 55\nwrote 2 bytes at EXTMEM:0x0: 11 55\n") && !banks.contains("nothing had written"), "{banks}");
    // The caller can place the stack, and a memory the processor lacks is refused.
    assert!(run("0x5", json!(["SP=0x50"])).unwrap().contains("the internal stack began where the caller set SP\n"));
    assert!(run("0x5", json!(["XDATA:0x1=hex:00"])).unwrap_err().contains("this processor has no memory called XDATA"));
    drop(client);
    std::fs::remove_dir_all(&dir).unwrap();
}
