//! Railroad Tycoon 3 (MSVC 7, 2003), unpacked: `run` gets through the C runtime's string
//! functions, which ask the system for the thread's locale, and through the version API.
//! `RECORE_RT3` names the binary, which stays out of the repository.

mod common;

use common::{Client, edits_dir};
use serde_json::{Value, json};

/// The C runtime's `_mtinit`, its thread and lock setup.
const MTINIT: &str = "0x5abd49";

fn run(client: &mut Client, function: &str, options: Value) -> String {
    let mut arguments = json!({ "path": std::env::var("RECORE_RT3").expect("RECORE_RT3 names the binary"), "function": function });
    arguments.as_object_mut().unwrap().extend(options.as_object().unwrap().clone());
    client.tool("run", arguments).unwrap()
}

fn first_line(answer: &str) -> &str {
    answer.lines().next().unwrap()
}

#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn game_version_x100_reads_the_files_version_resource() {
    let mut client = Client::start();
    let answer = run(&mut client, "0x482e00", json!({}));
    assert_eq!(first_line(&answer), "0x482e00 returned EAX = 0x69 (105) after 270 instructions", "{answer}");
}

/// `_stricmp` and `strncmp` once `_mtinit` has set up the locks and the thread's data.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn the_c_runtimes_string_functions_run_once_it_has_started() {
    let mut client = Client::start();
    let stricmp = |client: &mut Client, a: &str, b: &str| run(client, "0x5a57cf", json!({ "args": [format!("str:{a}"), format!("str:{b}")], "before": [MTINIT], "bits": 32 }));
    assert!(first_line(&stricmp(&mut client, "WHALEl", "WhaleL")).contains(" returned EAX = 0x0 (0) "));
    assert!(first_line(&stricmp(&mut client, "Whale", "WhaleL")).contains(" returned EAX = 0xffffffff (4294967295, -1 signed) "));
    let strncmp = run(&mut client, "0x5a5f26", json!({ "args": ["str:abc", "str:abd", 2], "before": [MTINIT] }));
    assert!(first_line(&strncmp).contains(" returned EAX = 0x0 (0) "), "{strncmp}");
}

/// `car_offered` compares the engine's name with `_stricmp` on the way to its answer. One engine
/// of kind 2, offered from 1829 to 1840, in a game on February 1830.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn car_offered_runs() {
    let mut client = Client::start();
    let set = [
        "ECX=0x28900200",
        "0x6cec74=hex:00000023",
        "0x6cec78=hex:00000022",
        "0x6cec7c=hex:00001023",
        "0x6ada84=hex:00000028",
        // The game's date: 1830, month 2.
        "0x2200000d=hex:260702",
        // The engines, a collection of one at 0x28100100.
        "0x28000004=hex:0100000000010000",
        "0x28000014=hex:0200000001000000",
        "0x28000030=hex:0000102800010028",
        "0x28000068=hex:ffffffff",
        "0x28100134=hex:506c616e65744c00",
        "0x2810017b=hex:01000000",
        // The car: kind 2, years 1829 to 1840, engine 1.
        "0x28900241=hex:02000000",
        "0x28900305=hex:2507000030070000",
        "0x28900326=hex:01000000",
    ];
    let answer = run(&mut client, "0x41d550", json!({ "set": set, "args": [1, 0], "before": [MTINIT] }));
    assert!(first_line(&answer).starts_with("0x41d550 returned EAX = 0x1 (1) "), "{answer}");
    // `_mtinit` calls no TlsGetValue: these are `_stricmp`'s.
    assert!(answer.contains("TlsGetValue x2"), "{answer}");
}

/// A snapshot of a thread whose C runtime data is in place: its TLS slot 1, which the runtime's
/// index says is its own, holds the data, and the data's locale is the runtime's. `_stricmp`
/// then needs no setup and allocates nothing.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn the_c_runtime_finds_its_thread_data_in_a_snapshot() {
    let dir = edits_dir().join("snapshot");
    std::fs::create_dir_all(&dir).unwrap();
    let (teb, data) = (0x7ffd_0000u32, 0x3000_0000u32);
    let mut block = vec![0u8; 0x1000];
    block[0x18..0x1c].copy_from_slice(&teb.to_le_bytes());
    block[0xe14..0xe18].copy_from_slice(&data.to_le_bytes());
    let mut thread_data = vec![0u8; 0x88];
    thread_data[0x64..0x68].copy_from_slice(&0x62a008u32.to_le_bytes());
    std::fs::write(dir.join("0062aa3c.bin"), 1u32.to_le_bytes()).unwrap();
    std::fs::write(dir.join("7ffd0000.bin"), block).unwrap();
    std::fs::write(dir.join("30000000.bin"), thread_data).unwrap();
    std::fs::write(dir.join("snapshot.tsv"), "region\t0062aa3c\t0062aa40\trw-p\tRT3.exe\nregion\t7ffd0000\t7ffd1000\trw-p\t\nregion\t30000000\t30001000\trw-p\t\nteb\t7ffd0000\n").unwrap();
    let mut client = Client::start();
    let answer = run(&mut client, "0x5a57cf", json!({ "args": ["str:WHALEl", "str:WhaleL"], "snapshot": dir }));
    assert!(first_line(&answer).contains(" returned EAX = 0x0 (0) "), "{answer}");
    assert!(answer.contains("ran stand-ins for: GetLastError x1, SetLastError x1, TlsGetValue x1\n"), "{answer}");
    std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
}
