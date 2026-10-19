//! `run` on a 32-bit Windows program: the stand-ins for the system functions the MSVC C runtime
//! calls, and a run that starts from a snapshot of a process. The program is written here, a PE
//! of hand-assembled functions that import what they test.

mod common;

use std::path::{Path, PathBuf};

use common::{Client, edits_dir};
use serde_json::{Value, json};

const BASE: u64 = 0x40_0000;
const TEXT: u64 = BASE + 0x1000;
const DATA: u64 = BASE + 0x2000;
const IDATA: u64 = BASE + 0x3000;
const RSRC: u64 = BASE + 0x4000;

const IMPORTS: [(&str, &[&str]); 2] = [
    ("KERNEL32.dll", &["GetLastError", "SetLastError", "TlsAlloc", "TlsGetValue", "TlsSetValue"]),
    ("VERSION.dll", &["GetFileVersionInfoSizeA", "GetFileVersionInfoA", "VerQueryValueA"]),
];

// Data the functions read: names, and where VerQueryValueA leaves its answer.
const NAME: u64 = DATA;
const ROOT: u64 = DATA + 0x10;
const TRANSLATION: u64 = DATA + 0x14;
const VALUE: u64 = DATA + 0x40;
const VALUE_LEN: u64 = DATA + 0x44;
const GLOBAL: u64 = DATA + 0x48;
const SAVED_INDEX: u64 = DATA + 0x4c;
const VERSION_BUFFER: u64 = DATA + 0x100;

/// The address of the import address table slot of `function`.
fn slot(function: &str) -> u64 {
    let mut at = IDATA + 0x100;
    for (_, functions) in IMPORTS {
        for name in functions {
            if *name == function {
                return at;
            }
            at += 4;
        }
        at += 4;
    }
    panic!("{function} is not imported");
}

fn le(value: u64) -> [u8; 4] {
    (value as u32).to_le_bytes()
}

/// x86 instructions, as the functions below use them.
fn call(function: &str) -> Vec<u8> {
    [&[0xff, 0x15][..], &le(slot(function))].concat()
}
fn push(value: u64) -> Vec<u8> {
    [&[0x68][..], &le(value)].concat()
}
fn push_from(addr: u64) -> Vec<u8> {
    [&[0xff, 0x35][..], &le(addr)].concat()
}
fn load_eax(addr: u64) -> Vec<u8> {
    [&[0xa1][..], &le(addr)].concat()
}
fn store_eax(addr: u64) -> Vec<u8> {
    [&[0xa3][..], &le(addr)].concat()
}
fn add_eax(addr: u64) -> Vec<u8> {
    [&[0x03, 0x05][..], &le(addr)].concat()
}
const RET: u8 = 0xc3;

/// The functions of the program, each with its name.
fn functions() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        // TlsAlloc, TlsSetValue(index, 0x55aa), TlsGetValue(index), which pop their arguments.
        ("tls", [vec![0x56], call("TlsAlloc"), vec![0x8b, 0xf0], push(0x55aa), vec![0x56], call("TlsSetValue"), vec![0x56], call("TlsGetValue"), vec![0x5e, RET]].concat()),
        ("last_error", [push(5), call("SetLastError"), call("GetLastError"), vec![RET]].concat()),
        // The TLS index of a C runtime whose startup did not run, TLS_OUT_OF_INDEXES.
        ("unallocated", [push(7), push(0xffff_ffff), call("TlsSetValue"), push(0xffff_ffff), call("TlsGetValue"), vec![RET]].concat()),
        // MOV EAX, FS:[0x18], the block's own address.
        ("teb", vec![0x64, 0xa1, 0x18, 0, 0, 0, RET]),
        // dwFileVersionMS of the fixed file information.
        ("file_version", [push(0), push(NAME), call("GetFileVersionInfoSizeA"), push(VERSION_BUFFER), vec![0x50], push(0), push(NAME), call("GetFileVersionInfoA"), push(VALUE_LEN), push(VALUE), push(ROOT), push(VERSION_BUFFER), call("VerQueryValueA"), load_eax(VALUE), vec![0x8b, 0x40, 0x08, RET]].concat()),
        ("translation", [push(0), push(NAME), call("GetFileVersionInfoSizeA"), push(VERSION_BUFFER), vec![0x50], push(0), push(NAME), call("GetFileVersionInfoA"), push(VALUE_LEN), push(VALUE), push(TRANSLATION), push(VERSION_BUFFER), call("VerQueryValueA"), load_eax(VALUE), vec![0x8b, 0x00, RET]].concat()),
        ("globals", [load_eax(0x1000_0000), add_eax(GLOBAL), add_eax(0x1000_0004), vec![RET]].concat()),
        ("slot_3", [push(3), call("TlsGetValue"), vec![RET]].concat()),
        // Setup and the function it is for: a TLS index kept in a global, and its value.
        ("init", [call("TlsAlloc"), store_eax(SAVED_INDEX), push(0x77), vec![0x50], call("TlsSetValue"), vec![RET]].concat()),
        ("saved", [push_from(SAVED_INDEX), call("TlsGetValue"), vec![RET]].concat()),
    ]
}

/// The address of each function in `.text`, after the entry, which calls them all.
fn layout() -> (Vec<u8>, Vec<(&'static str, u64)>) {
    let functions = functions();
    let mut at = TEXT + 5 * functions.len() as u64 + 1;
    let mut placed = Vec::new();
    for (name, code) in &functions {
        placed.push((*name, at));
        at += code.len() as u64;
    }
    let mut text = Vec::new();
    for &(_, addr) in &placed {
        let from = TEXT + text.len() as u64 + 5;
        text.push(0xe8);
        text.extend((addr.wrapping_sub(from) as u32).to_le_bytes());
    }
    text.push(RET);
    for (_, code) in functions {
        text.extend(code);
    }
    (text, placed)
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// A version block: its length, its value's, its type, its name, the value and the blocks in it.
fn version_block(name: &str, value: &[u8], text: bool, children: &[u8]) -> Vec<u8> {
    let mut block = vec![0; 6];
    block.extend(utf16(name));
    block.resize(block.len().next_multiple_of(4), 0);
    block.extend(value);
    block.resize(block.len().next_multiple_of(4), 0);
    block.extend(children);
    let length = block.len() as u16;
    let value_length = if text { value.len() / 2 } else { value.len() } as u16;
    block[..6].copy_from_slice(&[length.to_le_bytes(), value_length.to_le_bytes(), u16::from(text).to_le_bytes()].concat());
    block
}

/// The resource directory: one `RT_VERSION`, version 1.5.2.3, in US English.
fn resources() -> Vec<u8> {
    let fixed: Vec<u8> = [0xfeef_04bd, 0x0001_0000, 0x0001_0005, 0x0002_0003, 0x0001_0005, 0x0002_0003, 0x3f, 0, 0x4, 0x1, 0, 0, 0].iter().flat_map(|&word: &u32| word.to_le_bytes()).collect();
    let translation = version_block("Translation", &0x04b0_0409u32.to_le_bytes(), false, &[]);
    let info = version_block("VS_VERSION_INFO", &fixed, false, &version_block("VarFileInfo", &[], true, &translation));
    let table = |entry: u32, to: u32| [&[0u8; 14][..], &1u16.to_le_bytes(), &entry.to_le_bytes(), &to.to_le_bytes()].concat();
    let mut rsrc = [table(16, 0x8000_0018), table(1, 0x8000_0030), table(0x409, 0x48)].concat();
    rsrc.extend([le(RSRC - BASE + 0x58), le(info.len() as u64), [0; 4], [0; 4]].concat());
    rsrc.extend(info);
    rsrc
}

/// The import directory at `IDATA`: descriptors, then names at 0x40, then the address table at
/// 0x100, which the lookup table at 0x80 repeats, and the functions' names at 0x130.
fn imports() -> Vec<u8> {
    let mut idata = vec![0; 0x200];
    let (mut names, mut slot) = (0x130usize, 0usize);
    for (index, (dll, functions)) in IMPORTS.iter().enumerate() {
        let descriptor = 20 * index;
        let first = slot;
        for function in *functions {
            let hint = names;
            idata[hint + 2..hint + 2 + function.len()].copy_from_slice(function.as_bytes());
            names = (hint + 3 + function.len()).next_multiple_of(2);
            let rva = le(IDATA - BASE + hint as u64);
            idata[0x80 + 4 * slot..0x84 + 4 * slot].copy_from_slice(&rva);
            idata[0x100 + 4 * slot..0x104 + 4 * slot].copy_from_slice(&rva);
            slot += 1;
        }
        slot += 1;
        let name = 0x40 + 0x10 * index;
        idata[name..name + dll.len()].copy_from_slice(dll.as_bytes());
        idata[descriptor..descriptor + 4].copy_from_slice(&le(IDATA - BASE + 0x80 + 4 * first as u64));
        idata[descriptor + 12..descriptor + 16].copy_from_slice(&le(IDATA - BASE + name as u64));
        idata[descriptor + 16..descriptor + 20].copy_from_slice(&le(IDATA - BASE + 0x100 + 4 * first as u64));
    }
    idata
}

fn data() -> Vec<u8> {
    let mut data = vec![0; 0x200];
    data[..6].copy_from_slice(b"t.exe\0");
    data[0x10..0x12].copy_from_slice(b"\\\0");
    data[0x14..0x14 + 25].copy_from_slice(b"\\VarFileInfo\\Translation\0");
    data[0x48..0x4c].copy_from_slice(&le(0x100));
    data
}

/// The program as a PE file, and the address of each function.
fn program() -> (Vec<u8>, Vec<(&'static str, u64)>) {
    let (text, placed) = layout();
    // Name, contents, size in memory, characteristics.
    let sections = [(".text", text, 0x1000, 0x6000_0020u32), (".data", data(), 0x1000, 0xc000_0040), (".idata", imports(), 0x1000, 0xc000_0040), (".rsrc", resources(), 0x1000, 0x4000_0040)];
    let mut file = vec![0u8; 0x200];
    file[..2].copy_from_slice(b"MZ");
    file[0x3c..0x40].copy_from_slice(&le(0x40));
    let mut headers = b"PE\0\0".to_vec();
    headers.extend([&0x14cu16.to_le_bytes()[..], &(sections.len() as u16).to_le_bytes(), &[0; 12], &0xe0u16.to_le_bytes(), &0x103u16.to_le_bytes()].concat());
    let size_of_image = 0x1000 * (sections.len() as u64 + 1);
    let words = |values: &[u32]| values.iter().flat_map(|value| value.to_le_bytes()).collect::<Vec<u8>>();
    headers.extend([0x0b, 0x01, 7, 10]);
    headers.extend(words(&[0x200, 0x600, 0, 0x1000, 0x1000, 0x2000, BASE as u32, 0x1000, 0x200]));
    headers.extend([4u16, 0, 0, 0, 4, 0].iter().flat_map(|half| half.to_le_bytes()));
    headers.extend(words(&[0, size_of_image as u32, 0x200, 0]));
    headers.extend([3u16, 0].iter().flat_map(|half| half.to_le_bytes()));
    headers.extend(words(&[0x10_0000, 0x1000, 0x10_0000, 0x1000, 0, 16]));
    let mut directories = [[0u32; 2]; 16];
    directories[1] = [(IDATA - BASE) as u32, 60];
    directories[2] = [(RSRC - BASE) as u32, sections[3].1.len() as u32];
    headers.extend(directories.iter().flat_map(|pair| words(pair)));
    for (index, (name, contents, size, characteristics)) in sections.iter().enumerate() {
        let mut header = [0u8; 40];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let raw = contents.len().next_multiple_of(0x200) as u32;
        let offset = 0x200 * (1 + index as u32);
        header[8..24].copy_from_slice(&words(&[*size, 0x1000 * (1 + index as u32), raw, offset]));
        header[36..].copy_from_slice(&characteristics.to_le_bytes());
        headers.extend(header);
    }
    file[0x40..0x40 + headers.len()].copy_from_slice(&headers);
    for (_, contents, _, _) in sections {
        assert!(contents.len() <= 0x200, "a section of the test program outgrew its 0x200 bytes");
        let mut raw = contents;
        raw.resize(0x200, 0);
        file.extend(raw);
    }
    (file, placed)
}

/// Writes a snapshot of `regions`, each its start, its end, and the bytes from its start that
/// it holds, and of the threads whose blocks are at `tebs`, as `rt3 probe` writes one.
fn write_snapshot(dir: &Path, regions: &[(u64, u64, &[u8])], tebs: &[u64]) {
    std::fs::create_dir_all(dir).unwrap();
    let mut manifest = String::new();
    for &(start, end, bytes) in regions {
        manifest += &format!("region\t{start:08x}\t{end:08x}\trw-p\t\n");
        std::fs::write(dir.join(format!("{start:08x}.bin")), bytes).unwrap();
    }
    for teb in tebs {
        manifest += &format!("teb\t{teb:08x}\n");
    }
    std::fs::write(dir.join("snapshot.tsv"), manifest).unwrap();
}

struct Program {
    dir: PathBuf,
    path: PathBuf,
    functions: Vec<(&'static str, u64)>,
    client: Client,
}

impl Program {
    fn new() -> Program {
        let dir = edits_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let (file, functions) = program();
        let path = dir.join("t.exe");
        std::fs::write(&path, file).unwrap();
        Program { client: Client::start_in(&dir.join("edits")), dir, path, functions }
    }

    fn addr(&self, function: &str) -> String {
        format!("{:#x}", self.functions.iter().find(|(name, _)| *name == function).unwrap().1)
    }

    fn run(&mut self, function: &str, mut options: Value) -> String {
        options["path"] = json!(self.path);
        options["function"] = json!(self.addr(function));
        self.client.tool("run", options).unwrap()
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The value a run returned in EAX, from the first line of its answer.
fn returned(answer: &str) -> &str {
    answer.split("returned EAX = ").nth(1).and_then(|rest| rest.split(' ').next()).unwrap_or_else(|| panic!("{answer}"))
}

#[test]
fn the_c_runtimes_system_functions_run_and_take_their_arguments_off_the_stack() {
    let mut program = Program::new();
    // A stand-in that left its arguments on the stack would return to one of them.
    let tls = program.run("tls", json!({}));
    assert_eq!(returned(&tls), "0x55aa", "{tls}");
    assert!(tls.contains("ran stand-ins for: TlsAlloc x1, TlsGetValue x1, TlsSetValue x1\n"), "{tls}");
    assert_eq!(returned(&program.run("last_error", json!({}))), "0x5");
    let unallocated = program.run("unallocated", json!({}));
    assert_eq!(returned(&unallocated), "0x7");
    assert!(unallocated.contains("TlsSetValue was given TLS index 0xffffffff, which the thread has no slot for"), "{unallocated}");
    // FS is a block of the run's own, below its scratch memory, whose writes are not listed.
    let teb = program.run("teb", json!({}));
    assert_eq!(teb, format!("{} returned EAX = 0x7edff000 (2128605184) after 2 instructions\n", program.addr("teb")));
}

#[test]
fn the_version_api_answers_from_the_binarys_own_resource() {
    let mut program = Program::new();
    let version = program.run("file_version", json!({}));
    assert_eq!(returned(&version), "0x10005", "{version}");
    assert!(version.contains("GetFileVersionInfoSizeA asked for the version of t.exe, and the binary's own version resource answered\n"), "{version}");
    assert_eq!(returned(&program.run("translation", json!({}))), "0x4b00409");
}

#[test]
fn a_run_starts_from_the_memory_of_a_snapshot() {
    let mut program = Program::new();
    let snapshot = program.dir.join("snapshot");
    let mut teb = vec![0u8; 0x1000];
    teb[0x18..0x1c].copy_from_slice(&le(0x7ffd_0000));
    teb[0xe1c..0xe20].copy_from_slice(&le(0xabcd));
    let mut data = data();
    data[0x48..0x4c].copy_from_slice(&le(0x200));
    // Beyond the image a word, in a region that holds only it; the image's data as the process
    // changed it; a thread; and a region where the run would put its stack.
    write_snapshot(&snapshot, &[(0x1000_0000, 0x1000_1000, &le(0x1122_0000)), (DATA, DATA + 0x1000, &data), (0x7ffd_0000, 0x7ffd_1000, &teb), (0x7fe0_0000, 0x7ff0_0000, &[])], &[0x7ffd_0000]);
    let globals = program.run("globals", json!({ "snapshot": snapshot, "args": ["str:x"] }));
    assert_eq!(returned(&globals), "0x11220200", "{globals}");
    assert!(globals.contains("as zeros: the first at 0x10000004"), "{globals}");
    assert!(globals.contains("argument 1, a buffer at 0x7ed01000, unchanged"), "{globals}");
    // `set` applies on top of the snapshot.
    assert_eq!(returned(&program.run("globals", json!({ "snapshot": snapshot, "set": ["0x10000000=hex:00003344"] }))), "0x44330200");
    // The thread's TLS slots are the snapshot's.
    let slot = program.run("slot_3", json!({ "snapshot": snapshot }));
    assert_eq!(returned(&slot), "0xabcd", "{slot}");
    assert!(slot.contains("the run is on the snapshot's thread whose TEB is at 0x7ffd0000: set FS_OFFSET to choose another\n"), "{slot}");
}

#[test]
fn functions_run_before_set_up_the_state_the_function_reads() {
    let mut program = Program::new();
    let init = program.addr("init");
    let saved = program.run("saved", json!({ "before": [init] }));
    // What `init` wrote and the stand-ins it ran are setup, not the function's.
    assert_eq!(saved, format!("{} returned EAX = 0x77 (119) after 3 instructions\nran stand-ins for: TlsGetValue x1\n", program.addr("saved")), "{saved}");
}
