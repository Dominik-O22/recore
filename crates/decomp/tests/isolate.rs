//! Workers as the parent sees them: results, a function that takes too long, a child that dies.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use recore_decomp::isolate::{Options, Status, Worker};

/// The runner itself is the binary to decompile, so the tests need no corpus.
const RUNNER: &str = env!("CARGO_BIN_EXE_recore-decompile");

fn entry() -> u64 {
    recore::Image::load(Path::new(RUNNER)).unwrap().entry
}

#[test]
fn returns_c_and_reports_a_timeout() {
    // The first child is ready and then never answers, so the limit is all that ends the wait.
    // Every child after it is a real one.
    let started = AtomicBool::new(false);
    let command = move || {
        if started.swap(true, Ordering::Relaxed) {
            let mut command = Command::new(RUNNER);
            command.arg("worker");
            return command;
        }
        let mut command = Command::new("sh");
        command.args(["-c", r#"echo '"Ready"'; read line; exec sleep 600"#]);
        command
    };
    let options = Options { callees_first: false, ..Options::default() };
    let mut worker = Worker::new(command, Path::new(RUNNER), &options);
    let (record, _) = worker.decompile(entry(), Duration::from_millis(200));
    assert_eq!(record.status, Status::Timeout);

    // The child that ran out of time is replaced.
    let (record, c_text) = worker.decompile(entry(), Duration::from_secs(60));
    assert_eq!(record.status, Status::Ok, "{:?}", record.message);
    assert!(c_text.unwrap().contains('{'));
}

#[test]
fn a_dying_child_is_reported_as_a_crash() {
    // Stands in for the engine faulting: ready, then killed by a signal at the first request.
    let command = || {
        let mut command = Command::new("sh");
        command.args(["-c", r#"echo '"Ready"'; read line; kill -SEGV $$"#]);
        command
    };
    let (record, _) = Worker::new(command, Path::new(RUNNER), &Options::default()).decompile(0x1000, Duration::from_secs(60));
    assert_eq!(record.status, Status::Crash);
    assert!(record.message.unwrap().contains("signal 11"));
}

/// A child whose parent is killed exits, though its stdin stays open as it does while the
/// child is busy with a function and not reading it.
#[test]
fn a_child_exits_when_its_parent_dies() {
    let options = serde_json::to_string(&Options::default()).unwrap();
    // `sh` is the parent. It hands the worker this test's stdin pipe, which the test holds open,
    // and the worker's "Ready" comes out on this test's stdout pipe once the worker is serving.
    let script = r#"exec 3<&0; "$0" worker "$0" "$1" <&3 2>/dev/null & echo $! >&2; wait"#;
    let mut parent = Command::new("sh")
        .args(["-c", script, RUNNER, &options])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // `wait` would close it.
    let _stdin = parent.stdin.take();
    let mut pid = String::new();
    BufReader::new(parent.stderr.take().unwrap()).read_line(&mut pid).unwrap();
    let child: libc::pid_t = pid.trim().parse().unwrap();
    let mut ready = String::new();
    let mut stdout = BufReader::new(parent.stdout.take().unwrap());
    stdout.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), r#""Ready""#);

    parent.kill().unwrap();
    parent.wait().unwrap();
    let alive = || unsafe { libc::kill(child, 0) } == 0;
    let deadline = Instant::now() + Duration::from_secs(1);
    while alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let leaked = alive();
    if leaked {
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    assert!(!leaked, "worker {child} outlived its parent by a second");
}

/// A child set up for the struct fixture, keeping its edits in a directory of its own.
fn structs_worker() -> Worker {
    let edits = std::env::temp_dir().join(format!("recore-isolate-structs-{}", std::process::id()));
    let command = move || {
        let mut command = Command::new(RUNNER);
        command.arg("worker").env(recore::edits::DIR_VAR, &edits);
        command
    };
    Worker::new(command, &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/structs.elf"), &Options::default())
}

/// Naming a recovered struct and its fields reaches the running child; a struct that grows
/// needs a new one, since the engine cannot redefine a type.
#[test]
fn named_structs_and_fields_reach_the_running_child() {
    let mut worker = structs_worker();
    let timeout = Duration::from_secs(60);
    let mut edits = recore::edits::Edits::default();
    edits.adopt(&worker.recovered("S_401000_RDI", timeout).unwrap());
    edits.name_struct("S_401000_RDI", "Connection").unwrap();
    assert!(worker.update(&edits, timeout));
    edits.name_field("Connection", "field_0x8", "session").unwrap();
    assert!(worker.update(&edits, timeout));
    let (_, c_text) = worker.decompile(0x401000, timeout);
    assert!(c_text.as_deref().unwrap().contains("param_1->session->field_0x4 = param_2;"), "{c_text:?}");

    let grown = recore::structs::Layout::new(0x40, edits.structs["Connection"].fields().clone()).unwrap();
    edits.structs.insert("Connection".into(), grown);
    assert!(!worker.update(&edits, timeout));
}
