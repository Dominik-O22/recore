//! Workers as the parent sees them: results, a function that takes too long, a child that dies.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use recore_decomp::isolate::{Options, Status, Worker};

/// The runner itself is the binary to decompile, so the tests need no corpus.
const RUNNER: &str = env!("CARGO_BIN_EXE_recore-decompile");

fn worker() -> Worker {
    let mut command = Command::new(RUNNER);
    command.arg("worker");
    Worker::start(command, Path::new(RUNNER), &Options::default()).unwrap()
}

fn entry() -> u64 {
    recore::Image::load(Path::new(RUNNER)).unwrap().entry
}

#[test]
fn returns_c_and_reports_a_timeout() {
    let (record, c_text) = worker().decompile(entry(), Duration::from_secs(60)).unwrap();
    assert_eq!(record.status, Status::Ok, "{:?}", record.message);
    assert!(c_text.unwrap().contains('{'));

    // No function finishes in no time at all. Setup does not count towards the limit.
    let record = worker().decompile(entry(), Duration::ZERO).unwrap_err();
    assert_eq!(record.status, Status::Timeout);
}

#[test]
fn a_dying_child_is_reported_as_a_crash() {
    // Stands in for the engine faulting: ready, then killed by a signal at the first request.
    let mut command = Command::new("sh");
    command.args(["-c", r#"echo '"Ready"'; read line; kill -SEGV $$"#]);
    let mut worker = Worker::spawn(command, Path::new(RUNNER), &Options::default()).unwrap();
    assert!(worker.is_alive());
    let record = worker.decompile(0x1000, Duration::from_secs(60)).unwrap_err();
    assert_eq!(record.status, Status::Crash);
    assert!(record.message.unwrap().contains("signal 11"));
    assert!(!worker.is_alive());
}
