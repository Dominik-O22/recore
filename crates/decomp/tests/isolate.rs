//! Workers as the parent sees them: results, a function that takes too long, a child that dies.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use recore_decomp::isolate::{Options, Status, Worker};

/// The runner itself is the binary to decompile, so the tests need no corpus.
const RUNNER: &str = env!("CARGO_BIN_EXE_recore-decompile");

fn worker() -> Worker {
    let command = || {
        let mut command = Command::new(RUNNER);
        command.arg("worker");
        command
    };
    Worker::new(command, Path::new(RUNNER), &Options::default())
}

fn entry() -> u64 {
    recore::Image::load(Path::new(RUNNER)).unwrap().entry
}

#[test]
fn returns_c_and_reports_a_timeout() {
    let mut worker = worker();
    // No function finishes in no time at all. Setup does not count towards the limit.
    let (record, _) = worker.decompile(entry(), Duration::ZERO);
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
