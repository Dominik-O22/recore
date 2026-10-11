//! The child side: one session, one binary, addresses from stdin, results to stdout.

use std::io::{BufRead, Write};
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use recore_decomp::{Facts, Session};

use crate::WorkerOptions;
use crate::report::{Event, FunctionRecord, Status};

/// Caps the address space, so that a runaway function fails its allocations instead of pushing
/// the machine into swap.
fn limit_memory(gib: u64) {
    let bytes = gib << 30;
    let limit = libc::rlimit { rlim_cur: bytes, rlim_max: bytes };
    // Failing to set the limit only loses the protection.
    unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) };
}

pub fn run(binary: &Path, options: &WorkerOptions) -> Result<()> {
    limit_memory(options.memory_gb);
    let image = recore::Image::load(binary)?;
    let analysis = recore::analyze(&image);
    let mut session = Session::from_image(&image, &analysis)?;
    session.add_functions(&Facts::derive(&image, &analysis))?;
    session.set_style(options.style.into())?;

    let mut out = std::io::stdout().lock();
    let mut send = |event: &Event| -> Result<()> {
        serde_json::to_writer(&mut out, event)?;
        out.write_all(b"\n")?;
        Ok(out.flush()?)
    };
    for line in std::io::stdin().lock().lines() {
        let addr = u64::from_str_radix(&line?, 16)?;
        send(&Event::Start(addr))?;
        let start = Instant::now();
        let result = session.decompile(addr);
        let ms = start.elapsed().as_secs_f64() * 1e3;
        send(&match result {
            Ok(function) => Event::Done {
                record: FunctionRecord {
                    addr,
                    status: Status::Ok,
                    message: None,
                    ms,
                    params: function.param_count(),
                    returns_value: function.returns_value,
                    c_len: function.c_text.len(),
                },
                c_text: options.emit_c.then_some(function.c_text),
            },
            Err(error) => Event::Done { record: FunctionRecord::failed(addr, Status::Error, error.to_string(), ms), c_text: None },
        })?;
    }
    Ok(())
}
