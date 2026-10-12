//! Counting the processor instructions a piece of work executes.
//!
//! Wall time moves with whatever else the machine is doing; the number of instructions executed
//! on one thread does not, to within a small fraction of a percent. It is the measure to hold a
//! change against when other work is running, and the one to keep a budget in.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The start of the kernel's `perf_event_attr`; the rest stays zero.
#[repr(C)]
struct Attr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    rest: [u64; 10],
}

const HARDWARE: u32 = 0;
const INSTRUCTIONS: u64 = 1;
/// Start stopped, count threads started later too, and leave out the kernel and hypervisor.
const FLAGS: u64 = 1 | 1 << 1 | 1 << 5 | 1 << 6;
const ENABLE: libc::c_ulong = 0x2400;
const DISABLE: libc::c_ulong = 0x2401;

/// A counter of the instructions this thread and the threads it starts execute in user mode.
/// `None` where the kernel does not allow one.
fn counter() -> Option<OwnedFd> {
    let attr = Attr { kind: HARDWARE, size: size_of::<Attr>() as u32, config: INSTRUCTIONS, sample_period: 0, sample_type: 0, read_format: 0, flags: FLAGS, rest: [0; 10] };
    let fd = unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, 0, -1, -1, 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Runs `work` on one thread of its own and returns what it returns with the number of
/// instructions it executed. Work that uses rayon runs on a pool of one thread, so that the
/// count does not depend on how the work was split.
pub fn instructions<T: Send>(work: impl FnOnce() -> T + Send) -> (T, Option<u64>) {
    std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            let counter = counter();
            // Built after the counter, so that the counter covers its thread.
            let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().expect("a pool of one thread");
            if let Some(counter) = &counter {
                unsafe { libc::ioctl(counter.as_raw_fd(), ENABLE, 0) };
            }
            let result = pool.install(work);
            let count = counter.and_then(|counter| {
                let mut count = 0u64;
                unsafe { libc::ioctl(counter.as_raw_fd(), DISABLE, 0) };
                let read = unsafe { libc::read(counter.as_raw_fd(), (&raw mut count).cast(), 8) };
                (read == 8).then_some(count)
            });
            (result, count)
        });
        run.join().expect("the work does not panic")
    })
}
