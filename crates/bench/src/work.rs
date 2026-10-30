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

/// A counter of the instructions this thread, the threads it starts and the processes it starts
/// execute in user mode. What a process does in the kernel is left out: between two runs of the
/// same work that moved by more than the work's whole size.
pub struct Counter(OwnedFd);

impl Counter {
    /// A stopped counter. `None` where the kernel does not allow one.
    pub fn new() -> Option<Counter> {
        let attr = Attr { kind: HARDWARE, size: size_of::<Attr>() as u32, config: INSTRUCTIONS, sample_period: 0, sample_type: 0, read_format: 0, flags: FLAGS, rest: [0; 10] };
        let fd = unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, 0, -1, -1, 0) };
        (fd >= 0).then(|| Counter(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
    }

    pub fn start(&self) {
        unsafe { libc::ioctl(self.0.as_raw_fd(), ENABLE, 0) };
    }

    /// The instructions counted so far, those of a process that is still running included.
    pub fn read(&self) -> Option<u64> {
        let mut count = 0u64;
        let read = unsafe { libc::read(self.0.as_raw_fd(), (&raw mut count).cast(), 8) };
        (read == 8).then_some(count)
    }
}

/// Runs `work` on one thread of its own and returns what it returns with the number of
/// instructions it executed. Work that uses rayon runs on a pool of one thread, so that the
/// count does not depend on how the work was split.
pub fn instructions<T: Send>(work: impl FnOnce() -> T + Send) -> (T, Option<u64>) {
    std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            let counter = Counter::new();
            // Built after the counter, so that the counter covers its thread.
            let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().expect("a pool of one thread");
            if let Some(counter) = &counter {
                counter.start();
            }
            let result = pool.install(work);
            (result, counter.and_then(|counter| counter.read()))
        });
        run.join().expect("the work does not panic")
    })
}
