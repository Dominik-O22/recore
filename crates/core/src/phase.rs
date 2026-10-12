//! Wall time per phase of the analysis, for `recore-bench phases`. Off unless enabled, and then
//! one clock read at each end of a phase: the phases are coarse, a few dozen per binary.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static ENABLED: AtomicBool = AtomicBool::new(false);
static TOTALS: Mutex<Vec<(&'static str, Duration)>> = Mutex::new(Vec::new());

/// Adds the time until it is dropped to the phase it was started for.
pub struct Scope(Option<(&'static str, Instant)>);

/// Starts timing `name`. Phases started on the analyzing thread nest; give an inner one its
/// outer one's name as a prefix, `discover/drain`, and the report shows it underneath.
pub fn scope(name: &'static str) -> Scope {
    Scope(ENABLED.load(Ordering::Relaxed).then(|| (name, Instant::now())))
}

impl Drop for Scope {
    fn drop(&mut self) {
        let Some((name, start)) = self.0 else { return };
        let elapsed = start.elapsed();
        let mut totals = TOTALS.lock().unwrap();
        match totals.iter_mut().find(|total| total.0 == name) {
            Some(total) => total.1 += elapsed,
            None => totals.push((name, elapsed)),
        }
    }
}

pub fn enable(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// The time per phase since the last call, in the order the phases first ran.
pub fn take() -> Vec<(&'static str, Duration)> {
    std::mem::take(&mut TOTALS.lock().unwrap())
}
