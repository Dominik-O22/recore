//! recore: a fast binary analysis core.
//!
//! `Image` loads an executable, `analyze` recovers its functions and control-flow facts, and
//! `report` defines the JSON shape that every analyzer's output is reduced to for scoring.

pub mod analysis;
pub mod arch;
pub mod arm64;
pub mod discover;
pub mod image;
pub mod jumptable;
pub mod names;
pub mod noreturn;
pub mod pe;
pub mod phase;
pub mod program;
pub mod report;
pub mod rtti;
pub mod signature;
pub mod strings;
pub mod x86;

pub use analysis::analyze;
pub use image::Image;
/// The hash tables in recore's results. Their keys are addresses, which need no protection
/// against chosen collisions and are hashed many millions of times per binary.
pub use rustc_hash::{FxHashMap, FxHashSet};
