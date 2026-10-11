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
pub mod report;
pub mod strings;
pub mod x86;

pub use analysis::analyze;
pub use image::Image;
