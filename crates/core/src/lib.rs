//! recore: a fast binary analysis core.
//!
//! `Image` loads an executable, `analyze` recovers its functions and control-flow facts, and
//! `report` defines the JSON shape that every analyzer's output is reduced to for scoring.

pub mod analysis;
pub mod arch;
pub mod arm;
pub mod arm64;
pub mod cache;
pub mod cfg;
pub mod diff;
pub mod discover;
pub mod edits;
pub mod hardware;
pub mod i8051;
pub mod il2cpp;
pub mod image;
pub mod itanium;
pub mod jumptable;
pub mod layout;
pub mod library;
pub mod macho;
pub mod names;
pub mod noreturn;
pub mod objc;
pub mod pe;
pub mod phase;
pub mod program;
pub mod report;
pub mod rtti;
pub mod score;
pub mod sectionless;
pub mod signature;
pub mod strings;
pub mod structs;
pub mod sweep;
pub mod swift;
pub mod thumb;
pub mod x86;

pub use analysis::analyze;
pub use image::Image;
/// The hash tables in recore's results. Their keys are addresses, which need no protection
/// against chosen collisions and are hashed many millions of times per binary.
pub use rustc_hash::{FxHashMap, FxHashSet};
