//! The static lifter: turns a 32-bit x86 program into Rust that runs on `recore-machine`
//! (crates/machine), written out as a cargo workspace. `recore-mcp lift --config <lift.toml>`
//! runs it ([`workspace::run`]). It serves the lifted games and `player/`, not agents.
//!
//! [`pcode`] reads the decompiler's raw p-code into operations; recore-mcp's emulator takes the
//! same operations, so it lives here, below both.

use anyhow::Result;
use recore::edits::Edits;
use recore::program::Program;
use recore_decomp::Instruction;

mod lift;
pub mod pcode;
pub mod workspace;

/// The binary a lift reads: its analysis and edits, and from its decompiler process each
/// instruction's raw p-code and the registers of its processor. recore-mcp's `Binary` is one;
/// the decompiler process runs as recore-mcp, so the binary stays there.
pub trait Source {
    fn program(&self) -> &Program;
    fn edits(&self) -> &Edits;
    /// `[start, end)` lifted to raw p-code: see [`recore_decomp::Session::lift`].
    fn lift(&mut self, start: u64, end: u64) -> Result<Vec<Instruction>>;
    /// The space, offset and size of a register: see [`recore_decomp::Session::register`].
    fn register(&mut self, name: &str) -> Result<(String, u64, u32)>;
}
