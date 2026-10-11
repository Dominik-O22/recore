//! The analysis result as written to disk and consumed by the scorer.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalyzedFunction {
    pub addr: u64,
    /// Body as `[start, end)` ranges.
    pub ranges: Vec<(u64, u64)>,
    #[serde(default)]
    pub noreturn: bool,
    #[serde(default)]
    pub thunk: bool,
    /// How the entry point was found, for diagnosing false starts.
    #[serde(default)]
    pub origin: Origin,
    /// Set when this is not a function of its own but a compiler-split piece of another, such as
    /// a `.cold` section holding its unlikely paths. The value is the owning function's entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_of: Option<u64>,
}

/// The evidence that first identified a function entry point.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    #[default]
    Unknown,
    /// An `.eh_frame` entry.
    Frame,
    /// The entry point or an exported symbol.
    Export,
    /// A code pointer stored in data by a relocation.
    DataPointer,
    Call,
    /// An address computed by `lea`.
    AddressTaken,
    /// A jump that crosses a function boundary.
    TailCall,
    /// Unreferenced code after padding at an aligned address.
    GapAligned,
    /// Unreferenced code opening with `endbr64`.
    GapEndbr,
}

/// Where a call or tail call goes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallTarget {
    /// A function in this binary, by entry address.
    Function(u64),
    /// An imported function, by the address of the slot the loader fills in.
    Import(u64),
}

/// A direct call, a call through an import slot, or a jump that leaves its function.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CallSite {
    /// Address of the call or jump instruction.
    pub at: u64,
    pub target: CallTarget,
    /// The callee never returns, so nothing after this instruction is reached through it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub noreturn: bool,
    /// A jump used as a call: the callee returns to this function's caller.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tail: bool,
}

/// A function provided by another library, reached through a slot the loader fills in.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Import {
    pub slot: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub noreturn: bool,
}

/// An indirect jump resolved to the code addresses it can reach.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JumpTable {
    /// Address of the indirect jump instruction.
    pub jump: u64,
    /// Distinct target addresses, sorted.
    pub targets: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Analysis {
    pub name: String,
    pub functions: Vec<AnalyzedFunction>,
    /// Call instructions the analyzer treats as never returning.
    pub noreturn_calls: Vec<u64>,
    #[serde(default)]
    pub instructions: u64,
    #[serde(default)]
    pub jump_tables: Vec<JumpTable>,
    /// Calls and tail calls with a known target, sorted by address.
    #[serde(default)]
    pub calls: Vec<CallSite>,
    /// Imported functions that the code refers to.
    #[serde(default)]
    pub imports: Vec<Import>,
}
