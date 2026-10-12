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
    /// The function's name when the image carries one, demangled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    /// Code inside another function's extent that nothing in that function reaches.
    Unreachable,
    /// The target of a function that is nothing but a jump, such as an incremental-linking
    /// thunk or an import stub.
    Thunk,
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
    /// The tail call is a conditional jump, so execution may also carry on past it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conditional: bool,
}

/// A function provided by another library, reached through a slot the loader fills in.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Import {
    pub slot: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub noreturn: bool,
}

/// A text string found in the image's data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StringLiteral {
    pub addr: u64,
    pub text: String,
    /// Stored as UTF-16, as Windows APIs with a `W` suffix take.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wide: bool,
}

/// An instruction that refers to data at a fixed address.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct DataRef {
    /// Address of the instruction.
    pub from: u64,
    /// The data address it refers to.
    pub to: u64,
    /// The instruction reads or writes the data. Otherwise it only takes its address.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub access: bool,
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
    /// Data addresses that code takes, sorted by instruction.
    #[serde(default)]
    pub data_refs: Vec<DataRef>,
    /// Strings at addresses the code or relocated pointers refer to, sorted by address.
    #[serde(default)]
    pub strings: Vec<StringLiteral>,
    /// C++ classes that have a vtable and run-time type information, sorted by vtable address.
    #[serde(default)]
    pub classes: Vec<Class>,
}

/// A C++ class as its vtable and type information describe it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Class {
    pub name: String,
    pub vtable: u64,
    /// Entry points of the virtual functions, in vtable order.
    pub methods: Vec<u64>,
    /// Classes it derives from, directly or not.
    pub bases: Vec<String>,
}
