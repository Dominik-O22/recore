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
    /// The entry of the function that begins where this one's body ends, when the last
    /// instruction of the body passes control on to it: that function returns for both, and no
    /// jump or call says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs_on: Option<u64>,
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
    /// Call instructions the analyzer treats as never returning, sorted.
    pub noreturn_calls: Vec<u64>,
    #[serde(default)]
    pub instructions: u64,
    /// Sorted by the address of the jump.
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
    /// C++ classes: those with a vtable and run-time type information, sorted by vtable
    /// address, then the vtables of the rest, which a constructor stores in an object, sorted by
    /// address; then Objective-C classes and categories in the order the image lists them.
    #[serde(default)]
    pub classes: Vec<Class>,
    /// Objective-C message sends whose selector is known, sorted by address. Each is also one
    /// of `calls`, to the runtime's dispatcher.
    #[serde(default)]
    pub sends: Vec<MessageSend>,
    /// Calls through a slot of an object's vtable where the vtables the object may have are
    /// known, sorted by address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub virtual_calls: Vec<VirtualCall>,
    /// Swift classes, structs and enums, in the order the image lists them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<SwiftType>,
}

/// A Swift class, struct or enum as the image's metadata describes it. A class is also among
/// the Objective-C classes when the image is built for Apple's runtime.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwiftType {
    /// Qualified by module and enclosing types: `Shapes.Shape.Corner`.
    pub name: String,
    /// `class`, `struct` or `enum`.
    pub kind: String,
    /// Address of the type's descriptor.
    pub descriptor: u64,
    /// The superclass of a class.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<String>,
    /// Stored properties in declaration order, or the cases of an enum.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    /// Entry points of a class's methods: those it adds to the vtable, in vtable order, with
    /// zero for one it leaves abstract, and then those that override a superclass's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<u64>,
    /// The protocols it conforms to by a conformance in this image.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conformances: Vec<String>,
}

/// A stored property of a Swift type, or a case of an enum.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Field {
    pub name: String,
    /// The type as Swift writes it. `None` for an enum case without a payload, and for a type
    /// the metadata spells in a way that is not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
}

/// A class as the image describes it: a C++ class by its vtable and type information, or by
/// the vtable its constructor stores where it has none, or an Objective-C class or category by
/// its metadata.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Class {
    /// An Objective-C category is named `Class(Category)`, and a class known only by its vtable
    /// after the vtable's address, `vtable_402000`.
    pub name: String,
    /// Address of the vtable, or of the class object or category record in Objective-C.
    pub vtable: u64,
    /// Entry points of the virtual functions, in vtable order. A slot bound to a function of
    /// another image holds the slot's own address, and a null slot zero. In Objective-C, the
    /// instance methods and then the class methods, each in the order of its method list.
    pub methods: Vec<u64>,
    /// Classes it derives from, directly or not, nearest first.
    pub bases: Vec<String>,
    /// Described by Objective-C metadata, where methods are found by selector and not by slot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub objc: bool,
}

/// A call through a slot of the vtable of an object whose vtable is known to be one of a few,
/// by following the object from a constructor's store, or from the entry of a method, where it
/// is `this` and its vtable one of those that hold the method.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VirtualCall {
    /// Address of the call or jump instruction.
    pub at: u64,
    /// The slot, counted from zero: the call goes to entry `slot` of a class's `methods`.
    pub slot: u64,
    /// The vtables the object may have that are long enough to have the slot, sorted.
    pub vtables: Vec<u64>,
    /// The functions those vtables hold in the slot, distinct and sorted.
    pub targets: Vec<u64>,
    /// A jump used as a call.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tail: bool,
}

/// A call to the Objective-C runtime's dispatcher, which picks the method by the receiver's
/// class and the selector.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageSend {
    /// Address of the call or jump instruction.
    pub at: u64,
    pub selector: String,
    /// The class the message is sent to, or the class of the object it is sent to, when the
    /// code says which: the receiver is loaded from a class reference or comes from a call
    /// that returns that class or allocates an object of it, or is `self` in a method of the
    /// class. Unknown for any other object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    /// The receiver is an object of the class, or of a subclass, and not the class itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub instance: bool,
    /// The method the image implements for the message: the method of that name of the
    /// receiver's class or the nearest superclass in this image when the receiver is known,
    /// and otherwise the selector's implementation when the image has exactly one and the
    /// send is not to a superclass. None for a receiver that may be of a subclass, as `self`
    /// may, when a subclass in this image has a method of that name too. In the second case
    /// the receiver may still be an object of another library's class that has a method of
    /// the same name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<u64>,
}

impl MessageSend {
    /// The send as a method name: `+[NSString alloc]` to a known class, `-[NSString init]`
    /// to an object of one, and `-[? setSide:]` with the class left open otherwise.
    pub fn label(&self) -> String {
        match &self.receiver {
            Some(class) => format!("{}[{class} {}]", if self.instance { '-' } else { '+' }, self.selector),
            None => format!("-[? {}]", self.selector),
        }
    }
}
