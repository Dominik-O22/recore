//! A function's data flow as the decompiler leaves it after simplification: basic blocks, and
//! p-code operations over values in static single assignment form.
//!
//! Every [`Value`] is defined by at most one [`Op`], so following a value to its uses or back to
//! what it was computed from is a walk over `inputs` and `output`. This is what the decompiler's
//! C is printed from, with stack bookkeeping and dead code already removed.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Address of the first instruction.
    pub start: u64,
    /// Address of the last instruction.
    pub stop: u64,
    /// Indices of the blocks control can pass to.
    pub successors: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Const(u64),
    /// A parameter of the function, by position from zero.
    Param { index: usize, name: String },
    /// Memory at a fixed address.
    Global { addr: u64, name: Option<String> },
    /// A named local variable. Several values share a name when the variable is assigned more
    /// than once.
    Local(String),
    /// An intermediate result, with the register or temporary that holds it.
    Temp(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// Size in bytes.
    pub size: u32,
    pub kind: Kind,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Op {
    /// Address of the instruction the operation comes from.
    pub addr: u64,
    pub block: usize,
    /// The p-code operation, such as `INT_ADD`, `LOAD`, `CALL` or `RETURN`.
    pub code: String,
    pub output: Option<u32>,
    /// The values read. For a call these are the arguments in order, for a store the address
    /// and then the value stored, for a return the value returned if there is one.
    pub inputs: Vec<u32>,
    /// The function a direct call goes to.
    pub callee: Option<Callee>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Callee {
    /// Its entry. An imported function has no code in the image and gets an address outside it.
    pub addr: u64,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Flow {
    pub blocks: Vec<Block>,
    pub values: BTreeMap<u32, Value>,
    /// In address order within each block.
    pub ops: Vec<Op>,
}

impl Flow {
    /// Reads the shim's text form: see `dump_flow` in `shim.cc`.
    pub(crate) fn parse(text: &str) -> Result<Flow> {
        let hex = |field: &str| u64::from_str_radix(field, 16).with_context(|| format!("`{field}` is not a hex number"));
        let list = |field: &str| field.split(',').filter(|item| !item.is_empty()).map(hex).collect::<Result<Vec<u64>>>();
        let mut flow = Flow::default();
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                ["B", _, start, stop, successors] => {
                    flow.blocks.push(Block { start: hex(start)?, stop: hex(stop)?, successors: list(successors)?.into_iter().map(|index| index as usize).collect() });
                }
                ["V", id, size, kind, text] => {
                    let (first, rest) = text.split_once(' ').map_or((*text, None), |(first, rest)| (first, Some(rest.to_string())));
                    let kind = match *kind {
                        "const" => Kind::Const(hex(text)?),
                        "param" => Kind::Param { index: hex(first)? as usize, name: rest.unwrap_or_default() },
                        "global" => Kind::Global { addr: hex(first)?, name: rest },
                        "local" => Kind::Local(text.to_string()),
                        "temp" => Kind::Temp(text.to_string()),
                        other => bail!("unknown value kind `{other}`"),
                    };
                    flow.values.insert(hex(id)? as u32, Value { size: hex(size)? as u32, kind });
                }
                ["O", addr, block, code, output, inputs, callee] => flow.ops.push(Op {
                    addr: hex(addr)?,
                    block: hex(block)? as usize,
                    code: code.to_string(),
                    output: if *output == "-" { None } else { Some(hex(output)? as u32) },
                    inputs: list(inputs)?.into_iter().map(|id| id as u32).collect(),
                    callee: match callee.split_once(' ') {
                        Some((addr, name)) => Some(Callee { addr: hex(addr)?, name: name.to_string() }),
                        None => None,
                    },
                }),
                _ => bail!("unreadable flow line `{line}`"),
            }
        }
        Ok(flow)
    }

    /// A value as the listing names it: a constant's value, a variable's name, or `t` and its
    /// number for an intermediate result.
    pub fn name(&self, id: u32) -> String {
        match self.values.get(&id).map(|value| &value.kind) {
            Some(Kind::Const(value)) => format!("{value:#x}"),
            Some(Kind::Param { name, .. }) | Some(Kind::Local(name)) => name.clone(),
            Some(Kind::Global { name: Some(name), .. }) => name.clone(),
            Some(Kind::Global { addr, name: None }) => format!("*{addr:#x}"),
            Some(Kind::Temp(_)) | None => format!("t{id}"),
        }
    }

    /// The operation that defines a value, if one in this function does.
    pub fn definition(&self, id: u32) -> Option<&Op> {
        self.ops.iter().find(|op| op.output == Some(id))
    }

    /// The operations that read a value.
    pub fn uses(&self, id: u32) -> impl Iterator<Item = &Op> {
        self.ops.iter().filter(move |op| op.inputs.contains(&id))
    }
}
