//! Ground truth about function signatures, read from a separate debug file.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};

/// What the debug info says about one function.
#[derive(Debug, Clone)]
pub struct Function {
    /// Source-level parameters: `DW_TAG_formal_parameter` children of the `DW_TAG_subprogram`.
    pub params: usize,
    pub variadic: bool,
}

/// The parts of a debug file that signature comparisons need.
#[derive(Debug, Default)]
pub struct DebugInfo {
    /// Every `DW_TAG_subprogram` that has a `DW_AT_low_pc`, by that address.
    pub functions: BTreeMap<u64, Function>,
    /// Names of all code symbols, including pieces like `foo.cold` that have no subprogram entry.
    pub symbols: BTreeMap<u64, String>,
}

impl DebugInfo {
    pub fn load(path: &Path) -> Result<DebugInfo> {
        use gimli::{EndianArcSlice, LittleEndian};
        let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
        let debug = object::File::parse(&*data)?;
        let symbols = debug
            .symbols()
            .filter(|s| s.kind() == object::SymbolKind::Text)
            .filter_map(|s| Some((s.address(), s.name().ok()?.to_string())))
            .collect();
        let dwarf = gimli::Dwarf::load(|id| -> Result<_> {
            let data = match debug.section_by_name(id.name()) {
                Some(section) => section.uncompressed_data()?.into_owned(),
                None => Vec::new(),
            };
            Ok(EndianArcSlice::new(data.into(), LittleEndian))
        })?;

        let mut functions = BTreeMap::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            // Subprograms enclosing the current entry, as (depth, address); the address is `None`
            // for declarations and abstract instances, whose parameters do not count.
            let mut open: Vec<(isize, Option<u64>)> = Vec::new();
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                while open.last().is_some_and(|&(depth, _)| entry.depth() <= depth) {
                    open.pop();
                }
                match entry.tag() {
                    gimli::DW_TAG_subprogram => {
                        let addr = match entry.attr_value(gimli::DW_AT_low_pc) {
                            Some(gimli::AttributeValue::Addr(addr)) => Some(addr),
                            Some(gimli::AttributeValue::DebugAddrIndex(index)) => dwarf.address(&unit, index).ok(),
                            _ => None,
                        }
                        .filter(|&addr| addr != 0);
                        if let Some(addr) = addr {
                            functions.insert(addr, Function { params: 0, variadic: false });
                        }
                        open.push((entry.depth(), addr));
                    }
                    // Only direct children: deeper ones belong to inlined callees.
                    tag @ (gimli::DW_TAG_formal_parameter | gimli::DW_TAG_unspecified_parameters) => {
                        if let Some(&(_, Some(addr))) = open.last().filter(|&&(depth, _)| entry.depth() == depth + 1) {
                            let function = functions.get_mut(&addr).expect("inserted when opened");
                            if tag == gimli::DW_TAG_formal_parameter {
                                function.params += 1;
                            } else {
                                function.variadic = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(DebugInfo { functions, symbols })
    }
}
