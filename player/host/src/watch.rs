//! TT_WATCH=<field>,...: game memory read at every frame and printed when it changes, as
//! `watch frame 2063 [0x65b914]+0x14 = 04`. A field is `address:length`, or
//! `[pointer]+offset:length` for a field of the struct a global points to; numbers are hex with
//! or without 0x.

use recore_machine::Cpu;

struct Field {
    text: String,
    /// The address, or the address of the pointer to the struct.
    at: u32,
    /// For `[pointer]+offset`, the offset into the struct.
    offset: Option<u32>,
    len: usize,
    last: Option<Vec<u8>>,
}

pub struct Watch(Vec<Field>);

fn hex(text: &str) -> Option<u32> {
    u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

impl Watch {
    pub fn from_env() -> Watch {
        let spec = std::env::var("TT_WATCH").unwrap_or_default();
        let fields = spec.split(',').filter(|s| !s.trim().is_empty()).map(|item| {
            let (place, len) = item.rsplit_once(':').unwrap_or((item, "4"));
            let len = len.parse().unwrap_or_else(|_| panic!("TT_WATCH {item:?}: the length is a decimal number"));
            let (at, offset) = match place.trim().strip_prefix('[').and_then(|rest| rest.split_once(']')) {
                Some((pointer, offset)) => (hex(pointer), Some(hex(offset.trim_start_matches('+')).unwrap_or(0))),
                None => (hex(place), None),
            };
            let at = at.unwrap_or_else(|| panic!("TT_WATCH {item:?}: not an address"));
            Field { text: place.trim().to_string(), at, offset, len, last: None }
        });
        Watch(fields.collect())
    }

    /// Prints each field that changed since the last frame.
    pub fn frame(&mut self, c: &mut Cpu, frame: u64) {
        for f in &mut self.0 {
            let at = match f.offset {
                Some(offset) => c.u32_at(f.at).wrapping_add(offset),
                None => f.at,
            };
            let bytes = c.mem.bytes(at, f.len);
            if f.last.as_ref() != Some(&bytes) {
                eprintln!("watch frame {frame} {} = {}", f.text, bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
                f.last = Some(bytes);
            }
        }
    }
}
