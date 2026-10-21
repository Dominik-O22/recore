//! A 32-bit PE image whose base relocations are stripped, so nothing marks which words are
//! addresses: its switch table and the callbacks it takes the address of are found from the
//! bytes alone, and the numbers it pushes that land outside it are not taken for addresses.

use recore::image::{Format, Image, Machine, Section};
use recore::report::Origin;

#[test]
fn reads_a_switch_table_and_a_taken_address_without_relocations() {
    #[rustfmt::skip]
    let code = [
        0x8b, 0x44, 0x24, 0x04,                    // 0x401000  mov eax, [esp+4]
        0x83, 0xf8, 0x03,                          // 0x401004  cmp eax, 3
        0x77, 0x20,                                // 0x401007  ja 0x401029
        0xff, 0x24, 0x85, 0x2c, 0x10, 0x40, 0x00,  // 0x401009  jmp [eax*4 + 0x40102c]
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,        // 0x401010  mov eax, 1; ret
        0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,        // 0x401016  mov eax, 2; ret
        0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3,        // 0x40101c  mov eax, 3; ret
        0x68, 0x3c, 0x10, 0x40, 0x00, 0x58, 0xc3,  // 0x401022  push 0x40103c; pop eax; ret
        0x31, 0xc0, 0xc3,                          // 0x401029  xor eax, eax; ret
        0x10, 0x10, 0x40, 0x00, 0x16, 0x10, 0x40, 0x00, 0x1c, 0x10, 0x40, 0x00, 0x22, 0x10, 0x40, 0x00,
        0x68, 0x01, 0x00, 0x00, 0x00,              // 0x40103c  push 1
        0x68, 0x00, 0x00, 0x80, 0xbf,              // 0x401041  push 0xbf800000, which is -1.0
        0x83, 0xc4, 0x08,                          // 0x401046  add esp, 8
        0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3,        // 0x401049  mov eax, 7; ret
    ];
    let text = Section { name: ".text".into(), addr: 0x401000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let image = Image { base: 0x400000, relocations_stripped: true, ..Image::bare("stripped".into(), Format::Pe, Machine::X86, 0x401000, vec![text]) };

    let analysis = recore::analyze(&image);

    let tables: Vec<_> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
    assert_eq!(tables, [(0x401009, &[0x401010, 0x401016, 0x40101c, 0x401022][..])]);
    let callback = analysis.functions.iter().find(|function| function.addr == 0x40103c).map(|function| function.origin);
    assert_eq!(callback, Some(Origin::AddressTaken));
    // Numbers the image does not map are no addresses.
    let references: Vec<_> = analysis.data_refs.iter().map(|reference| (reference.from, reference.to)).collect();
    assert_eq!(references, [(0x401009, 0x40102c), (0x401022, 0x40103c)]);
}

/// MSVC maps sparse cases onto a dense jump table through a table of bytes, and puts both after
/// the function. Neither is code, and the function after them, which only a tail call reaches,
/// still begins after a break.
#[test]
fn a_switch_indexed_through_a_byte_table_leaves_both_tables_out_of_the_code() {
    #[rustfmt::skip]
    let code = [
        0x8b, 0x44, 0x24, 0x04,                    // 0x401000  mov eax, [esp+4]
        0x83, 0xf8, 0x05,                          // 0x401004  cmp eax, 5
        0x77, 0x14,                                // 0x401007  ja 0x40101d
        0x0f, 0xb6, 0x80, 0x30, 0x10, 0x40, 0x00,  // 0x401009  movzx eax, byte [eax + 0x401030]
        0xff, 0x24, 0x85, 0x24, 0x10, 0x40, 0x00,  // 0x401010  jmp [eax*4 + 0x401024]
        0xb0, 0x01, 0xc3,                          // 0x401017  mov al, 1; ret
        0xb0, 0x02, 0xc3,                          // 0x40101a  mov al, 2; ret
        0xe8, 0x2e, 0x00, 0x00, 0x00, 0xc3,        // 0x40101d  call 0x401050; ret
        0x90,
        0x17, 0x10, 0x40, 0x00, 0x1a, 0x10, 0x40, 0x00, 0x1d, 0x10, 0x40, 0x00,  // 0x401024
        0x00, 0x01, 0x02, 0x01, 0x00, 0x02,        // 0x401030
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3,        // 0x401040  mov eax, 7; ret
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x31, 0xc0,                                // 0x401050  xor eax, eax
        0xe9, 0xe9, 0xff, 0xff, 0xff,              // 0x401052  jmp 0x401040
    ];
    let text = Section { name: ".text".into(), addr: 0x401000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let image = Image { base: 0x400000, relocations_stripped: true, ..Image::bare("byte table".into(), Format::Pe, Machine::X86, 0x401000, vec![text]) };

    let analysis = recore::analyze(&image);

    let tables: Vec<_> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
    assert_eq!(tables, [(0x401010, &[0x401017, 0x40101a, 0x40101d][..])]);
    let starts: Vec<u64> = analysis.functions.iter().map(|function| function.addr).collect();
    assert_eq!(starts, [0x401000, 0x401040, 0x401050]);
}
