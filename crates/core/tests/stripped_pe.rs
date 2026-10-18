//! A 32-bit PE image whose base relocations are stripped, so nothing marks which words are
//! addresses: its switch table and the callbacks it takes the address of are found from the
//! bytes alone.

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
        0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3,        // 0x40103c  mov eax, 7; ret
    ];
    let text = Section { name: ".text".into(), addr: 0x401000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let image = Image { base: 0x400000, relocations_stripped: true, ..Image::bare("stripped".into(), Format::Pe, Machine::X86, 0x401000, vec![text]) };

    let analysis = recore::analyze(&image);

    let tables: Vec<_> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
    assert_eq!(tables, [(0x401009, &[0x401010, 0x401016, 0x40101c, 0x401022][..])]);
    let callback = analysis.functions.iter().find(|function| function.addr == 0x40103c).map(|function| function.origin);
    assert_eq!(callback, Some(Origin::AddressTaken));
}
