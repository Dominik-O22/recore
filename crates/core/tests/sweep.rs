//! A sweep of a small banked image: two banks stored in the wrong order after the common code.

use std::path::Path;

/// SDCC's stub, which switches banks on the way to a function.
const STUB: [u8; 18] = [0xC0, 0xB1, 0xC8, 0xC0, 0xE0, 0xE9, 0xC0, 0xE0, 0xEA, 0x54, 0x0F, 0x53, 0xB1, 0xF0, 0x42, 0xB1, 0xC8, 0x22];

#[test]
fn a_sweep_finds_the_banks_the_common_code_and_the_trampolines() {
    // The common code calls three functions in bank 1 and two in bank 2 through the stub at
    // 0x40: MOV R0, #low; MOV R1, #high; MOV R2, #bank; LCALL 0x0040.
    let call = |bank: u8, target: u16| [0x78, target as u8, 0x79, (target >> 8) as u8, 0x7A, bank, 0x12, 0x00, 0x40];
    let mut common: Vec<u8> = [(1, 0x8002), (1, 0x8005), (1, 0x8009), (2, 0x8004), (2, 0x800B)].into_iter().flat_map(|(bank, target)| call(bank, target)).collect();
    common.push(0x22);
    common.resize(0x40, 0);
    common.extend(STUB);
    // Functions at 0x8000, 0x8002, 0x8005 and 0x8009.
    let bank_1 = [0xE4, 0x22, 0x74, 0x01, 0x22, 0x12, 0x80, 0x00, 0x22, 0x74, 0x07, 0xF5, 0x30, 0x22];
    // Functions at 0x8000, 0x8004 and 0x800B.
    let bank_2 = [0x75, 0x30, 0x02, 0x22, 0x75, 0x31, 0x03, 0x75, 0x32, 0x04, 0x22, 0xE4, 0x22];

    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sweep");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("image.bin"), [&common[..], &bank_2, &bank_1].concat()).unwrap();
    let region = |offset: usize, length: usize, place: &str| format!("[[region]]\nfile = \"image.bin\"\noffset = {offset}\nlength = {length}\n{place}\nexecutable = true\n");
    let open = [
        "machine = \"8051\"\nentry = [0]\n".to_string(),
        region(0, common.len(), "address = 0"),
        region(common.len(), bank_2.len(), "bank = \"?\"\naddress = 0x8000"),
        region(common.len() + bank_2.len(), bank_1.len(), "bank = \"?\"\naddress = 0x8000"),
    ];
    std::fs::write(dir.join("open.toml"), open.join("\n")).unwrap();
    assert!(recore::Image::load(&dir.join("open.toml")).is_err(), "a layout with banks open is not an image yet");

    let sweep = recore::sweep::sweep(&dir.join("open.toml")).unwrap();
    assert_eq!(sweep.common, [(0, 0x8000)]);
    let best = &sweep.candidates[0];
    assert_eq!(best.scheme, "SDCC __sdcc_banked_call");
    assert_eq!(best.placements.iter().map(|placement| placement.bank).collect::<Vec<_>>(), [Some(2), Some(1)]);

    let found = dir.join("found.toml");
    std::fs::write(&found, sweep.layout(&found).unwrap().unwrap()).unwrap();
    let image = recore::Image::load(&found).unwrap();
    assert_eq!(image.bytes_from(0x1_8000).unwrap(), bank_1);
    assert_eq!(image.bytes_from(0x2_8000).unwrap(), bank_2);
    let mut reached: Vec<u64> = image.banking.calls.values().copied().collect();
    reached.sort_unstable();
    assert_eq!(reached, [0x1_8002, 0x1_8005, 0x1_8009, 0x2_8004, 0x2_800B]);
}
