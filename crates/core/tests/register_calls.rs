//! 32-bit MSVC code that calls one import several times loads it from its slot into a register
//! once and calls the register. A register a call preserves still holds the import after
//! another call; one a call may overwrite does not.

use recore::image::{Format, Image, Machine, Section};
use recore::report::CallTarget;

#[test]
fn a_call_through_a_register_loaded_from_an_import_slot_calls_the_import() {
    #[rustfmt::skip]
    let code = [
        0x56,                                // 0x401000  push esi
        0x8b, 0x35, 0x00, 0x20, 0x40, 0x00,  // 0x401001  mov esi, [0x402000]
        0x6a, 0x00,                          // 0x401007  push 0
        0xff, 0xd6,                          // 0x401009  call esi
        0xe8, 0x0f, 0x00, 0x00, 0x00,        // 0x40100b  call 0x40101f
        0x6a, 0x01,                          // 0x401010  push 1
        0xff, 0xd6,                          // 0x401012  call esi
        0xa1, 0x04, 0x20, 0x40, 0x00,        // 0x401014  mov eax, [0x402004]
        0xff, 0xd0,                          // 0x401019  call eax
        0xff, 0xd0,                          // 0x40101b  call eax, which the call before may have changed
        0x5e,                                // 0x40101d  pop esi
        0xc3,                                // 0x40101e  ret
        0x31, 0xc0, 0xc3,                    // 0x40101f  xor eax, eax; ret
    ];
    let text = Section { name: ".text".into(), addr: 0x401000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let idata = Section { name: ".idata".into(), addr: 0x402000, data: vec![0; 8], file_offset: None, executable: false, writable: false };
    let mut image = Image { base: 0x400000, ..Image::bare("calls".into(), Format::Pe, Machine::X86, 0x401000, vec![text, idata]) };
    image.import_slots.insert(0x402000, "LockWindowUpdate".into());
    image.import_slots.insert(0x402004, "GetTickCount".into());

    let analysis = recore::analyze(&image);

    let calls: Vec<_> = analysis.calls.iter().map(|call| (call.at, call.target)).collect();
    assert_eq!(
        calls,
        [
            (0x401009, CallTarget::Import(0x402000)),
            (0x40100b, CallTarget::Function(0x40101f)),
            (0x401012, CallTarget::Import(0x402000)),
            (0x401019, CallTarget::Import(0x402004)),
        ]
    );
}
