//! A 32-bit PE image without type information, as MSVC builds C++ with `/GR-`: the vtable a
//! constructor stores is found from the store, and calls through it are resolved where the
//! object's vtable can be followed to them.

use recore::image::{Format, Image, Machine, Section};
use recore::program::Program;
use recore::report::{Class, VirtualCall};

const VTABLE: u64 = 0x402000;
const FIRST: u64 = 0x401060;
const SECOND: u64 = 0x401070;

#[test]
fn calls_through_a_stored_vtable_reach_its_slots() {
    #[rustfmt::skip]
    let code = [
        // The entry point.
        0xb9, 0x30, 0x20, 0x40, 0x00,              // 0x401000  mov ecx, 0x402030
        0xc7, 0x01, 0x00, 0x20, 0x40, 0x00,        // 0x401005  mov dword [ecx], 0x402000
        0x8b, 0x01,                                // 0x40100b  mov eax, [ecx]
        0xff, 0x10,                                // 0x40100d  call [eax]
        0xb9, 0x20, 0x20, 0x40, 0x00,              // 0x40100f  mov ecx, 0x402020
        0xe8, 0x27, 0x00, 0x00, 0x00,              // 0x401014  call 0x401040
        0xa3, 0x10, 0x20, 0x40, 0x00,              // 0x401019  mov [0x402010], eax
        0x8b, 0xc8,                                // 0x40101e  mov ecx, eax
        0x8b, 0x10,                                // 0x401020  mov edx, [eax]
        0xff, 0x52, 0x04,                          // 0x401022  call [edx+4]
        0xe8, 0x56, 0x00, 0x00, 0x00,              // 0x401025  call 0x401080
        0x8b, 0x0d, 0x10, 0x20, 0x40, 0x00,        // 0x40102a  mov ecx, [0x402010]
        0xe8, 0x6b, 0x00, 0x00, 0x00,              // 0x401030  call 0x4010a0
        0xc3,                                      // 0x401035  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        // A constructor: it stores the vtable in the object it is given, and returns it.
        0xc7, 0x01, 0x00, 0x20, 0x40, 0x00,        // 0x401040  mov dword [ecx], 0x402000
        0x8b, 0xc1,                                // 0x401046  mov eax, ecx
        0xc3,                                      // 0x401048  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        // The first virtual function, which jumps to the second through its own object.
        0x8b, 0x01,                                // 0x401060  mov eax, [ecx]
        0xff, 0x60, 0x04,                          // 0x401062  jmp [eax+4]
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        // The second.
        0x33, 0xc0,                                // 0x401070  xor eax, eax
        0xc3,                                      // 0x401072  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        // Calls through the object in the global, then through one from the stack.
        0x8b, 0x0d, 0x10, 0x20, 0x40, 0x00,        // 0x401080  mov ecx, [0x402010]
        0x8b, 0x01,                                // 0x401086  mov eax, [ecx]
        0xff, 0x10,                                // 0x401088  call [eax]
        0x8b, 0x74, 0x24, 0x04,                    // 0x40108a  mov esi, [esp+4]
        0x8b, 0x06,                                // 0x40108e  mov eax, [esi]
        0x8b, 0xce,                                // 0x401090  mov ecx, esi
        0xff, 0x10,                                // 0x401092  call [eax]
        0xc3,                                      // 0x401094  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        // No virtual function, called only with the object in `ecx`.
        0x8b, 0x01,                                // 0x4010a0  mov eax, [ecx]
        0xff, 0x50, 0x04,                          // 0x4010a2  call [eax+4]
        0xc3,                                      // 0x4010a5  ret
    ];
    let mut data = vec![0; 0x40];
    data[..8].copy_from_slice(&[0x60, 0x10, 0x40, 0x00, 0x70, 0x10, 0x40, 0x00]);
    let text = Section { name: ".text".into(), addr: 0x401000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let data = Section { name: ".data".into(), addr: VTABLE, data, file_offset: None, executable: false, writable: true };
    let image = Image { base: 0x400000, relocations_stripped: true, ..Image::bare("vtables".into(), Format::Pe, Machine::X86, 0x401000, vec![text, data]) };

    let analysis = recore::analyze(&image);

    let vtable = Class { name: "vtable_402000".into(), vtable: VTABLE, methods: vec![FIRST, SECOND], bases: Vec::new(), objc: false };
    assert_eq!(analysis.classes, [vtable]);
    let call = |at, slot, target, tail| VirtualCall { at, slot, vtables: vec![VTABLE], targets: vec![target], tail };
    assert_eq!(
        analysis.virtual_calls,
        [
            // After the store, in the same function.
            call(0x40100d, 0, FIRST, false),
            // Through what the constructor returns.
            call(0x401022, 1, SECOND, false),
            // Through `this` in a virtual function, which the object's vtable holds.
            call(0x401062, 1, SECOND, true),
            // Through the object every store to the global puts there. The call through the
            // object from the stack after it is not resolved.
            call(0x401088, 0, FIRST, false),
            // Through `this` in a function whose one caller passes the object.
            call(0x4010a2, 1, SECOND, false),
        ]
    );

    let program = Program::new(image, analysis);
    let mut callers: Vec<u64> = program.sites_reaching(SECOND).collect();
    callers.sort_unstable();
    assert_eq!(callers, [0x401022, 0x401062, 0x4010a2]);
}
