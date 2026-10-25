//! Railroad Tycoon 3 (MSVC 7, 2003), unpacked: its C runtime's `cos`, `sin` and `sqrt` come
//! back from a call into the routine after them. `RECORE_RT3` names the binary, which stays
//! out of the repository.

use recore::report::CallTarget;
use recore_decomp::{Facts, Session};

/// The math helpers return, so the code after their calls is reached: the call to
/// `rand_range` in `ai_pick_engine` after `sqrt`, and `city_grow` after `sin`.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn the_c_runtimes_math_helpers_return() {
    let image = recore::Image::load(std::env::var("RECORE_RT3").expect("RECORE_RT3 names the binary").as_ref()).unwrap();
    let analysis = recore::analyze(&image);

    // cos, sin, sqrt, and app_run, which calls cos.
    let noreturn: Vec<u64> = [0x5a1494, 0x5a13e4, 0x5a1634, 0x4840e0].into_iter().filter(|&addr| analysis.functions.iter().any(|f| f.addr == addr && f.noreturn)).collect();
    assert_eq!(noreturn, [0u64; 0]);
    let caller = analysis.functions.iter().find(|f| f.ranges.iter().any(|&(start, end)| (start..end).contains(&0x407af5))).map(|f| f.addr);
    assert_eq!(caller, Some(0x4078a0));
    assert!(analysis.calls.iter().any(|call| call.at == 0x407af5 && call.target == CallTarget::Function(0x518be0)));

    let mut session = Session::from_image(&image, &analysis).unwrap();
    session.add_functions(&Facts::derive(&image, &analysis)).unwrap();
    let city_grow = session.decompile(0x422ee0).unwrap();
    assert!(city_grow.c_text.contains("func_0x005a13e4(") && !city_grow.c_text.contains("does not return"), "{}", city_grow.c_text);
}

/// Callbacks that the code pushes or stores begin functions, though the switch tables, padding
/// and dead code before them decode as instructions that run on into them. The tables are no
/// functions.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn the_callbacks_whose_addresses_the_code_takes_begin_functions() {
    let image = recore::Image::load(std::env::var("RECORE_RT3").expect("RECORE_RT3 names the binary").as_ref()).unwrap();
    let analysis = recore::analyze(&image);
    let is_start = |addr: u64| analysis.functions.iter().any(|f| f.addr == addr);

    // After a switch table, after padding behind a call to `exit`, and after padding a data
    // word points into.
    let missing: Vec<u64> = [0x46a830, 0x4d0a90, 0x4d3d90, 0x4d71b0, 0x4ed100, 0x50b910, 0x515780, 0x593790, 0x5b3a10].into_iter().filter(|&addr| !is_start(addr)).collect();
    assert_eq!(missing, [0u64; 0]);
    // The tables, and what a word in data points to in padding.
    let tables: Vec<u64> = [0x4d0a60, 0x5156ea, 0x4ed0fc].into_iter().filter(|&addr| is_start(addr)).collect();
    assert_eq!(tables, [0u64; 0]);
}

/// The loop that MSVC aligned after a call at 0x538faa is part of 0x538f10, which returns.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn a_loop_aligned_after_a_call_stays_in_its_function() {
    let image = recore::Image::load(std::env::var("RECORE_RT3").expect("RECORE_RT3 names the binary").as_ref()).unwrap();
    let analysis = recore::analyze(&image);
    let function = analysis.functions.iter().find(|f| f.addr == 0x538f10).expect("a function at 0x538f10");
    assert_eq!((function.ranges.last().map(|&(_, end)| end), function.noreturn), (Some(0x5391a1), false));
}

/// RT3 has no type information, yet its constructors store vtables: `model_instance_new`
/// stores the one at 0x5dd1f0, whose 16 slots run up to the data after it. Calls through
/// vtables are resolved through what a constructor returns into a global, through `this` in a
/// virtual function, and through `this` that every direct caller passes, and they count among
/// the callers of what they reach.
#[test]
#[ignore = "needs Railroad Tycoon 3: RECORE_RT3=<RT3.unpacked.exe>"]
fn calls_through_the_vtables_constructors_store_are_resolved() {
    let image = recore::Image::load(std::env::var("RECORE_RT3").expect("RECORE_RT3 names the binary").as_ref()).unwrap();
    let analysis = recore::analyze(&image);

    let model = analysis.classes.iter().find(|class| class.vtable == 0x5dd1f0).expect("the vtable model_instance_new stores");
    assert_eq!((model.name.as_str(), model.methods.len(), model.methods.first(), model.methods.last()), ("vtable_5dd1f0", 16, Some(&0x52db00), Some(&0x52eb80)));

    let call = |at: u64| analysis.virtual_calls.iter().find(|call| call.at == at).map(|call| (call.slot, call.vtables.clone(), call.targets.clone()));
    // `collection_add` of the collection a constructor puts in the global 0x62be10.
    assert_eq!(call(0x40762f), Some((1, vec![0x5c9bf8], vec![0x518900])));
    // In a virtual function only the vtable at 0x5c8c50 holds, through its own object.
    assert_eq!(call(0x40e035), Some((28, vec![0x5c8c50], vec![0x40ccb0])));
    // In 0x4a45f0, which each of its callers calls on the object in the global 0x6cfcb4.
    assert_eq!(call(0x4a46f7), Some((2, vec![0x5d0040], vec![0x4a4300])));
    // In 0x52d640, which methods of two classes call on their own objects.
    assert_eq!(call(0x52d64f), Some((3, vec![0x5ca078, 0x5dd1c8], vec![0x439d50, 0x52d370])));

    let program = recore::program::Program::new(image, analysis);
    assert!(program.sites_reaching(0x518900).any(|site| site == 0x40762f));
}
