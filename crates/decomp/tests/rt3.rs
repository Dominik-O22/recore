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
