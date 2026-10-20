//! Tanktics (MSVC 5 or 6, 1999): imports called through a register, DirectX, and the Miles
//! Sound System, whose exports carry stdcall's decorated names.
//! `RECORE_TANKTICS` names the binary, which stays out of the repository.
//!
//! The tests check where each argument comes from, not how the decompiler spells it: a cast,
//! a mask or a local's name may change as the types it recovers get better.

mod common;

use common::Client;
use serde_json::json;

fn decompile(function: &str) -> String {
    let path = std::env::var("RECORE_TANKTICS").expect("RECORE_TANKTICS names the binary");
    Client::start().tool("decompile", json!({ "path": path, "functions": [function] })).unwrap()
}

/// The arguments of each call to `callee` in `c`, split at the commas outside parentheses.
fn calls(c: &str, callee: &str) -> Vec<Vec<String>> {
    let opening = format!("{callee}(");
    c.match_indices(&opening)
        .map(|(at, _)| {
            let mut arguments = vec![String::new()];
            let mut depth = 0;
            for ch in c[at + opening.len()..].chars() {
                match ch {
                    ')' if depth == 0 => break,
                    ',' if depth == 0 => arguments.push(String::new()),
                    _ => {
                        depth += i32::from(ch == '(') - i32::from(ch == ')');
                        if !ch.is_whitespace() {
                            arguments.last_mut().unwrap().push(ch);
                        }
                    }
                }
            }
            arguments
        })
        .collect()
}

/// The function that picks the DirectDraw driver calls `LockWindowUpdate` through `ESI` before
/// and after `DirectDrawEnumerateA`, then moves the window to the rectangle `GetWindowRect`
/// filled before them. With a call's arguments left on the stack, the rectangle reads as the
/// registers the function saved.
#[test]
#[ignore = "needs Tanktics: RECORE_TANKTICS=<tanktics.exe>"]
fn the_window_goes_back_to_the_rectangle_read_before_the_calls() {
    let c = decompile("0x45b000");
    let window = "pvRam0066b630";
    let locks = calls(&c, "LockWindowUpdate");
    assert!(locks.len() == 2 && locks[0] == [window] && locks[1][0].ends_with("0x0"), "{locks:?} in\n{c}");
    let enumerate = calls(&c, "DirectDrawEnumerateA");
    assert!(enumerate.len() == 1 && enumerate[0].len() == 2 && enumerate[0][0] == "func_0x0045c340", "{enumerate:?} in\n{c}");
    let rect = calls(&c, "GetWindowRect");
    let left = rect.first().and_then(|arguments| arguments.get(1)?.strip_prefix('&')).unwrap_or_else(|| panic!("{rect:?} in\n{c}"));
    let moved = calls(&c, "SetWindowPos");
    assert!(moved.len() == 1 && moved[0].len() == 7 && moved[0][0] == window && moved[0][2] == left, "{moved:?} in\n{c}");
    assert!(!c.contains("unaff_"), "{c}");
}

/// Playing a sound sets the sample's rate and volume from the function's own parameters.
#[test]
#[ignore = "needs Tanktics: RECORE_TANKTICS=<tanktics.exe>"]
fn a_sound_plays_at_the_rate_and_volume_it_is_given() {
    let c = decompile("0x43e000");
    assert!(c.contains("param_3") && !c.contains("param_4"), "{c}");
    let rate = calls(&c, "_AIL_set_sample_playback_rate@8");
    assert!(rate.len() == 1 && rate[0].len() == 2 && rate[0][1] == "param_2", "{rate:?} in\n{c}");
    let volume = calls(&c, "_AIL_set_sample_volume@8");
    assert!(volume.len() == 1 && volume[0].len() == 2 && volume[0][1].contains("param_3"), "{volume:?} in\n{c}");
}
