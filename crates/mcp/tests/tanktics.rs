//! Tanktics (MSVC 5 or 6, 1999): imports called through a register, DirectX, and the Miles
//! Sound System, whose exports carry stdcall's decorated names.
//! `RECORE_TANKTICS` names the binary, which stays out of the repository.

mod common;

use common::Client;
use serde_json::json;

fn decompile(function: &str) -> String {
    let path = std::env::var("RECORE_TANKTICS").expect("RECORE_TANKTICS names the binary");
    Client::start().tool("decompile", json!({ "path": path, "functions": [function] })).unwrap()
}

/// The function that picks the DirectDraw driver calls `LockWindowUpdate` through `ESI` before
/// and after `DirectDrawEnumerateA`, then moves the window to the rectangle it read before them.
#[test]
#[ignore = "needs Tanktics: RECORE_TANKTICS=<tanktics.exe>"]
fn the_window_goes_back_to_the_rectangle_read_before_the_calls() {
    let c = decompile("0x45b000");
    for line in [
        "LockWindowUpdate(pvRam0066b630);",
        "DirectDrawEnumerateA(func_0x0045c340,(void *)0x66b61c);",
        "LockWindowUpdate((void *)0x0);",
        "SetWindowPos(pvRam0066b630,(void *)0x0,iStack_10,iStack_c,iStack_8 - iStack_10,iStack_4 - iStack_c",
    ] {
        assert!(c.contains(line), "{line} in\n{c}");
    }
}

/// Playing a sound sets the sample's rate, pan and volume from the function's own parameters.
#[test]
#[ignore = "needs Tanktics: RECORE_TANKTICS=<tanktics.exe>"]
fn a_sound_plays_at_the_rate_and_volume_it_is_given() {
    let c = decompile("0x43e000");
    for line in ["_AIL_set_sample_playback_rate@8(uRam0066a664,param_2);", "_AIL_set_sample_volume@8(uRam0066a664,param_3 & 0xff);"] {
        assert!(c.contains(line), "{line} in\n{c}");
    }
}
