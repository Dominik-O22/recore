//! Tanktics (MSVC 5 or 6, 1999): code that loads an import into a register and calls it there.
//! `RECORE_TANKTICS` names the binary, which stays out of the repository.

mod common;

use common::Client;
use serde_json::json;

/// The function that picks the DirectDraw driver calls `LockWindowUpdate` through `ESI` before
/// and after `DirectDrawEnumerateA`.
#[test]
#[ignore = "needs Tanktics: RECORE_TANKTICS=<tanktics.exe>"]
fn an_import_called_through_a_register_takes_its_argument() {
    let mut client = Client::start();
    let path = std::env::var("RECORE_TANKTICS").expect("RECORE_TANKTICS names the binary");
    let c = client.tool("decompile", json!({ "path": path, "functions": ["0x45b000"] })).unwrap();
    for line in ["LockWindowUpdate(pvRam0066b630);", "LockWindowUpdate((void *)0x0);"] {
        assert!(c.contains(line), "{line} in\n{c}");
    }
}
