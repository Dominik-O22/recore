//! The C of an IL2CPP build decompiled with the types of its managed program: the release of
//! A-Van-Gestel/Unity-Minecraft_Clone that `bench/agent/fetch.py` pins, where the environment
//! variable `RECORE_MINECRAFT_CLONE` names its `GameAssembly.so`.

use recore_decomp::Session;
use recore_decomp::types::{self, Importer};

#[test]
fn methods_read_fields_statics_and_enums_by_name() {
    let Some(path) = std::env::var_os("RECORE_MINECRAFT_CLONE") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let image = recore::Image::load(&path).unwrap();
    let analysis = recore::analyze(&image);
    let debug = types::load(&path, &image).expect("the metadata gives types");
    let mut session = Session::from_image(&image, &analysis).unwrap();
    let mut importer = Importer::new(&debug, Default::default());
    importer.globals(&mut session);
    let mut c = |addr: u64| {
        importer.functions(&mut session, [addr]);
        session.decompile(addr).unwrap().c_text
    };

    let update = c(0x1f1a1c0);
    assert!(update.contains("(Player *this,Il2CppMethodInfo *method)"), "{update}");
    assert!(update.contains("WorldLaunchState_TypeInfo->static_fields->CurrentMode"), "{update}");
    assert!(update.contains("this->orientation"), "{update}");
    let route = c(0x20722f0);
    assert!(route.starts_with("\nLightingJobProcessor.CrossChunkModRoute") || route.contains("LightingJobProcessor.CrossChunkModRoute\n"), "{route}");
    assert!(route.contains("bool targetInWorld"), "{route}");
}
