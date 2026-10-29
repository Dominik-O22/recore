//! IL2CPP builds recore was checked against: Fishing Planet (Unity 6000.3, metadata version 39)
//! and a release of A-Van-Gestel/Unity-Minecraft_Clone (Unity 6000.5, version 107), the build
//! `bench/agent/fetch.py` pins. Each test runs where its environment variable names the build's
//! `GameAssembly.so`, laid out as it ships, with its `global-metadata.dat` in the data directory.
//! Expected values are from the game's C# source, or from Cpp2IL's dump of the build.

use std::path::Path;

use recore::Image;
use recore::il2cpp::Il2Cpp;

fn build(var: &str) -> Option<Image> {
    let path = std::env::var_os(var)?;
    Some(Image::load(Path::new(&path)).unwrap())
}

fn il2cpp(image: &Image) -> &Il2Cpp {
    image.il2cpp.as_deref().expect("the build's metadata is read")
}

/// A class's objects hold its parent's fields, each once, and then its own. A field may still
/// share a name with one of its ancestors' that it hides.
fn assert_fields_inherited_once(il2cpp: &Il2Cpp) {
    let instance =
        |def: &recore::il2cpp::TypeDef| def.fields.iter().filter(|field| !field.is_static).map(|field| (field.name.clone(), field.offset)).collect::<Vec<_>>();
    for def in il2cpp.types.iter().filter(|def| !def.is_value_type) {
        let Some(parent) = def.parent else {
            continue;
        };
        let (fields, inherited) = (instance(def), instance(&il2cpp.types[parent as usize]));
        assert!(fields.starts_with(&inherited), "{} does not start with the fields of {}", def.name, il2cpp.types[parent as usize].name);
        assert!(
            !fields[inherited.len()..].starts_with(&inherited) || inherited.is_empty(),
            "{} repeats the fields of {}",
            def.name,
            il2cpp.types[parent as usize].name
        );
    }
}

fn field_offset(il2cpp: &Il2Cpp, class: &str, field: &str) -> Option<u32> {
    let class = il2cpp.types.iter().find(|def| def.name == class)?;
    class.fields.iter().find(|found| found.name == field)?.offset
}

#[test]
fn fishing_planet_names_methods_fields_vtables_and_usage_slots() {
    let Some(image) = build("RECORE_FISHING_PLANET") else {
        return;
    };
    let il2cpp = il2cpp(&image);
    assert_eq!(il2cpp.version, 39);
    assert_eq!(image.symbol_names[&0x41a1010], "Lure1stBehaviour.OnLateUpdate");
    assert_eq!(field_offset(il2cpp, "PlayerController", "rodLocalPoints"), Some(0x9e0));
    let controller = il2cpp.types.iter().find(|def| def.name == "PlayerController").unwrap();
    assert_eq!(controller.vtable[3].as_deref(), Some("UnityEngine.Object.ToString"));
    assert_eq!(controller.vtable[4].as_deref(), Some("PlayerController.get_IsPitching"));
    // The state a state machine's method returns, which the code loads from a usage slot.
    assert_eq!(image.symbol_names[&0x98f1d08], "typeof(PlayerThrowInOneHand)");
    assert!(il2cpp.generic_methods.len() > 200_000);
    assert_fields_inherited_once(il2cpp);
}

#[test]
fn a_unity_6_5_build_has_its_tables_found_by_what_they_hold() {
    let Some(image) = build("RECORE_MINECRAFT_CLONE") else {
        return;
    };
    let il2cpp = il2cpp(&image);
    assert_eq!(il2cpp.version, 107);
    assert_eq!(image.symbol_names[&0x1f1a1c0], "Player.Update");
    assert_eq!(image.symbol_names[&0x3634660], "List<int>.Add");
    // A type nested in a generic type, with the outer type's arguments on the outer part.
    assert_eq!(image.symbol_names[&0x303ce40], "List<GpuUpdaterStaged<ushort>.CopyInfo>.Enumerator.MoveNext");
    assert_eq!(image.symbol_names[&0x4ba7200], "WorldLaunchState_TypeInfo");
    assert_eq!(image.symbol_names[&0x4bd2010], "\"MeshGenerationBenchmark requires a World instance in the scene!\"");
    assert_eq!(field_offset(il2cpp, "Player", "_world"), Some(0x38));
    assert_eq!(field_offset(il2cpp, "Player", "orientation"), Some(0x70));
    let route = il2cpp.types.iter().find(|def| def.name == "LightingJobProcessor.CrossChunkModRoute").unwrap();
    let members: Vec<(&str, i64)> = route.members.iter().map(|(name, value)| (name.as_str(), *value)).collect();
    assert_eq!(members, [("DropOutOfWorld", 0), ("PersistUndeliverable", 1), ("Defer", 2), ("ApplyDirect", 3)]);
    let tags = il2cpp.types.iter().find(|def| def.name == "BlockTags").unwrap();
    assert!(tags.members.contains(&("DEBUG".to_string(), 1 << 16)));
    assert_fields_inherited_once(il2cpp);
    let step = il2cpp.types.iter().find(|def| def.name == "WorldMigrationStep").unwrap();
    // An abstract method's slot, which the vtable table leaves empty.
    assert_eq!(step.vtable[4].as_deref(), Some("WorldMigrationStep.get_SourceWorldVersion"));
    assert_eq!(step.vtable[10].as_deref(), Some("WorldMigrationStep.MigrateLevelDat"));
}
