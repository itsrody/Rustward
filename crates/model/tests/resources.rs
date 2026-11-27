use model::resources::{ResourceCatalog, ResourceSnapshot};
use std::path::Path;

fn fixture_catalog() -> ResourceCatalog {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    ResourceCatalog::load_verified(
        &root.join("config/resources/ubo-official.json"),
        "b5c816d61ec4201175899d17637c785d81e3de530fee949c1bf780b4ffd9df5b",
    )
    .expect("load pinned official resource snapshot")
}

#[test]
fn case_sensitive_legacy_aliases_resolve() {
    let catalog = fixture_catalog();
    let cases = [
        ("no-setTimeout-if", "prevent-setTimeout.js"),
        ("addEventListener-defuser", "prevent-addEventListener.js"),
        ("adjust-setInterval", "adjust-setInterval.js"),
        ("adjust-setTimeout", "adjust-setTimeout.js"),
        ("no-setInterval-if", "prevent-setInterval.js"),
        ("prevent-innerHTML", "prevent-innerHTML.js"),
        (
            "no-requestAnimationFrame-if",
            "prevent-requestAnimationFrame.js",
        ),
        ("prevent-addEventListener", "prevent-addEventListener.js"),
    ];
    for (alias, canonical) in cases {
        let found = catalog
            .find(alias)
            .unwrap_or_else(|| panic!("alias {alias} missing from official snapshot"));
        assert_eq!(found.name, canonical);
        assert!(catalog.dependency_closure(alias).is_ok());
    }
}

#[test]
fn redirect_aliases_resolve_after_suffix_stripping() {
    let catalog = fixture_catalog();
    for (name, canonical) in [
        ("noopjs", "noop.js"),
        ("fuckadblock.js-3.2.0", "nofab.js"),
        ("noop-1s.mp4", "noop-1s.mp4"),
    ] {
        let found = catalog
            .find(name)
            .unwrap_or_else(|| panic!("redirect alias {name} missing from official snapshot"));
        assert_eq!(found.name, canonical);
    }
    assert!(catalog.find("noopjs:10").is_none());
}

#[test]
fn folded_names_do_not_resolve() {
    let catalog = fixture_catalog();
    for folded in [
        "no-settimeout-if",
        "addeventlistener-defuser",
        "adjust-setinterval",
        "prevent-innerhtml",
    ] {
        assert!(catalog.find(folded).is_none(), "unexpected alias {folded}");
    }
}

#[test]
fn brave_snapshot_merges_into_official_catalog() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ubo = ResourceSnapshot::load_verified(
        &root.join("config/resources/ubo-official.json"),
        "b5c816d61ec4201175899d17637c785d81e3de530fee949c1bf780b4ffd9df5b",
    )
    .expect("load uBO snapshot");
    let brave = ResourceSnapshot::load_verified(
        &root.join("config/resources/brave-official.json"),
        "31d6bdd604b45e155d1093064a082b8f93ca63650be4bbb3e338a7a60d485053",
    )
    .expect("load Brave snapshot");
    let merged = ubo.merge(brave).into_catalog().expect("merge snapshots");

    assert_eq!(merged.resources.len(), 225);
    assert!(merged.source.contains("Brave"));
    assert!(merged.commit.contains("b84ad0fd"));

    for name in [
        "brave-fix.js",
        "brave-fix",
        "de-amp.js",
        "optimizely.js",
        "sourcepoint-reject.js",
        "ketch-reject-unblock.js",
    ] {
        let found = merged
            .find(name)
            .unwrap_or_else(|| panic!("Brave scriptlet {name} missing after merge"));
        assert_eq!(found.permission, 0);
        assert!(merged.dependency_closure(name).is_ok());
    }

    // uBO aliases must remain resolvable after the merge.
    assert_eq!(
        merged
            .find("no-setTimeout-if")
            .expect("uBO alias after merge")
            .name,
        "prevent-setTimeout.js"
    );
}

#[test]
fn duplicate_resource_names_across_snapshots_are_rejected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ubo = ResourceSnapshot::load_verified(
        &root.join("config/resources/ubo-official.json"),
        "b5c816d61ec4201175899d17637c785d81e3de530fee949c1bf780b4ffd9df5b",
    )
    .expect("load uBO snapshot");
    let duplicate = ubo.clone();
    assert!(ubo.merge(duplicate).into_catalog().is_err());
}
