use model::resources::ResourceCatalog;
use std::path::Path;

fn fixture_catalog() -> ResourceCatalog {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    ResourceCatalog::load_verified(
        &root.join("config/resources/ubo-official.json"),
        "ddc13cecf2441456e0c707a484fb7e76a4d82d1ad13b09e8075ee1ab2e4cd038",
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
