use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn copy_fixture_tree(root: &Path) {
    let source = repo_root();
    for relative in [
        "config/sources.toml",
        "config/profiles.toml",
        "config/resources/ubo-official.json",
        "tests/fixtures/basic.txt",
        "tests/fixtures/hosts.txt",
    ] {
        let destination = root.join(relative);
        fs::create_dir_all(destination.parent().expect("parent")).expect("create parent");
        fs::copy(source.join(relative), &destination).expect("copy fixture");
    }
}

fn run_build(root: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustshield"))
        .args(["--root"])
        .arg(root)
        .args(["--config", "config/sources.toml", "build"])
        .output()
        .expect("run rustshield")
}

#[test]
fn fixture_build_is_verified_deterministic_and_golden_rule_clean() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rustshield-fixture-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    copy_fixture_tree(&root);

    let first = run_build(&root);
    assert!(
        first.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let list_path = root.join("RustShield.txt");
    let first_list = fs::read_to_string(&list_path).expect("read list");
    assert!(first_list.contains("||ads.example^$image,script"));
    assert!(first_list.contains("||tracker.example^$domain=site-a.example|site-b.example"));
    assert!(first_list.contains("example.com,other.example##.ad"));
    assert!(first_list.contains("+js(abort-on-property-read, adblockWasFound)"));
    assert!(!first_list.contains("matches-css"));
    assert!(!first_list.contains("denyallow"));
    assert!(!first_list.contains("inactive.example"));

    for artifact in [
        "RustShield.txt.sha256",
        "lists.lock",
        "reports/manifest.json",
        "reports/build.json",
        "reports/build.md",
        "reports/analysis.json",
        "reports/rewrites.tsv",
        "reports/dropped.tsv",
        "reports/excluded.tsv",
        "reports/dialect_gaps.tsv",
        "reports/verify.json",
        "reports/bench.json",
    ] {
        assert!(root.join(artifact).exists(), "missing artifact {artifact}");
    }

    let verify: Value =
        serde_json::from_slice(&fs::read(root.join("reports/verify.json")).expect("read verify"))
            .expect("parse verify");
    assert_eq!(verify["required"], true);
    assert_eq!(
        verify["mismatches"].as_array().expect("mismatches").len(),
        0
    );
    assert_eq!(verify["golden_rule_violations"], 0);
    assert_eq!(verify["emit_order_violations"], 0);

    let build: Value =
        serde_json::from_slice(&fs::read(root.join("reports/build.json")).expect("read build"))
            .expect("parse build");
    assert_eq!(build["metrics"]["rewrites_applied"], 3);

    let rewrites = fs::read_to_string(root.join("reports/rewrites.tsv")).expect("read rewrites");
    assert!(rewrites.contains("type_union"));
    assert!(rewrites.contains("domain_union"));
    assert!(rewrites.contains("cosmetic_host_union"));

    let second = run_build(&root);
    assert!(
        second.status.success(),
        "second build failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        fs::read_to_string(&list_path).expect("read rebuilt list"),
        first_list,
        "build is not deterministic"
    );

    fs::remove_dir_all(&root).ok();
}
