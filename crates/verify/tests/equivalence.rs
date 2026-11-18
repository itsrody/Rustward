use verify::network_equivalence;

#[test]
fn type_union_is_engine_equivalent() {
    let before = [
        "||ads.example^$script".to_string(),
        "||ads.example^$image".to_string(),
    ];
    assert!(
        network_equivalence(&before, "||ads.example^$image,script", 0).expect("equivalence check")
    );
}

#[test]
fn domain_union_is_engine_equivalent() {
    let before = [
        "||tracker.example^$domain=site-a.example".to_string(),
        "||tracker.example^$domain=site-b.example".to_string(),
    ];
    assert!(
        network_equivalence(
            &before,
            "||tracker.example^$domain=site-a.example|site-b.example",
            0
        )
        .expect("equivalence check")
    );
}

#[test]
fn unrelated_rewrite_is_rejected() {
    let before = ["||ads.example^$script".to_string()];
    assert!(
        !network_equivalence(&before, "||other.example^$script", 0).expect("equivalence check")
    );
}
