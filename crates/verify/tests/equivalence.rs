use verify::{literal_contains_equivalence, network_equivalence};

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
fn network_alias_and_option_order_are_engine_equivalent() {
    let before = ["||ads.example^$xhr,3p,domain=b.example|a.example".to_string()];
    assert!(
        network_equivalence(
            &before,
            "||ads.example^$domain=a.example|b.example,third-party,xmlhttprequest",
            0
        )
        .expect("equivalence check")
    );

    let before = ["@@||ads.example^$ghide,image".to_string()];
    assert!(
        network_equivalence(&before, "@@||ads.example^$generichide,image", 0)
            .expect("equivalence check")
    );
}

#[test]
fn literal_contains_normalization_is_engine_equivalent() {
    assert!(
        literal_contains_equivalence(
            "contains.example##.promo:contains(Legacy Ad)",
            "contains.example##.promo:has-text(Legacy Ad)",
            0
        )
        .expect("equivalence check")
    );

    assert!(
        !literal_contains_equivalence(
            "contains.example##.promo:contains(Ad One)",
            "contains.example##.promo:has-text(Ad Two)",
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
