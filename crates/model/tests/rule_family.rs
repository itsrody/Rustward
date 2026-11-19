use model::{
    AdmitConfig, CosmeticPayload, Dialect, Eligibility, GapClass, HideOrUnhide, Rule, RuleFamily,
    RuleState,
    model::{CosmeticRule, DialectGap, NetworkRule},
};

fn cosmetic(text: &str) -> Rule {
    Rule::Cosmetic(CosmeticRule {
        hosts: vec!["example.com".into()],
        not_hosts: vec![],
        entities: vec![],
        not_entities: vec![],
        payload: CosmeticPayload::NativeCss("div.ad".into()),
        selector_ops: vec!["css-selector".into()],
        action: HideOrUnhide::Hide,
        action_detail: None,
        generic: false,
        script_inject: false,
        permission: 0,
        text: text.into(),
        source_id: "test".into(),
        line_no: 1,
        dialect: Dialect::Ubo,
        source_trusted: false,
        source_permissions: 0,
        source_priority: 0,
        eligibility: Eligibility::Eligible,
        state: RuleState::Active,
        dialect_gaps: vec![],
        provenance: vec![],
    })
}

fn network() -> Rule {
    Rule::Network(NetworkRule {
        engine_id: 1,
        mask: 0,
        features: 0,
        hostname: Some("example.com".into()),
        body: "ads.example".into(),
        left_anchor: true,
        right_anchor: true,
        hostname_anchor: true,
        is_regex: false,
        is_literal_boundary_regex: false,
        is_complete_regex: false,
        is_hostname_regex: false,
        is_exception: false,
        important: false,
        match_case: false,
        is_badfilter: false,
        is_redirect: false,
        is_csp: false,
        is_removeparam: false,
        is_generic_hide: false,
        domains: vec![],
        not_domains: vec![],
        to_domains: vec![],
        not_to_domains: vec![],
        domain_hashes: vec![],
        not_domain_hashes: vec![],
        to_domain_hashes: vec![],
        not_to_domain_hashes: vec![],
        modifier_option: None,
        tag: None,
        text: "||ads.example^".into(),
        source_id: "test".into(),
        line_no: 1,
        dialect: Dialect::Ubo,
        source_trusted: false,
        source_permissions: 0,
        source_priority: 0,
        eligibility: Eligibility::Eligible,
        state: RuleState::Active,
        dialect_gaps: vec![],
        provenance: vec![],
    })
}

#[test]
fn nested_slow_operators_are_classified_as_nested_procedural() {
    for text in [
        "example.com##.ad:matches-css(display: none)",
        "example.com##.ad:has-text(/Sponsored/)",
        "example.com##.ad:matches-attr(/href/)",
        "example.com#?#.ad:has(div)",
        "example.com##:-abp-has(.ad)",
        "example.com##.ad:matches-path(/promo/)",
    ] {
        assert_eq!(
            cosmetic(text).family(),
            Some(RuleFamily::NestedProcedural),
            "{text}"
        );
    }
    assert_eq!(cosmetic("example.com##div.ad > span:has(a)").family(), None);
}

#[test]
fn semantic_gap_policy_finds_unaccepted_gaps() {
    let mut rule = network();
    match &mut rule {
        Rule::Network(network) => {
            network.dialect_gaps = vec![
                DialectGap::new("all", GapClass::SemanticGap, "accepted"),
                DialectGap::new("entity_domain", GapClass::SemanticGap, "rejected"),
            ];
        }
        Rule::Cosmetic(_) => unreachable!(),
    }
    let accepted = AdmitConfig::default().accepted_semantic_gaps;
    assert_eq!(
        rule.unaccepted_semantic_gap(&accepted),
        Some("entity_domain")
    );
    assert_eq!(
        rule.unaccepted_semantic_gap(&["all".into()]),
        Some("entity_domain")
    );
    assert_eq!(
        rule.unaccepted_semantic_gap(&["all".into(), "entity_domain".into()]),
        None
    );
}

#[test]
fn plain_rules_have_no_family_and_batch_exclusion_default_is_nested_procedural() {
    assert_eq!(network().family(), None);
    assert_eq!(
        AdmitConfig::default().exclude_families,
        vec![RuleFamily::NestedProcedural]
    );
}
