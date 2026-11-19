//! Classification and build metrics.

use anyhow::Result;
use model::{
    AdmissionResult, AnalysisReport, Config, CosmeticPayload, Dialect, Eligibility,
    ExclusionReason, GapClass, ParsedOutcome, Rule, model::ParsedRecord,
};
use serde_json::json;
use std::collections::BTreeMap;

pub fn analyze(
    records: &[ParsedRecord],
    admission: &AdmissionResult,
    output_rules: &[Rule],
    config: &Config,
) -> Result<AnalysisReport> {
    let mut report = AnalysisReport::default();
    let mut metrics: BTreeMap<String, usize> = BTreeMap::new();
    let mut dialects: BTreeMap<String, usize> = BTreeMap::new();
    let mut gaps: BTreeMap<String, usize> = BTreeMap::new();

    fn bump(map: &mut BTreeMap<String, usize>, key: impl Into<String>) {
        *map.entry(key.into()).or_default() += 1;
    }

    fn set(map: &mut BTreeMap<String, usize>, key: impl Into<String>, value: usize) {
        map.insert(key.into(), value);
    }

    set(&mut metrics, "raw_lines", records.len());
    set(
        &mut metrics,
        "network_rules",
        output_rules
            .iter()
            .filter(|rule| matches!(rule, Rule::Network(_)))
            .count(),
    );
    set(
        &mut metrics,
        "cosmetic_rules",
        output_rules
            .iter()
            .filter(|rule| matches!(rule, Rule::Cosmetic(_)))
            .count(),
    );
    set(
        &mut metrics,
        "badfilter_resolved",
        admission
            .excluded
            .iter()
            .filter(|row| row.reason.code() == "BADFILTER_RESOLVED")
            .count(),
    );
    set(
        &mut metrics,
        "badfilter_targets_pruned",
        admission
            .excluded
            .iter()
            .filter(|row| row.reason.code() == "BADFILTER_TARGET")
            .count(),
    );

    for record in records {
        bump(&mut dialects, record.dialect.as_str());
        let gap_sources: &[model::DialectGap] = match &record.outcome {
            ParsedOutcome::Network(rule) => &rule.dialect_gaps,
            ParsedOutcome::Cosmetic(rule) => &rule.dialect_gaps,
            ParsedOutcome::Unsupported { gap, .. } => match gap {
                Some(gap) => std::slice::from_ref(gap),
                None => &[],
            },
            _ => &[],
        };
        for gap in gap_sources {
            bump(&mut gaps, format!("{}:{}", gap.kind, gap.class.as_str()));
            if gap.class == GapClass::SemanticGap {
                let key = if config
                    .admit
                    .accepted_semantic_gaps
                    .iter()
                    .any(|accepted| accepted == &gap.kind)
                {
                    "semantic_gaps_accepted"
                } else {
                    "semantic_gaps_unresolved"
                };
                bump(&mut metrics, key);
                bump(&mut metrics, &format!("{key}_{}", gap.kind));
            }
        }
        match &record.outcome {
            ParsedOutcome::Network(_) => bump(&mut metrics, "effective_network_rules"),
            ParsedOutcome::Cosmetic(_) => bump(&mut metrics, "effective_cosmetic_rules"),
            ParsedOutcome::Comment => bump(&mut metrics, "comments"),
            ParsedOutcome::Metadata => bump(&mut metrics, "metadata"),
            ParsedOutcome::Directive => bump(&mut metrics, "directives"),
            ParsedOutcome::Empty => bump(&mut metrics, "empty_lines"),
            ParsedOutcome::Unsupported { .. } => bump(&mut metrics, "parse_errors"),
        }
    }

    for rule in &admission.accepted {
        match rule.eligibility() {
            Eligibility::Eligible => bump(&mut metrics, "eligible"),
            Eligibility::RewritableToEligible => bump(&mut metrics, "rewritable_to_eligible"),
            Eligibility::Ineligible(_) => bump(&mut metrics, "ineligible"),
        }
        if let Rule::Cosmetic(cosmetic) = rule {
            match &cosmetic.payload {
                CosmeticPayload::NativeCss(_) => bump(&mut metrics, "cosmetic_fast_native"),
                CosmeticPayload::LightProcedural { .. } => {
                    bump(&mut metrics, "cosmetic_light_procedural")
                }
                CosmeticPayload::VettedScriptlet { .. } => {
                    bump(&mut metrics, "cosmetic_vetted_scriptlet")
                }
            }
        }
    }
    set(&mut metrics, "excluded_by_gate", admission.excluded.len());
    for exclusion in &admission.excluded {
        match &exclusion.reason {
            ExclusionReason::BatchExcluded(family) => {
                bump(&mut metrics, &format!("batch_excluded_{family}"));
            }
            ExclusionReason::SemanticGap(kind) => {
                bump(&mut metrics, "semantic_gaps_excluded");
                bump(&mut metrics, &format!("semantic_gaps_excluded_{kind}"));
            }
            _ => {}
        }
    }

    for rule in output_rules {
        if let Rule::Cosmetic(cosmetic) = rule {
            match &cosmetic.payload {
                CosmeticPayload::NativeCss(_) => bump(&mut metrics, "output_fast_native_css"),
                CosmeticPayload::LightProcedural { .. } => {
                    bump(&mut metrics, "output_light_procedural")
                }
                CosmeticPayload::VettedScriptlet { .. } => {
                    bump(&mut metrics, "output_vetted_scriptlet")
                }
            }
        }
    }

    report.metrics = metrics
        .into_iter()
        .map(|(key, value)| (key, json!(value)))
        .collect();
    report.dialects = dialects;
    report.gaps = gaps;

    let mut eligibility = BTreeMap::new();
    for rule in &admission.accepted {
        let key = match rule.eligibility() {
            Eligibility::Eligible => "ELIGIBLE",
            Eligibility::RewritableToEligible => "REWRITABLE_TO_ELIGIBLE",
            Eligibility::Ineligible(reason) => reason.code(),
        };
        *eligibility.entry(key.to_string()).or_insert(0usize) += 1;
    }
    report.eligibility = eligibility;
    Ok(report)
}

pub fn addressable_dialects() -> Vec<Dialect> {
    vec![Dialect::Abp, Dialect::Adguard, Dialect::Ubo, Dialect::Hosts]
}
