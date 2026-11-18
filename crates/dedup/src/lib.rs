//! Exact and semantic deduplication with source-priority resolution.

use anyhow::Result;
use model::{Origin, Rule, util::semantic_key};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct DedupResult {
    pub rules: Vec<Rule>,
    pub duplicate_exact: usize,
    pub duplicate_semantic: usize,
}

pub fn dedup(rules: Vec<Rule>) -> Result<DedupResult> {
    let mut by_exact: BTreeMap<String, Rule> = BTreeMap::new();
    let mut by_semantic: BTreeMap<String, Rule> = BTreeMap::new();
    let mut duplicate_exact = 0usize;
    let mut duplicate_semantic = 0usize;

    for rule in rules {
        if rule.is_badfilter() {
            // $badfilter targets depend on exact text; these rules are barriers.
            let key = format!(
                "badfilter\0{}\0{}\0{}",
                rule.source_id(),
                rule.line_no(),
                rule.text()
            );
            by_semantic.insert(key, rule);
            continue;
        }

        let exact_key = rule.text().trim().to_string();
        if let Some(existing) = by_exact.get_mut(&exact_key) {
            duplicate_exact += 1;
            if preferred(existing, &rule) {
                let mut chosen = rule;
                chosen = merge_into(chosen, existing);
                *existing = chosen;
            } else {
                merge_provenance(existing, &rule);
            }
            continue;
        }
        by_exact.insert(exact_key, rule);
    }

    for rule in by_exact.into_values() {
        let key = semantic_key(&rule)?;
        if let Some(existing) = by_semantic.get_mut(&key) {
            duplicate_semantic += 1;
            let replacement = preferred(existing, &rule);
            if replacement {
                let mut chosen = rule;
                chosen = merge_into(chosen, existing);
                *existing = chosen;
            } else {
                merge_provenance(existing, &rule);
            }
            continue;
        }
        by_semantic.insert(key, rule);
    }

    let mut output: Vec<Rule> = by_semantic.into_values().collect();
    output.sort_by(|a, b| {
        a.source_id()
            .cmp(b.source_id())
            .then(a.line_no().cmp(&b.line_no()))
            .then(a.text().cmp(b.text()))
    });
    Ok(DedupResult {
        rules: output,
        duplicate_exact,
        duplicate_semantic,
    })
}

fn rank(rule: &Rule) -> (i32, usize, &str, usize) {
    (
        source_priority(rule).saturating_neg(),
        rule.text().len(),
        rule.source_id(),
        rule.line_no(),
    )
}

fn preferred(existing: &Rule, candidate: &Rule) -> bool {
    rank(candidate) < rank(existing)
}

fn merge_provenance(existing: &mut Rule, other: &Rule) {
    let mut origins: Vec<Origin> = existing.provenance().to_vec();
    let mut seen: HashSet<(String, usize, String)> = origins
        .iter()
        .map(|origin| {
            (
                origin.source_id.clone(),
                origin.line_no,
                origin.text.clone(),
            )
        })
        .collect();
    for origin in other.provenance() {
        let key = (
            origin.source_id.clone(),
            origin.line_no,
            origin.text.clone(),
        );
        if seen.insert(key) {
            origins.push(origin.clone());
        }
    }
    origins.sort_by(|a, b| {
        a.source_id
            .cmp(&b.source_id)
            .then(a.line_no.cmp(&b.line_no))
    });
    set_provenance(existing, origins);
}

fn merge_into(mut chosen: Rule, other: &Rule) -> Rule {
    merge_provenance(&mut chosen, other);
    chosen
}

fn set_provenance(rule: &mut Rule, origins: Vec<Origin>) {
    match rule {
        Rule::Network(network) => network.provenance = origins,
        Rule::Cosmetic(cosmetic) => cosmetic.provenance = origins,
    }
}

pub fn source_priority(rule: &Rule) -> i32 {
    match rule {
        Rule::Network(network) => network.source_priority,
        Rule::Cosmetic(cosmetic) => cosmetic.source_priority,
    }
}
