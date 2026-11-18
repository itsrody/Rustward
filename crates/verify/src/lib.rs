//! Differential verification and benchmarks using the real `adblock-rust` engine.

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions, ParsedLine, parse_filter},
    request::Request,
    resources::{PermissionMask, Resource},
};
use anyhow::Result;
use model::{
    BenchReport, Config, CosmeticPayload, Eligibility, ExclusionReason, Mismatch, Rule,
    VerifyReport,
};
use serde::Serialize;
use std::{collections::BTreeSet, time::Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub blocked: bool,
    pub redirect: Option<String>,
    pub rewritten_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CorpusCase {
    pub url: String,
    pub source_url: String,
    pub request_type: &'static str,
    pub method: &'static str,
    pub label: String,
}

pub fn build_engine(lists: &[(String, u8)], resources: &[Resource], optimize: bool) -> Engine {
    let mut set = FilterSet::new(false);
    for (text, permissions) in lists {
        set.add_filter_list(
            text.clone(),
            ParseOptions {
                permissions: PermissionMask::from_bits(*permissions),
                ..Default::default()
            },
        );
    }
    let mut engine = if optimize {
        Engine::new_with_filter_set(set)
    } else {
        Engine::new_with_filter_set_no_optimize(set)
    };
    engine.use_resources(resources.iter().cloned());
    engine
}

pub fn admitted_lists(rules: &[Rule]) -> Vec<(String, u8)> {
    let mut groups: std::collections::BTreeMap<u8, Vec<&str>> = std::collections::BTreeMap::new();
    for rule in rules {
        groups
            .entry(rule.source_permissions())
            .or_default()
            .push(rule.text());
    }
    groups
        .into_iter()
        .map(|(permissions, lines)| (lines.join("\n"), permissions))
        .collect()
}

pub fn candidate_lists(text: &str, permissions: u8) -> Vec<(String, u8)> {
    vec![(text.to_string(), permissions)]
}

pub fn verify(
    config: &Config,
    admitted_rules: &[Rule],
    candidate_rules: &[Rule],
    candidate_text: &str,
    canonical_text: &str,
    resources: &[Resource],
) -> Result<VerifyReport> {
    let admitted = build_engine(&admitted_lists(admitted_rules), resources, true);
    let candidate = build_engine(
        &candidate_lists(candidate_text, config.engine.permissions),
        resources,
        true,
    );
    let corpus = generate_corpus(admitted_rules, config.verify.max_cases);
    let mut mismatches = Vec::new();

    for case in &corpus {
        let request =
            match Request::new(&case.url, &case.source_url, case.request_type, case.method) {
                Ok(request) => request,
                Err(_) => continue,
            };
        let before = decision(&admitted.check_network_request(&request));
        let after = decision(&candidate.check_network_request(&request));
        if before != after {
            mismatches.push(Mismatch {
                case: case.label.clone(),
                detail: format!("network decision {before:?} != {after:?}"),
            });
            if mismatches.len() > config.verify.max_mismatches {
                break;
            }
        }
    }

    for host in cosmetic_hosts(admitted_rules)
        .into_iter()
        .take(config.verify.max_cosmetic_hosts.max(1))
    {
        let url = format!("https://{host}/");
        let before = cosmetic_snapshot(&admitted.url_cosmetic_resources(&url));
        let after = cosmetic_snapshot(&candidate.url_cosmetic_resources(&url));
        if before != after {
            mismatches.push(Mismatch {
                case: format!("cosmetic:{host}"),
                detail: format!("cosmetic resources {before:?} != {after:?}"),
            });
            if mismatches.len() > config.verify.max_mismatches {
                break;
            }
        }
    }

    let golden_rule_violations = candidate_rules
        .iter()
        .filter(|rule| !passes_golden_rule(rule))
        .count();
    let emit_order_violations = usize::from(candidate_text != canonical_text);
    if golden_rule_violations > 0 {
        mismatches.push(Mismatch {
            case: "golden-rule".to_string(),
            detail: format!("{golden_rule_violations} emitted rules fail the golden rule"),
        });
    }
    if emit_order_violations > 0 {
        mismatches.push(Mismatch {
            case: "emit-order".to_string(),
            detail: "candidate text is not in canonical compiler-friendly-v1 order".to_string(),
        });
    }

    Ok(VerifyReport {
        required: config.verify.required,
        mismatches,
        cases_checked: corpus.len(),
        golden_rule_violations,
        emit_order_violations,
    })
}

pub fn bench(
    config: &Config,
    admitted_rules: &[Rule],
    candidate_text: &str,
    resources: &[Resource],
    emit_order: &str,
) -> BenchReport {
    let admitted_lists = admitted_lists(admitted_rules);
    let candidate_lists = candidate_lists(candidate_text, config.engine.permissions);

    let started = Instant::now();
    let admitted_opt = build_engine(&admitted_lists, resources, true);
    let admitted_build_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let candidate_opt = build_engine(&candidate_lists, resources, true);
    let candidate_build_ms = started.elapsed().as_millis();
    let admitted_noopt = build_engine(&admitted_lists, resources, false);
    let candidate_noopt = build_engine(&candidate_lists, resources, false);

    let corpus = generate_corpus(admitted_rules, config.verify.max_cases);
    let iterations = config.verify.bench_iterations.max(1);
    let admitted_qps = throughput(&admitted_opt, &corpus, iterations);
    let candidate_qps = throughput(&candidate_opt, &corpus, iterations);

    BenchReport {
        admitted_opt_bytes: admitted_opt.serialize().len(),
        candidate_opt_bytes: candidate_opt.serialize().len(),
        admitted_noopt_bytes: admitted_noopt.serialize().len(),
        candidate_noopt_bytes: candidate_noopt.serialize().len(),
        admitted_build_ms,
        candidate_build_ms,
        admitted_qps,
        candidate_qps,
        emit_order: emit_order.to_string(),
    }
}

fn throughput(engine: &Engine, corpus: &[CorpusCase], iterations: usize) -> f64 {
    let requests: Vec<Request> = corpus
        .iter()
        .filter_map(|case| {
            Request::new(&case.url, &case.source_url, case.request_type, case.method).ok()
        })
        .collect();
    if requests.is_empty() {
        return 0.0;
    }
    let started = Instant::now();
    for _ in 0..iterations {
        for request in &requests {
            std::hint::black_box(engine.check_network_request(request));
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    if elapsed == 0.0 {
        return 0.0;
    }
    (requests.len() * iterations) as f64 / elapsed
}

fn decision(result: &adblock::blocker::BlockerResult) -> Decision {
    Decision {
        blocked: result.should_block(),
        redirect: result.redirect.clone(),
        rewritten_url: result.rewritten_url.clone(),
    }
}

fn generate_corpus(rules: &[Rule], max_cases: usize) -> Vec<CorpusCase> {
    let max_cases = max_cases.max(1);
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();

    fn push(
        cases: &mut Vec<CorpusCase>,
        seen: &mut BTreeSet<String>,
        label: String,
        url: String,
        source: String,
        kind: &'static str,
        method: &'static str,
    ) {
        if seen.insert(label.clone()) {
            cases.push(CorpusCase {
                url,
                source_url: source,
                request_type: kind,
                method,
                label,
            });
        }
    }

    let types = ["script", "image", "document", "xmlhttprequest"];

    // Keep unconditional negative probes even when the corpus budget is small.
    for host in [
        "example.org",
        "news.example.net",
        "site-a.example",
        "site-b.example",
        "neutral.example",
    ] {
        for kind in types {
            push(
                &mut cases,
                &mut seen,
                format!("negative:{host}:{kind}"),
                format!("https://{host}/benign.js"),
                "https://example.org/".to_string(),
                kind,
                "GET",
            );
        }
    }

    let neutral_sources = [
        "https://site-a.example/".to_string(),
        "https://site-b.example/".to_string(),
        "https://neutral.example/".to_string(),
    ];
    let methods = ["GET", "POST"];
    let network_count = rules
        .iter()
        .filter(|rule| matches!(rule, Rule::Network(_)))
        .count()
        .max(1);
    let budget = max_cases.saturating_sub(cases.len());
    let per_rule_limit = (budget / network_count).clamp(1, 144);

    for rule in rules {
        if cases.len() >= max_cases {
            break;
        }
        let Rule::Network(network) = rule else {
            continue;
        };
        if network.is_badfilter {
            continue;
        }

        let mut rule_cases = Vec::new();
        {
            let mut push_rule = |label: String,
                                 url: String,
                                 source: String,
                                 kind: &'static str,
                                 method: &'static str| {
                if seen.insert(label.clone()) {
                    rule_cases.push(CorpusCase {
                        url,
                        source_url: source,
                        request_type: kind,
                        method,
                        label,
                    });
                }
            };

            let mut urls = Vec::new();
            if let Some(host) = &network.hostname {
                urls.push(format!("http://{host}/rs-probe.js"));
                urls.push(format!("https://{host}/path?q=1"));
                urls.push(format!("https://sub.{host}/"));
            }
            if !network.body.is_empty() && !network.is_regex {
                let body = network.body.trim_matches(|c: char| c == '|' || c == '^');
                if !body.is_empty() {
                    urls.push(format!("https://neutral.example/path/{body}"));
                    urls.push(format!("https://neutral.example/?q={body}"));
                }
            }
            let mut sources = neutral_sources.to_vec();
            for domain in network.domains.iter().take(4) {
                sources.push(format!("https://{domain}/"));
            }
            for (url_index, url) in urls.into_iter().enumerate() {
                for source in sources.iter().take(6) {
                    for kind in types {
                        for method in methods {
                            push_rule(
                                format!(
                                    "rule:{}:{}:{url_index}:{source}:{kind}:{method}",
                                    rule.source_id(),
                                    rule.line_no()
                                ),
                                url.clone(),
                                source.clone(),
                                kind,
                                method,
                            );
                        }
                    }
                }
            }
        }
        cases.extend(evenly_sample(rule_cases, per_rule_limit));
    }

    cases.truncate(max_cases);
    cases
}

fn evenly_sample(cases: Vec<CorpusCase>, limit: usize) -> Vec<CorpusCase> {
    if cases.len() <= limit || limit == 0 {
        return cases;
    }
    let step = cases.len() / limit;
    (0..limit)
        .map(|index| cases[index * step].clone())
        .collect()
}

fn cosmetic_hosts(rules: &[Rule]) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for rule in rules {
        if let Rule::Cosmetic(cosmetic) = rule {
            for host in cosmetic.hosts.iter().chain(cosmetic.entities.iter()) {
                hosts.insert(host.clone());
            }
        }
    }
    if hosts.is_empty() {
        hosts.insert("example.com".to_string());
    }
    hosts
}

fn cosmetic_snapshot(
    resources: &adblock::cosmetic_filter_cache::UrlSpecificResources,
) -> (Vec<String>, bool, String) {
    let mut selectors: Vec<String> = resources.hide_selectors.iter().cloned().collect();
    selectors.sort();
    (
        selectors,
        resources.generichide,
        normalize_injected_script(&resources.injected_script),
    )
}

/// The engine concatenates scriptlets in list order. Re-emission intentionally changes rule order for
/// engine locality, so compare the multiset of independent `try { ... } catch` blocks instead.
fn normalize_injected_script(script: &str) -> String {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut saw_block = false;
    for line in script.lines() {
        current.push_str(line);
        current.push('\n');
        if line == "} catch ( e ) { }" {
            blocks.push(std::mem::take(&mut current));
            saw_block = true;
        }
    }
    if !saw_block || !current.trim().is_empty() {
        return script.to_string();
    }
    blocks.sort();
    blocks.concat()
}

fn passes_golden_rule(rule: &Rule) -> bool {
    if rule.eligibility() != &Eligibility::Eligible {
        return false;
    }
    match rule {
        Rule::Network(network) => {
            !network.is_regex
                && !network.is_complete_regex
                && !network.is_hostname_regex
                && !network.match_case
                && !network
                    .dialect_gaps
                    .iter()
                    .any(|gap| gap.class == model::GapClass::Unsupported)
        }
        Rule::Cosmetic(cosmetic) => match &cosmetic.payload {
            CosmeticPayload::NativeCss(_) => {
                cosmetic.selector_ops == ["css-selector"] && cosmetic.action_detail.is_none()
            }
            CosmeticPayload::LightProcedural { .. } => cosmetic.action_detail.is_none(),
            CosmeticPayload::VettedScriptlet {
                resource_digest, ..
            } => *resource_digest != [0; 32],
        },
    }
}

/// Verifies a local rewrite group against the real engine before it is applied.
pub fn network_equivalence(before: &[String], after: &str, permissions: u8) -> Result<bool> {
    let before_lists: Vec<(String, u8)> = before
        .iter()
        .map(|text| (text.clone(), permissions))
        .collect();
    let before_engine = build_engine(&before_lists, &[], true);
    let after_engine = build_engine(&candidate_lists(after, permissions), &[], true);
    let corpus = corpus_for_texts(std::iter::once(after).chain(before.iter().map(String::as_str)));
    for case in &corpus {
        let Ok(request) = Request::new(&case.url, &case.source_url, case.request_type, case.method)
        else {
            continue;
        };
        if decision(&before_engine.check_network_request(&request))
            != decision(&after_engine.check_network_request(&request))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn cosmetic_equivalence(before: &[String], after: &str, permissions: u8) -> Result<bool> {
    let before_lists: Vec<(String, u8)> = before
        .iter()
        .map(|text| (text.clone(), permissions))
        .collect();
    let before_engine = build_engine(&before_lists, &[], true);
    let after_engine = build_engine(&candidate_lists(after, permissions), &[], true);
    let hosts = {
        let mut hosts = BTreeSet::new();
        for text in std::iter::once(after).chain(before.iter().map(String::as_str)) {
            if let Some((left, _, _)) = split_cosmetic(text) {
                for host in left.split(',') {
                    if !host.is_empty() && !host.starts_with('~') {
                        hosts.insert(host.trim().to_string());
                    }
                }
            }
        }
        hosts
    };
    for host in hosts {
        let url = format!("https://{host}/");
        if cosmetic_snapshot(&before_engine.url_cosmetic_resources(&url))
            != cosmetic_snapshot(&after_engine.url_cosmetic_resources(&url))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn corpus_for_texts<'a>(texts: impl Iterator<Item = &'a str>) -> Vec<CorpusCase> {
    let mut cases = Vec::new();
    for text in texts {
        let Ok(parsed) = parse_filter(text, false, ParseOptions::default()) else {
            continue;
        };
        let ParsedLine::Network(filter) = parsed else {
            continue;
        };
        let mut urls = Vec::new();
        if let Some(host) = filter.hostname.as_deref() {
            urls.push(format!("https://{host}/rs-probe.js"));
            urls.push(format!("http://{host}/path"));
        }
        if let Some(body) = filter.filter.string_view() {
            let body = body.trim_matches(|c: char| c == '|' || c == '^');
            if !body.is_empty() {
                urls.push(format!("https://neutral.example/path/{body}"));
            }
        }
        for (index, url) in urls.into_iter().enumerate() {
            for source in ["https://site-a.example/", "https://site-b.example/"] {
                for kind in ["script", "image", "document"] {
                    cases.push(CorpusCase {
                        url: url.clone(),
                        source_url: source.to_string(),
                        request_type: kind,
                        method: "GET",
                        label: format!("rewrite:{index}:{source}:{kind}:{text}"),
                    });
                }
            }
        }
    }
    if cases.is_empty() {
        for url in ["https://ads.example/x.js", "https://neutral.example/x.js"] {
            cases.push(CorpusCase {
                url: url.to_string(),
                source_url: "https://site-a.example/".to_string(),
                request_type: "script",
                method: "GET",
                label: format!("rewrite-default:{url}"),
            });
        }
    }
    cases
}

fn split_cosmetic(text: &str) -> Option<(&str, &str, &str)> {
    for separator in ["##", "#@#", "#?#"] {
        if let Some(index) = text.find(separator) {
            return Some((&text[..index], separator, &text[index + separator.len()..]));
        }
    }
    None
}

#[allow(dead_code)]
fn unused_reason(_: ExclusionReason) {}
