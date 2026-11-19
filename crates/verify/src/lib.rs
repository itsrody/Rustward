//! Differential verification and benchmarks using the real `adblock-rust` engine.

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions, ParsedLine, parse_filter},
    request::Request,
    resources::{PermissionMask, Resource},
};
use anyhow::Result;
use model::{
    BenchReport, Config, CosmeticPayload, Eligibility, ExclusionReason, Mismatch, RewriteReceipt,
    Rule, VerifyCoverage, VerifyReport,
};
use serde::Serialize;
use std::{collections::BTreeSet, time::Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub blocked: bool,
    pub important: bool,
    pub exception: bool,
    pub redirect: Option<String>,
    pub rewritten_url: Option<String>,
    pub csp: Option<String>,
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
    receipts: &[RewriteReceipt],
) -> Result<VerifyReport> {
    let admitted = build_engine(&admitted_lists(admitted_rules), resources, true);
    let candidate = build_engine(
        &candidate_lists(candidate_text, config.engine.permissions),
        resources,
        true,
    );
    let (mut corpus, network_rules_probed) =
        generate_corpus(admitted_rules, config.verify.max_cases);
    let (receipt_corpus, rewrite_receipts_exercised) =
        generate_receipt_corpus(receipts, config.verify.max_cases);
    corpus.extend(receipt_corpus);
    let mut mismatches = Vec::new();

    for case in &corpus {
        let request =
            match Request::new(&case.url, &case.source_url, case.request_type, case.method) {
                Ok(request) => request,
                Err(_) => continue,
            };
        let before = decision(&admitted, &request);
        let after = decision(&candidate, &request);
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

    let cosmetic_hosts = cosmetic_hosts(admitted_rules);
    let cosmetic_hosts_total = cosmetic_hosts.len();
    let selected_hosts = stride_sample(
        cosmetic_hosts.into_iter().collect(),
        config.verify.max_cosmetic_hosts.max(1),
    );
    let cosmetic_hosts_checked = selected_hosts.len();
    for host in selected_hosts {
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

    let network_rules_total = admitted_rules
        .iter()
        .filter(|rule| matches!(rule, Rule::Network(_)))
        .count();
    let golden_rule_violations = candidate_rules
        .iter()
        .filter(|rule| !passes_golden_rule(rule, config))
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
        coverage: VerifyCoverage {
            network_rules_total,
            network_rules_probed,
            rewrite_receipts_total: receipts.len(),
            rewrite_receipts_exercised,
            cosmetic_hosts_total,
            cosmetic_hosts_checked,
        },
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

    let (corpus, _) = generate_corpus(admitted_rules, config.verify.max_cases);
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

/// Full observable engine decision for one request. Exceptions are forced so that an
/// explicit `@@` rule is visible even when no blocking rule matched; CSP directives are
/// read separately because the engine exposes them through a dedicated API.
fn decision(engine: &Engine, request: &Request) -> Decision {
    let result = engine.check_network_request_subset(request, false, true);
    Decision {
        blocked: result.should_block(),
        important: result.important,
        exception: result.exception.is_some(),
        redirect: result.redirect.clone(),
        rewritten_url: result.rewritten_url.clone(),
        csp: engine.get_csp_directives(request),
    }
}

const NEGATIVE_TYPES: [&str; 10] = [
    "script",
    "image",
    "document",
    "subdocument",
    "stylesheet",
    "font",
    "media",
    "xmlhttprequest",
    "fetch",
    "ping",
];

const REQUEST_TYPE_BITS: [(&str, u32); 13] = [
    ("image", 1 << 0),
    ("media", 1 << 1),
    ("object", 1 << 2),
    ("other", 1 << 3),
    ("ping", 1 << 4),
    ("script", 1 << 5),
    ("stylesheet", 1 << 6),
    ("subdocument", 1 << 7),
    ("websocket", 1 << 8),
    ("xmlhttprequest", 1 << 9),
    ("font", 1 << 10),
    ("document", 1 << 29),
    ("fetch", 0),
];

const METHOD_BITS: [(&str, u32); 3] = [("GET", 1 << 26), ("HEAD", 1 << 27), ("POST", 1 << 30)];

fn generate_corpus(rules: &[Rule], max_cases: usize) -> (Vec<CorpusCase>, usize) {
    let max_cases = max_cases.max(1);
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    let mut probed_rules = BTreeSet::new();

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

    // Unconditional negative probes stay even when the corpus budget is small.
    for host in [
        "example.org",
        "news.example.net",
        "site-a.example",
        "site-b.example",
        "neutral.example",
    ] {
        for kind in NEGATIVE_TYPES {
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
        push(
            &mut cases,
            &mut seen,
            format!("negative:{host}:query"),
            format!("https://{host}/benign.js?utm_source=rs&keep=1"),
            "https://example.org/".to_string(),
            "document",
            "GET",
        );
    }

    let network_rules: Vec<&model::NetworkRule> = rules
        .iter()
        .filter_map(|rule| match rule {
            Rule::Network(network) if !network.is_badfilter => Some(network),
            _ => None,
        })
        .collect();
    let budget = max_cases.saturating_sub(cases.len());
    let stride = (network_rules.len() / budget.max(1)).max(1);
    let per_rule_limit = (budget / network_rules.len().max(1)).clamp(1, 24);

    // Sampling by stride covers every source instead of only the first lists.
    for (index, network) in network_rules.iter().enumerate() {
        if cases.len() >= max_cases {
            break;
        }
        if index % stride != 0 {
            continue;
        }

        let urls = rule_urls(network);
        let sources = rule_sources(network);
        let kinds = if network.is_csp {
            vec!["document", "subdocument"]
        } else {
            mask_types(network.mask)
        };
        let methods = mask_methods(network.mask);
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

            // Special-action probes come first: they exercise important, explicit
            // exceptions, CSP, redirect, and removeparam paths even at a one-case budget.
            if network.important
                || network.is_exception
                || network.is_csp
                || network.is_redirect
                || network.is_removeparam
            {
                for (url_index, url) in urls.iter().take(2).enumerate() {
                    for source in sources.iter().take(3) {
                        for kind in kinds.iter().take(2) {
                            for method in methods.iter().take(2) {
                                push_rule(
                                    format!(
                                        "special:{}:{}:{url_index}:{source}:{kind}:{method}",
                                        network.source_id, network.line_no
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

            // $domain/$from and $to matrices: target host and initiator are varied
            // independently so partially rewrites cannot hide a domain regression.
            let has_domain_matrix = !network.domains.is_empty()
                || !network.not_domains.is_empty()
                || !network.to_domains.is_empty()
                || !network.not_to_domains.is_empty();
            if has_domain_matrix {
                for (url_index, url) in urls.iter().take(3).enumerate() {
                    for source in sources.iter().take(6) {
                        for kind in kinds.iter().take(2) {
                            for method in methods.iter().take(2) {
                                push_rule(
                                    format!(
                                        "matrix:{}:{}:{url_index}:{source}:{kind}:{method}",
                                        network.source_id, network.line_no
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

            for (url_index, url) in urls.iter().take(2).enumerate() {
                for source in sources.iter().take(3) {
                    for kind in kinds.iter().take(3) {
                        for method in methods.iter().take(2) {
                            push_rule(
                                format!(
                                    "general:{}:{}:{url_index}:{source}:{kind}:{method}",
                                    network.source_id, network.line_no
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
        let sampled = prioritized_sample(rule_cases, per_rule_limit);
        if !sampled.is_empty() {
            probed_rules.insert(network.engine_id);
        }
        cases.extend(sampled);
    }

    cases.truncate(max_cases);
    (cases, probed_rules.len())
}

fn mask_types(mask: u32) -> Vec<&'static str> {
    let mut types: Vec<&'static str> = REQUEST_TYPE_BITS
        .iter()
        .filter(|(_, bit)| *bit != 0 && mask & bit != 0)
        .map(|(kind, _)| *kind)
        .collect();
    if types.is_empty() {
        types.extend(["script", "image", "document", "xmlhttprequest"]);
    }
    types
}

fn mask_methods(mask: u32) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = METHOD_BITS
        .iter()
        .filter(|(_, bit)| mask & bit != 0)
        .map(|(method, _)| *method)
        .collect();
    if methods.is_empty() {
        methods.extend(["GET", "HEAD", "POST"]);
    }
    methods
}

fn rule_urls(rule: &model::NetworkRule) -> Vec<String> {
    let mut urls = Vec::new();
    let scheme = if rule.mask & (1 << 12) != 0 {
        "https"
    } else if rule.mask & (1 << 11) != 0 {
        "http"
    } else {
        "https"
    };

    if let Some(host) = &rule.hostname {
        push_unique(&mut urls, format!("{scheme}://{host}/rs-probe.js"));
        push_unique(&mut urls, format!("{scheme}://{host}/path?q=1"));
        push_unique(&mut urls, format!("{scheme}://sub.{host}/"));
    }
    for host in rule
        .to_domains
        .iter()
        .chain(rule.not_to_domains.iter())
        .take(4)
    {
        let host = host.trim_start_matches('~');
        push_unique(&mut urls, format!("{scheme}://{host}/rs-probe.js"));
    }
    if !rule.body.is_empty() && !rule.is_regex {
        let body = rule.body.trim_matches(|c: char| c == '|' || c == '^');
        if !body.is_empty() {
            push_unique(&mut urls, format!("{scheme}://neutral.example/path/{body}"));
            push_unique(&mut urls, format!("{scheme}://neutral.example/?q={body}"));
        }
    }
    if rule.is_removeparam {
        for param in removeparam_params(rule) {
            push_unique(
                &mut urls,
                format!("{scheme}://neutral.example/path?{param}=rs1&keep=1"),
            );
            push_unique(
                &mut urls,
                format!("{scheme}://neutral.example/path?keep=1&{param}=rs2"),
            );
            push_unique(
                &mut urls,
                format!("{scheme}://neutral.example/path?{param}="),
            );
        }
    }
    if urls.is_empty() {
        push_unique(&mut urls, format!("{scheme}://neutral.example/rs-probe.js"));
    }
    urls
}

fn removeparam_params(rule: &model::NetworkRule) -> Vec<String> {
    let mut params = Vec::new();
    if let Some(modifier) = &rule.modifier_option {
        let raw = modifier
            .strip_prefix("removeparam=")
            .unwrap_or(modifier.as_str());
        for part in raw.split('|') {
            let name = part.trim();
            if !name.is_empty()
                && !name.starts_with('/')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                push_unique(&mut params, name.to_string());
            }
        }
    }
    if params.is_empty() {
        params.extend(["utm_source".to_string(), "fbclid".to_string()]);
    }
    params
}

fn rule_sources(rule: &model::NetworkRule) -> Vec<String> {
    let mut sources = vec![
        "https://site-a.example/".to_string(),
        "https://site-b.example/".to_string(),
        "https://neutral.example/".to_string(),
    ];
    for domain in rule.domains.iter().chain(rule.not_domains.iter()).take(6) {
        let domain = domain.trim_start_matches('~');
        push_unique(&mut sources, format!("https://{domain}/"));
    }
    sources
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn prioritized_sample(cases: Vec<CorpusCase>, limit: usize) -> Vec<CorpusCase> {
    if cases.len() <= limit || limit == 0 {
        return cases;
    }
    let mut result = Vec::with_capacity(limit);
    let special_count = (limit / 2).max(1).min(cases.len());
    for case in cases.iter().take(special_count) {
        result.push(case.clone());
    }
    for case in evenly_sample(cases, limit) {
        if result.len() >= limit {
            break;
        }
        if !result.iter().any(|selected| selected.label == case.label) {
            result.push(case);
        }
    }
    result
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

/// Select at most `limit` values evenly across the whole input, so a capped probe set still
/// covers every source instead of only the lexicographically first ones.
fn stride_sample<T: Clone>(values: Vec<T>, limit: usize) -> Vec<T> {
    if values.len() <= limit || limit == 0 {
        return values;
    }
    let step = values.len() / limit;
    (0..limit)
        .filter_map(|index| values.get(index * step).cloned())
        .collect()
}

/// Build one or two targeted differential probes from every rewrite receipt. Global rule
/// sampling alone can miss a rewrite entirely when its removed rule is not selected.
fn generate_receipt_corpus(receipts: &[RewriteReceipt], budget: usize) -> (Vec<CorpusCase>, usize) {
    if budget == 0 || receipts.is_empty() {
        return (Vec::new(), 0);
    }
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    let mut exercised = 0;
    let stride = (receipts.len() / budget).max(1);
    for (index, receipt) in receipts.iter().enumerate() {
        if cases.len() >= budget {
            break;
        }
        if index % stride != 0 {
            continue;
        }
        let mut added = false;
        for (side, text) in receipt
            .before
            .iter()
            .map(|text| ("before", text))
            .chain(std::iter::once(("after", &receipt.after)))
        {
            let Ok(parsed) = parse_filter(text, false, ParseOptions::default()) else {
                continue;
            };
            let ParsedLine::Network(filter) = parsed else {
                continue;
            };
            let mut urls = Vec::new();
            if let Some(host) = filter.hostname.as_deref() {
                urls.push(format!("https://{host}/rs-probe.js"));
            }
            if let Some(body) = filter.filter.string_view() {
                let body = body.trim_matches(|c: char| c == '|' || c == '^');
                if !body.is_empty() {
                    urls.push(format!("https://neutral.example/path/{body}"));
                }
            }
            for (url_index, url) in urls.into_iter().take(2).enumerate() {
                for kind in ["script", "image"] {
                    let label = format!(
                        "receipt:{}:{}:{side}:{url_index}:{kind}",
                        receipt.id, receipt.family
                    );
                    if seen.insert(label.clone()) {
                        cases.push(CorpusCase {
                            url: url.clone(),
                            source_url: format!("https://{}.example/", receipt.source_id),
                            request_type: kind,
                            method: "GET",
                            label,
                        });
                        added = true;
                    }
                }
            }
            if cases.len() >= budget {
                break;
            }
        }
        if added {
            exercised += 1;
        }
    }
    (cases, exercised)
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
    let mut preamble = String::new();
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in script.lines() {
        match &mut current {
            None => {
                if line == "try {" {
                    current = Some(vec![line]);
                } else {
                    preamble.push_str(line);
                    preamble.push('\n');
                }
            }
            Some(block) => {
                block.push(line);
                if line == "} catch ( e ) { }" {
                    let mut text = block.join("\n");
                    text.push('\n');
                    blocks.push(text);
                    current = None;
                }
            }
        }
    }
    if current.is_some() || blocks.is_empty() {
        return script.to_string();
    }
    blocks.sort();
    let mut result = normalize_declarations(&preamble);
    result.push_str(&blocks.concat());
    result
}

/// Dependency declarations are concatenated in engine list order. Sort the independent
/// top-level function/class declarations so re-emitted rule order does not change the
/// scriptlet payload.
fn normalize_declarations(preamble: &str) -> String {
    let mut leading = String::new();
    let mut declarations = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in preamble.lines() {
        if is_top_level_declaration(line) {
            if let Some(previous) = current.take() {
                declarations.push(join_lines(&previous));
            }
            current = Some(vec![line]);
        } else if let Some(block) = &mut current {
            block.push(line);
        } else {
            leading.push_str(line);
            leading.push('\n');
        }
    }
    if let Some(last) = current {
        declarations.push(join_lines(&last));
    }
    if declarations.is_empty() {
        return preamble.to_string();
    }
    declarations.sort();
    leading.push_str(&declarations.concat());
    leading
}

fn is_top_level_declaration(line: &str) -> bool {
    line.starts_with("function ")
        || line.starts_with("async function ")
        || line.starts_with("class ")
}

fn join_lines(lines: &[&str]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

fn passes_golden_rule(rule: &Rule, config: &Config) -> bool {
    if rule.eligibility() != &Eligibility::Eligible {
        return false;
    }
    if rule
        .family()
        .is_some_and(|family| config.admit.exclude_families.contains(&family))
    {
        return false;
    }
    if rule
        .unaccepted_semantic_gap(&config.admit.accepted_semantic_gaps)
        .is_some()
    {
        return false;
    }
    match rule {
        Rule::Network(network) => {
            let regex_ok = !network.is_complete_regex
                && !network.is_hostname_regex
                && (!network.is_regex
                    || (config.admit.literal_boundary_regex && network.is_literal_boundary_regex));
            regex_ok
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
        if decision(&before_engine, &request) != decision(&after_engine, &request) {
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

/// Extracts literal domain values from named `$` options in raw rule text. Entity
/// domains (`.*`) and negations (`~`) are normalized; the engine remains authoritative
/// for semantics, this only supplies initiator/target hosts for differential probes.
fn option_domain_values(text: &str, keys: &[&str]) -> Vec<String> {
    let Some((_, options)) = text.rsplit_once('$') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for option in options.split(',') {
        let option = option.trim().trim_start_matches('~');
        for key in keys {
            let Some(value) = option
                .strip_prefix(*key)
                .and_then(|rest| rest.strip_prefix('='))
            else {
                continue;
            };
            for domain in value.split('|') {
                let domain = domain.trim().trim_start_matches('~').trim_end_matches(".*");
                if domain.contains('.') && !domain.contains('*') {
                    out.push(domain.to_string());
                }
            }
        }
    }
    out
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
                urls.push(format!("https://neutral.example/path?{body}=1&keep=1"));
            }
        }
        // Include `$to=` domains as target hosts and `$domain=`/`$from=` domains as
        // initiators. Without these, a domain-restricted rule never fires in the
        // differential corpus and an unsafe rewrite could pass trivially.
        for domain in option_domain_values(text, &["to"]) {
            urls.push(format!("https://{domain}/rs-probe.js"));
        }
        let mut sources: Vec<String> = vec![
            "https://site-a.example/".to_string(),
            "https://site-b.example/".to_string(),
        ];
        for domain in option_domain_values(text, &["domain", "from"]) {
            sources.push(format!("https://{domain}/"));
        }
        for (index, url) in urls.into_iter().enumerate() {
            for source in &sources {
                for kind in mask_types(filter.mask.bits()) {
                    for method in mask_methods(filter.mask.bits()) {
                        cases.push(CorpusCase {
                            url: url.clone(),
                            source_url: source.clone(),
                            request_type: kind,
                            method,
                            label: format!("rewrite:{index}:{source}:{kind}:{method}:{text}"),
                        });
                    }
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
