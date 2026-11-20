//! Engine-backed parsing, directive evaluation, and canonical IR conversion.

use adblock::{
    filters::{
        cosmetic::{CosmeticFilterAction, CosmeticFilterMask, CosmeticFilterOperator},
        network::NetworkFilterMaskHelper,
    },
    lists::{FilterFormat, ParseOptions, ParsedLine, parse_filter},
    resources::PermissionMask,
};
use anyhow::{Context, Result};
use fetch::FetchedSource;
use model::{
    Config, Dialect, DialectGap, ExclusionReason, FastOperator, GapClass, HideOrUnhide,
    NetworkRule, Origin, ParsedOutcome, ParsedRecord, RewriteReceipt, Rule, RuleState,
    SourceFormat,
    model::{CosmeticPayload, CosmeticRule},
    util::{has_safe_literal_escapes, sha256_digest, sha256_hex, sorted_unique},
};
use std::{collections::HashMap, fs, path::Path};

#[derive(Debug, Clone)]
pub struct EffectiveLine {
    line_no: usize,
    /// Text after directive expansion and preparse normalization.
    text: String,
    /// Original upstream text, retained for provenance and exclusion reports.
    raw_text: String,
}

/// Expands `!#if`/`!#else`/`!#endif` and `!#include` for the pinned target profile.
pub fn evaluate_directives(
    source: &FetchedSource,
    root: &Path,
    config: &Config,
) -> Result<Vec<EffectiveLine>> {
    if !config.directives.enabled {
        return Ok(source
            .text
            .lines()
            .enumerate()
            .map(|(index, text)| EffectiveLine {
                line_no: index + 1,
                text: text.to_string(),
                raw_text: text.to_string(),
            })
            .collect());
    }
    evaluate_text(&source.text, source, root, config, &mut Vec::new())
}

fn evaluate_text(
    text: &str,
    source: &FetchedSource,
    root: &Path,
    config: &Config,
    seen_includes: &mut Vec<String>,
) -> Result<Vec<EffectiveLine>> {
    #[derive(Clone)]
    struct Frame {
        parent_active: bool,
        branch_active: bool,
        any_taken: bool,
        else_seen: bool,
    }

    fn active(stack: &[Frame]) -> bool {
        stack.iter().all(|frame| frame.branch_active)
    }

    let mut output = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(expr) = trimmed.strip_prefix("!#if ") {
            if active(&stack) {
                let parent_active = active(&stack);
                let branch_active = parent_active && eval_expr(expr, &config.directives.env);
                stack.push(Frame {
                    parent_active,
                    branch_active,
                    any_taken: branch_active,
                    else_seen: false,
                });
            }
            continue;
        }
        if trimmed == "!#else" {
            if let Some(frame) = stack.last_mut() {
                let should_take = frame.parent_active && !frame.any_taken && !frame.else_seen;
                frame.branch_active = should_take;
                frame.any_taken |= should_take;
                frame.else_seen = true;
            }
            continue;
        }
        if trimmed == "!#endif" {
            stack.pop();
            continue;
        }
        if let Some(include) = trimmed.strip_prefix("!#include ") {
            if active(&stack) {
                let include_path = include.trim().trim_matches('"');
                let (included, key) = if let Some(fetched) = source.includes.get(include_path) {
                    (fetched.text.clone(), fetched.url.clone())
                } else {
                    let root_dir = config
                        .directives
                        .include_root
                        .as_ref()
                        .map(|path| root.join(path))
                        .unwrap_or_else(|| root.to_path_buf());
                    let resolved = root_dir.join(include_path);
                    let canonical = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
                    let bytes = fs::read(&canonical)
                        .with_context(|| format!("failed to read !#include {include_path}"))?;
                    (
                        String::from_utf8(bytes)?,
                        canonical.to_string_lossy().to_string(),
                    )
                };
                if seen_includes.contains(&key) {
                    anyhow::bail!("recursive !#include: {key}");
                }
                seen_includes.push(key);
                let nested = evaluate_text(&included, source, root, config, seen_includes)?;
                seen_includes.pop();
                output.extend(nested);
            }
            continue;
        }
        if active(&stack) {
            output.push(EffectiveLine {
                line_no: index + 1,
                text: line.to_string(),
                raw_text: line.to_string(),
            });
        }
    }
    Ok(output)
}

fn eval_expr(expr: &str, env: &[String]) -> bool {
    expr.split("||")
        .any(|term| term.split("&&").all(|atom| eval_atom(atom, env)))
}

fn eval_atom(atom: &str, env: &[String]) -> bool {
    let mut atom = atom.trim();
    while atom.starts_with('(') && atom.ends_with(')') {
        atom = atom[1..atom.len() - 1].trim();
    }
    if let Some(rest) = atom.strip_prefix('!') {
        return !eval_atom(rest, env);
    }
    if matches!(atom, "true" | "1") || env.iter().any(|value| value == atom) {
        return true;
    }
    // uBO directives use `env_chromium`, `ext_ublock`, and similar prefixes. The profile config
    // stores the bare capability names, so accept either spelling.
    if let Some((prefix, capability)) = atom.split_once('_') {
        if matches!(prefix, "env" | "ext" | "cap" | "platform") {
            return env.iter().any(|value| value == capability || value == atom);
        }
    }
    false
}

pub fn parse_sources(
    sources: &[FetchedSource],
    root: &Path,
    config: &Config,
) -> Result<Vec<ParsedRecord>> {
    let mut records = Vec::new();
    for source in sources {
        let lines = evaluate_directives(source, root, config)?;
        for line in lines {
            records.push(parse_line(source, line, config)?);
        }
    }
    Ok(records)
}

fn parse_line(
    source: &FetchedSource,
    line: EffectiveLine,
    config: &Config,
) -> Result<ParsedRecord> {
    let trimmed = line.text.trim();
    let origin = || Origin {
        source_id: source.config.id.clone(),
        line_no: line.line_no,
        text: line.raw_text.clone(),
    };
    let base = |outcome| ParsedRecord {
        source_id: source.config.id.clone(),
        line_no: line.line_no,
        raw_text: line.raw_text.clone(),
        effective_text: Some(line.text.clone()),
        dialect: effective_dialect(&source.config),
        outcome,
        preparse_receipts: Vec::new(),
        baseline_rule: None,
    };

    if trimmed.is_empty() {
        return Ok(base(ParsedOutcome::Empty));
    }
    if trimmed.starts_with("!#") {
        return Ok(base(ParsedOutcome::Directive));
    }
    if trimmed.starts_with('!')
        || trimmed.starts_with("[Adblock")
        || (trimmed.starts_with('#') && trimmed[1..].starts_with(char::is_whitespace))
    {
        let outcome = if trimmed.starts_with("! Title:")
            || trimmed.starts_with("! Description:")
            || trimmed.starts_with("! Homepage:")
            || trimmed.starts_with("! License:")
        {
            ParsedOutcome::Metadata
        } else {
            ParsedOutcome::Comment
        };
        return Ok(base(outcome));
    }

    let format = match source.config.format {
        SourceFormat::Hosts => FilterFormat::Hosts,
        SourceFormat::Standard => FilterFormat::Standard,
    };
    let opts = ParseOptions {
        format,
        rule_types: Default::default(),
        permissions: PermissionMask::from_bits(source.config.permissions),
    };

    match parse_filter(trimmed, true, opts) {
        Ok(ParsedLine::Network(filter)) => {
            let body = filter.filter.string_view().unwrap_or_default();
            let is_regex = filter.is_regex();
            let is_literal_boundary_regex = is_regex
                && !filter.is_complete_regex()
                && !filter
                    .mask
                    .contains(adblock::filters::network::NetworkFilterMask::IS_HOSTNAME_REGEX)
                && is_literal_boundary_body(&body);
            let canonical_text = if matches!(format, FilterFormat::Hosts) {
                hosts_canonical_text(trimmed).unwrap_or_else(|| trimmed.to_string())
            } else {
                trimmed.to_string()
            };
            let options = parse_network_options(&canonical_text);
            let (domains, not_domains) =
                collect_domain_values(options.as_ref(), &["domain", "from"]);
            let (to_domains, not_to_domains) = collect_domain_values(options.as_ref(), &["to"]);
            let rule = NetworkRule {
                engine_id: filter.get_id(),
                mask: filter.mask.bits(),
                features: filter.features_mask.bits(),
                hostname: filter.hostname.as_deref().map(str::to_string),
                body: filter.filter.string_view().unwrap_or_default(),
                left_anchor: filter.is_left_anchor(),
                right_anchor: filter.is_right_anchor(),
                hostname_anchor: filter.is_hostname_anchor(),
                is_regex,
                is_literal_boundary_regex,
                is_complete_regex: filter.is_complete_regex(),
                is_hostname_regex: filter
                    .mask
                    .contains(adblock::filters::network::NetworkFilterMask::IS_HOSTNAME_REGEX),
                is_exception: filter.is_exception(),
                important: filter.is_important(),
                match_case: filter.match_case(),
                is_badfilter: filter.is_badfilter(),
                is_redirect: filter.is_redirect(),
                is_csp: filter.is_csp(),
                is_removeparam: filter.is_removeparam(),
                is_generic_hide: filter.is_generic_hide(),
                domains,
                not_domains,
                to_domains,
                not_to_domains,
                domain_hashes: hash_all(&filter.opt_domains),
                not_domain_hashes: hash_all(&filter.opt_not_domains),
                to_domain_hashes: hash_all(&filter.opt_to_domains),
                not_to_domain_hashes: hash_all(&filter.opt_not_to_domains),
                modifier_option: filter.modifier_option.map(str::to_string),
                tag: option_value(options.as_ref(), "tag"),
                text: canonical_text,
                source_id: source.config.id.clone(),
                line_no: line.line_no,
                dialect: effective_dialect(&source.config),
                source_trusted: source.config.trusted,
                source_permissions: source.config.permissions,
                source_priority: source.config.priority,
                eligibility: model::Eligibility::Eligible,
                state: model::RuleState::Active,
                dialect_gaps: detect_network_gaps(trimmed, &source.config),
                provenance: vec![origin()],
            };
            Ok(base(ParsedOutcome::Network(rule)))
        }
        Ok(ParsedLine::Cosmetic(filter)) => {
            let rule = build_cosmetic_rule(source, &line, &filter, config, origin());
            Ok(base(ParsedOutcome::Cosmetic(rule)))
        }
        Err(error) => {
            if let Some((rule, baseline_rule, receipt)) =
                normalize_literal_contains(trimmed, source, &line, opts, config)?
            {
                let mut record = base(ParsedOutcome::Cosmetic(rule));
                record.preparse_receipts.push(receipt);
                record.baseline_rule = Some(baseline_rule);
                return Ok(record);
            }
            let reason = classify_parse_error(trimmed, &error.to_string());
            let gap = detect_gap_for_error(trimmed);
            Ok(base(ParsedOutcome::Unsupported { reason, gap }))
        }
    }
}

/// The engine flags any pattern containing `^` or `*` as `IS_REGEX`, but those are adblock's
/// separator and wildcard tokens, not user-authored regular expressions. A body whose only
/// special token is `^` compiles to a bounded literal + separator matcher, which is safe to
/// admit once the complete-regex and hostname-wildcard families have been excluded.
fn is_literal_boundary_body(body: &str) -> bool {
    // adblock escapes punctuation when compiling a non-complete pattern, so only backslash escapes
    // that invoke real regex syntax (\d, \n, \p{...}, …) make this family unsafe. Redundant
    // punctuation escapes are canonicalized away by `network_canonicalization` before emission.
    body.contains('^') && !body.contains('*') && has_safe_literal_escapes(body)
}

const CONTAINS_MARKERS: &[&str] = &[":-abp-contains(", ":contains("];

/// Replaces a single literal `:contains(...)` / `:-abp-contains(...)` with `:has-text(...)`.
/// Regex arguments, nested operators, and multiple procedural markers are left for normal
/// admission/gap handling instead of being silently rewritten.
fn replace_literal_contains(selector: &str) -> Option<String> {
    let mut found = None;
    for marker in CONTAINS_MARKERS {
        if let Some(position) = selector.find(marker) {
            found = Some((position, *marker));
            break;
        }
    }
    let (position, marker) = found?;
    let tail = &selector[position + marker.len()..];
    if CONTAINS_MARKERS
        .iter()
        .any(|other| tail.contains(other.trim_end_matches('(')))
    {
        return None;
    }
    let (argument, close) = parse_paren_argument(tail)?;
    if !model::util::is_literal_arg(argument.trim()) {
        return None;
    }
    let mut output = String::with_capacity(selector.len() + 6);
    output.push_str(&selector[..position]);
    output.push_str(":has-text(");
    output.push_str(argument);
    output.push(')');
    output.push_str(&tail[close + 1..]);
    Some(output)
}

fn parse_paren_argument(text: &str) -> Option<(&str, usize)> {
    let mut depth = 1usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&text[..index], index));
                }
            }
            _ => {}
        }
    }
    None
}

/// D6: prepare a literal `:contains(...)` cosmetic rule for ADMIT. The original is kept as an ABP
/// extended (`#?#`) baseline rule so VERIFY compares engine behavior, not just the rewritten text.
fn normalize_literal_contains(
    text: &str,
    source: &FetchedSource,
    line: &EffectiveLine,
    opts: ParseOptions,
    config: &Config,
) -> Result<Option<(CosmeticRule, Rule, RewriteReceipt)>> {
    if !config.admit.literal_contains_rewrite {
        return Ok(None);
    }
    let Some((host_part, separator, selector)) = split_cosmetic(text) else {
        return Ok(None);
    };
    if separator != "##" || host_part.trim().is_empty() || selector.contains("+js(") {
        return Ok(None);
    }
    let Some(normalized_selector) = replace_literal_contains(selector) else {
        return Ok(None);
    };
    let candidate = format!("{host_part}{separator}{normalized_selector}");
    let Ok(adblock::lists::ParsedLine::Cosmetic(filter)) = parse_filter(&candidate, true, opts)
    else {
        return Ok(None);
    };
    let candidate_line = EffectiveLine {
        line_no: line.line_no,
        text: candidate.clone(),
        raw_text: line.raw_text.clone(),
    };
    let origin = || Origin {
        source_id: source.config.id.clone(),
        line_no: line.line_no,
        text: line.raw_text.clone(),
    };
    let candidate_rule = build_cosmetic_rule(source, &candidate_line, &filter, config, origin());
    if candidate_rule.script_inject
        || candidate_rule.action_detail.is_some()
        || candidate_rule.action != HideOrUnhide::Hide
        || (candidate_rule.hosts.is_empty() && candidate_rule.entities.is_empty())
        || candidate_rule.selector_ops != ["css-selector", "has-text"]
        || candidate_rule
            .dialect_gaps
            .iter()
            .any(|gap| gap.class == GapClass::Unsupported)
        || !matches!(
            &candidate_rule.payload,
            CosmeticPayload::LightProcedural {
                op: FastOperator::HasText(_),
                ..
            }
        )
    {
        return Ok(None);
    }
    if !verify::literal_contains_equivalence(text, &candidate, source.config.permissions)? {
        return Ok(None);
    }

    let probe = format!("{host_part}#?#{selector}");
    let Ok(adblock::lists::ParsedLine::Cosmetic(baseline_filter)) =
        parse_filter(&probe, true, opts)
    else {
        return Ok(None);
    };
    let baseline_line = EffectiveLine {
        line_no: line.line_no,
        text: probe,
        raw_text: line.raw_text.clone(),
    };
    let baseline_rule =
        build_cosmetic_rule(source, &baseline_line, &baseline_filter, config, origin());

    let id = format!("d6_literal_contains-{}", &sha256_hex(text.as_bytes())[..12]);
    let mut admitted = candidate_rule;
    admitted.state = RuleState::Rewritten(id.clone());
    let receipt = RewriteReceipt {
        id,
        family: "d6_literal_contains".to_string(),
        before: vec![text.to_string()],
        after: candidate,
        source_id: source.config.id.clone(),
        checks: vec![
            "reparse-equal".to_string(),
            "engine-differential".to_string(),
            "golden-rule-postcondition".to_string(),
        ],
    };
    Ok(Some((admitted, Rule::Cosmetic(baseline_rule), receipt)))
}

fn effective_dialect(source: &model::SourceConfig) -> Dialect {
    if source.format == SourceFormat::Hosts {
        Dialect::Hosts
    } else {
        source.dialect
    }
}

fn hosts_canonical_text(text: &str) -> Option<String> {
    let without_comment = text.split('#').next().unwrap_or(text).trim();
    let mut parts = without_comment.split_whitespace();
    let first = parts.next()?;
    let host = parts.next().unwrap_or(first);
    if parts.next().is_some() || host == "localhost" {
        return None;
    }
    Some(format!("||{host}^"))
}

fn hash_all(values: &Option<Vec<u64>>) -> Vec<u64> {
    let mut values = values.clone().unwrap_or_default();
    values.sort_unstable();
    values
}

#[derive(Debug, Clone)]
struct ParsedNetworkOption {
    name: String,
    value: Option<String>,
    negated: bool,
}

#[derive(Debug, Clone)]
struct ParsedNetworkOptions {
    options: Vec<ParsedNetworkOption>,
}

/// Structured `$` option parser. The engine remains authoritative for semantics; this
/// parser only exposes option shape so gap detection does not rely on substring matches.
fn parse_network_options(text: &str) -> Option<ParsedNetworkOptions> {
    let (prefix, raw_options) = text.rsplit_once('$')?;
    if prefix.contains('$') || raw_options.is_empty() || raw_options.contains('$') {
        return None;
    }
    let mut options = Vec::new();
    for item in raw_options.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (negated, item) = match item.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        let (name, value) = match item.split_once('=') {
            Some((name, value)) if !name.is_empty() && !value.is_empty() => {
                (name.to_ascii_lowercase(), Some(value.to_string()))
            }
            Some((name, _)) if name.is_empty() => return None,
            _ => (item.to_ascii_lowercase(), None),
        };
        options.push(ParsedNetworkOption {
            name,
            value,
            negated,
        });
    }
    if options.is_empty() {
        None
    } else {
        Some(ParsedNetworkOptions { options })
    }
}

fn option_value(options: Option<&ParsedNetworkOptions>, key: &str) -> Option<String> {
    options?
        .options
        .iter()
        .find(|option| option.name == key && !option.negated)
        .and_then(|option| option.value.clone())
}

fn collect_domain_values(
    options: Option<&ParsedNetworkOptions>,
    keys: &[&str],
) -> (Vec<String>, Vec<String>) {
    let mut positive = Vec::new();
    let mut negative = Vec::new();
    let Some(options) = options else {
        return (positive, negative);
    };
    for option in &options.options {
        if !keys.contains(&option.name.as_str()) {
            continue;
        }
        let Some(value) = &option.value else {
            continue;
        };
        for item in value.split('|') {
            if let Some(host) = item.strip_prefix('~') {
                negative.push(host.to_ascii_lowercase());
            } else {
                positive.push(item.to_ascii_lowercase());
            }
        }
    }
    sorted_unique(&mut positive);
    sorted_unique(&mut negative);
    (positive, negative)
}

fn build_cosmetic_rule(
    source: &FetchedSource,
    line: &EffectiveLine,
    filter: &adblock::filters::cosmetic::CosmeticFilter,
    config: &Config,
    origin: Origin,
) -> CosmeticRule {
    let (host_part, separator, payload_part) = split_cosmetic(&line.text).unwrap_or_default();
    let (mut hosts, mut not_hosts, mut entities, mut not_entities) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for item in host_part
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (negated, value) = match item.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        if let Some(entity) = value.strip_suffix(".*") {
            if negated {
                not_entities.push(entity.to_ascii_lowercase());
            } else {
                entities.push(entity.to_ascii_lowercase());
            }
        } else if negated {
            not_hosts.push(value.to_ascii_lowercase());
        } else {
            hosts.push(value.to_ascii_lowercase());
        }
    }
    sorted_unique(&mut hosts);
    sorted_unique(&mut not_hosts);
    sorted_unique(&mut entities);
    sorted_unique(&mut not_entities);

    let script_inject = filter.mask.contains(CosmeticFilterMask::SCRIPT_INJECT);
    let unhide = filter.mask.contains(CosmeticFilterMask::UNHIDE) || separator.contains('@');
    let action = if unhide {
        HideOrUnhide::Unhide
    } else {
        HideOrUnhide::Hide
    };
    let action_detail = filter.action.as_ref().map(|action| match action {
        CosmeticFilterAction::Remove => "remove".to_string(),
        CosmeticFilterAction::Style(style) => format!("style:{style}"),
        CosmeticFilterAction::RemoveAttr(name) => format!("remove-attr:{name}"),
        CosmeticFilterAction::RemoveClass(name) => format!("remove-class:{name}"),
    });

    let payload = if script_inject {
        let (name, args) = parse_scriptlet_invocation(payload_part);
        CosmeticPayload::VettedScriptlet {
            name,
            args,
            grade: model::ScriptletGrade::Standard,
            resource_digest: [0; 32],
            permission: filter.permission.to_bits(),
        }
    } else {
        classify_selector(&filter.selector, config)
    };

    CosmeticRule {
        hosts,
        not_hosts,
        entities,
        not_entities,
        payload,
        selector_ops: filter.selector.iter().map(operator_name).collect(),
        action,
        action_detail,
        generic: host_part.trim().is_empty(),
        script_inject,
        permission: filter.permission.to_bits(),
        text: line.text.trim().to_string(),
        source_id: source.config.id.clone(),
        line_no: line.line_no,
        dialect: effective_dialect(&source.config),
        source_trusted: source.config.trusted,
        source_permissions: source.config.permissions,
        source_priority: source.config.priority,
        eligibility: model::Eligibility::Eligible,
        state: model::RuleState::Active,
        dialect_gaps: detect_cosmetic_gaps(&line.text),
        provenance: vec![origin],
    }
}

fn split_cosmetic(text: &str) -> Option<(&str, &str, &str)> {
    for separator in ["##", "#@#", "#?#"] {
        if let Some(index) = text.find(separator) {
            return Some((&text[..index], separator, &text[index + separator.len()..]));
        }
    }
    None
}

fn parse_scriptlet_invocation(payload: &str) -> (String, String) {
    let inner = payload
        .trim()
        .strip_prefix("+js(")
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(payload.trim());
    // Official scriptlet names are case-sensitive identifiers. Lowercasing them here
    // silently breaks aliases such as `no-setTimeout-if` and `addEventListener-defuser`.
    match inner.split_once(',') {
        Some((name, args)) => (name.trim().to_string(), args.trim().to_string()),
        None => (inner.trim().to_string(), String::new()),
    }
}

fn operator_name(operator: &CosmeticFilterOperator) -> String {
    match operator {
        CosmeticFilterOperator::CssSelector(_) => "css-selector",
        CosmeticFilterOperator::HasText(_) => "has-text",
        CosmeticFilterOperator::MatchesAttr(_) => "matches-attr",
        CosmeticFilterOperator::MatchesCss(_) => "matches-css",
        CosmeticFilterOperator::MatchesCssBefore(_) => "matches-css-before",
        CosmeticFilterOperator::MatchesCssAfter(_) => "matches-css-after",
        CosmeticFilterOperator::MatchesPath(_) => "matches-path",
        CosmeticFilterOperator::MinTextLength(_) => "min-text-length",
        CosmeticFilterOperator::Upward(_) => "upward",
        CosmeticFilterOperator::Xpath(_) => "xpath",
    }
    .to_string()
}

fn classify_selector(operators: &[CosmeticFilterOperator], config: &Config) -> CosmeticPayload {
    if operators.len() == 1 {
        if let CosmeticFilterOperator::CssSelector(selector) = &operators[0] {
            return CosmeticPayload::NativeCss(selector.clone());
        }
    }
    if operators.len() == 2 {
        if let CosmeticFilterOperator::CssSelector(css) = &operators[0] {
            let op = match &operators[1] {
                CosmeticFilterOperator::HasText(value) => {
                    Some(FastOperator::HasText(value.clone()))
                }
                CosmeticFilterOperator::MatchesAttr(value) => {
                    Some(FastOperator::MatchesAttr(value.clone()))
                }
                _ => None,
            };
            if let Some(op) = op {
                return CosmeticPayload::LightProcedural {
                    css: css.clone(),
                    op,
                };
            }
        }
    }
    let detail = operators
        .iter()
        .map(|op| format!("{op:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let _ = config;
    CosmeticPayload::NativeCss(detail)
}

/// Only a syntactically valid bare hostname has the uBO host-intent ambiguity. URL fragments and
/// partial patterns are plain substring filters in every dialect and must not be flagged here.
fn is_bare_hostname(text: &str) -> bool {
    if text.is_empty() || text.len() > 253 || !text.contains('.') {
        return false;
    }
    text.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.starts_with(|c: char| c.is_ascii_alphanumeric())
            && label.ends_with(|c: char| c.is_ascii_alphanumeric())
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn detect_network_gaps(text: &str, source: &model::SourceConfig) -> Vec<DialectGap> {
    let mut gaps = Vec::new();
    if let Some(parsed) = parse_network_options(text) {
        for option in &parsed.options {
            let value = option.value.as_deref().unwrap_or_default();
            match option.name.as_str() {
                "denyallow" => gaps.push(DialectGap::new(
                    "denyallow",
                    GapClass::Unsupported,
                    "engine rejects $denyallow",
                )),
                "all" => gaps.push(DialectGap::new(
                    "all",
                    GapClass::SemanticGap,
                    "$all is expanded to engine type bits",
                )),
                "rewrite" => gaps.push(DialectGap::new(
                    "rewrite",
                    GapClass::Canonicalized,
                    "rewrite alias maps to redirect",
                )),
                "queryprune" => gaps.push(DialectGap::new(
                    "queryprune",
                    GapClass::Canonicalized,
                    "queryprune maps to removeparam",
                )),
                "match-case" => gaps.push(DialectGap::new(
                    "match-case",
                    GapClass::SemanticGap,
                    "match-case forces regex machinery",
                )),
                "domain" | "from" | "to" => {
                    if value
                        .split('|')
                        .any(|domain| domain.trim_start_matches('~').ends_with(".*"))
                    {
                        gaps.push(DialectGap::new(
                            "entity_domain",
                            GapClass::SemanticGap,
                            "entity domains are hashed literally",
                        ));
                    }
                }
                "method" => {
                    let allowed = ["get", "head", "post"];
                    if value
                        .split('|')
                        .any(|method| !allowed.contains(&method.to_ascii_lowercase().as_str()))
                    {
                        gaps.push(DialectGap::new(
                            "dropped_method",
                            GapClass::SemanticGap,
                            "unsupported methods are dropped by the engine",
                        ));
                    }
                }
                "scheme" => {
                    let allowed = ["http", "https", "ws", "wss"];
                    if value
                        .split('|')
                        .any(|scheme| !allowed.contains(&scheme.to_ascii_lowercase().as_str()))
                    {
                        gaps.push(DialectGap::new(
                            "dropped_scheme",
                            GapClass::SemanticGap,
                            "unsupported schemes are dropped by the engine",
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    if source.format == SourceFormat::Standard
        && source.dialect == Dialect::Ubo
        && is_bare_hostname(text)
    {
        gaps.push(DialectGap::new(
            "ubo_bare_hostname",
            GapClass::SemanticGap,
            "bare hostname intent differs from substring patterns",
        ));
    }
    sorted_unique_gaps(&mut gaps);
    gaps
}

fn detect_cosmetic_gaps(text: &str) -> Vec<DialectGap> {
    let mut gaps = Vec::new();
    if text.contains("#$#") {
        gaps.push(DialectGap::new(
            "css_injection",
            GapClass::Unsupported,
            "#$# is excluded",
        ));
    }
    if text.contains("#%#") {
        gaps.push(DialectGap::new(
            "js_injection",
            GapClass::Unsupported,
            "#%# is excluded",
        ));
    }
    if text.contains("+js(") {
        gaps.push(DialectGap::new(
            "scriptlet",
            GapClass::EngineNative,
            "scriptlet requires D11 qualification",
        ));
    }
    for (marker, name) in [
        (":matches-css", "matches-css"),
        (":matches-path", "matches-path"),
        (":min-text-length", "min-text-length"),
        (":upward", "upward"),
        (":xpath", "xpath"),
        (":-abp-", "extended-css"),
    ] {
        if text.contains(marker) {
            gaps.push(DialectGap::new(
                name,
                GapClass::SemanticGap,
                "procedural operator requires allowlist review",
            ));
        }
    }
    sorted_unique_gaps(&mut gaps);
    gaps
}

fn sorted_unique_gaps(gaps: &mut Vec<DialectGap>) {
    gaps.sort_by(|a, b| a.kind.cmp(&b.kind));
    gaps.dedup();
}

fn detect_gap_for_error(text: &str) -> Option<DialectGap> {
    detect_network_gaps(
        text,
        &model::SourceConfig {
            id: String::new(),
            url: String::new(),
            path: None,
            sha256: None,
            include_sha256: Default::default(),
            dialect: Dialect::Auto,
            format: SourceFormat::Standard,
            host_semantics: None,
            priority: 0,
            enabled: true,
            trusted: false,
            permissions: 0,
            license: String::new(),
            last_modified: None,
        },
    )
    .into_iter()
    .next()
    .or_else(|| detect_cosmetic_gaps(text).into_iter().next())
}

fn classify_parse_error(text: &str, error: &str) -> ExclusionReason {
    if text.contains("#$#") {
        return ExclusionReason::UnsupportedSyntax("CSS injection (#$#) is excluded".to_string());
    }
    if text.contains("#%#") {
        return ExclusionReason::UnsupportedSyntax("JS injection (#%#) is excluded".to_string());
    }
    if text.contains("$denyallow") {
        return ExclusionReason::UnsupportedSyntax("denyallow is not engine-native".to_string());
    }
    if text.contains("$match-case") || error.contains("match-case") {
        return ExclusionReason::MatchCase;
    }
    if text.contains('/') && text.starts_with('/') {
        return ExclusionReason::Regex;
    }
    ExclusionReason::ParseError(error.to_string())
}

#[allow(dead_code)]
fn digest_text(text: &str) -> [u8; 32] {
    sha256_digest(text.as_bytes())
}

#[allow(dead_code)]
fn option_map(options: &[(String, Vec<String>)]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (_, values) in options {
        for value in values {
            if let Some((key, val)) = value.split_once('=') {
                map.insert(key.to_ascii_lowercase(), val.to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use fetch::FetchedSource;
    use model::SourceConfig;
    use std::collections::BTreeMap;

    fn parse_record(text: &str) -> ParsedRecord {
        let source = FetchedSource {
            config: SourceConfig {
                id: "test".to_string(),
                url: "https://example.test/list.txt".to_string(),
                path: None,
                sha256: None,
                include_sha256: BTreeMap::new(),
                dialect: Dialect::Ubo,
                format: SourceFormat::Standard,
                host_semantics: None,
                priority: 50,
                enabled: true,
                trusted: false,
                permissions: 0,
                license: String::new(),
                last_modified: None,
            },
            text: String::new(),
            sha256: String::new(),
            final_url: String::new(),
            includes: BTreeMap::new(),
        };
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tests/fixtures/sources.toml");
        let config = Config::load(&config_path).expect("load fixture config");
        let record = parse_line(
            &source,
            EffectiveLine {
                line_no: 1,
                text: text.to_string(),
                raw_text: text.to_string(),
            },
            &config,
        )
        .expect("parse line");
        record
    }

    fn classify(text: &str) -> model::NetworkRule {
        match parse_record(text).outcome {
            ParsedOutcome::Network(rule) => rule,
            other => panic!("expected network rule, got {:?}", other),
        }
    }

    #[test]
    fn literal_boundary_regex_only_marks_separator_patterns() {
        let anchored = classify("||0.gravatar.com/avatar/abc123^$all");
        assert!(anchored.is_regex);
        assert!(anchored.is_literal_boundary_regex);
        assert!(!anchored.is_complete_regex);
        assert!(!anchored.is_hostname_regex);

        let query = classify("||docs.google.com/uc?export=download&id=abc123^$all");
        assert!(query.is_literal_boundary_regex);

        let complete = classify("/^139\\.45\\.197\\.24/");
        assert!(complete.is_complete_regex);
        assert!(!complete.is_literal_boundary_regex);

        let wildcard = classify("||ads.livetv*.me^");
        assert!(wildcard.is_hostname_regex);
        assert!(!wildcard.is_literal_boundary_regex);

        let path_wildcard = classify("||ads.example/path/*/banner^");
        assert!(path_wildcard.is_regex);
        assert!(!path_wildcard.is_literal_boundary_regex);

        let plain = classify("||ads.example^$script");
        assert!(!plain.is_regex);
        assert!(!plain.is_literal_boundary_regex);
    }

    #[test]
    fn literal_boundary_regex_tolerates_escaped_and_punctuation_literals() {
        let escaped = classify(r"||ads.example/path\.php^$all");
        assert!(escaped.is_regex);
        assert!(escaped.is_literal_boundary_regex);
        assert!(!escaped.is_complete_regex);

        let punctuation = classify("||ads.example/a+b(c)[d]^$all");
        assert!(punctuation.is_literal_boundary_regex);

        let regex_escape = classify(r"||ads.example/path\d+\.php^$all");
        assert!(regex_escape.is_regex);
        assert!(!regex_escape.is_literal_boundary_regex);
    }

    #[test]
    fn d6_normalizes_only_literal_contains() {
        let record = parse_record("contains.example##.promo:contains(Legacy Ad)");
        let ParsedOutcome::Cosmetic(rule) = &record.outcome else {
            panic!("expected cosmetic rule, got {:?}", record.outcome);
        };
        assert_eq!(rule.text, "contains.example##.promo:has-text(Legacy Ad)");
        assert!(matches!(
            &rule.payload,
            CosmeticPayload::LightProcedural {
                op: FastOperator::HasText(value),
                ..
            } if value == "Legacy Ad"
        ));
        assert!(
            matches!(&rule.state, RuleState::Rewritten(id) if id.starts_with("d6_literal_contains-"))
        );
        assert_eq!(record.preparse_receipts.len(), 1);
        assert_eq!(record.preparse_receipts[0].family, "d6_literal_contains");
        assert!(record.baseline_rule.is_some());

        let regex = parse_record("regex.example##.promo:contains(/Legacy/i)");
        assert!(matches!(regex.outcome, ParsedOutcome::Unsupported { .. }));

        let nested = parse_record("nested.example##.promo:contains(Ad):upward(1)");
        assert!(matches!(nested.outcome, ParsedOutcome::Unsupported { .. }));
    }

    #[test]
    fn scriptlet_names_preserve_official_case() {
        let record = parse_record("example.com##+js(no-setTimeout-if, adblockNotif)");
        let ParsedOutcome::Cosmetic(rule) = &record.outcome else {
            panic!("expected cosmetic rule, got {:?}", record.outcome);
        };
        match &rule.payload {
            CosmeticPayload::VettedScriptlet { name, args, .. } => {
                assert_eq!(name, "no-setTimeout-if");
                assert_eq!(args, "adblockNotif");
            }
            other => panic!("expected vetted scriptlet, got {other:?}"),
        }

        let mixed = parse_record("example.com##+js(addEventListener-defuser, click, interstitial)");
        let ParsedOutcome::Cosmetic(rule) = &mixed.outcome else {
            panic!("expected cosmetic rule, got {:?}", mixed.outcome);
        };
        match &rule.payload {
            CosmeticPayload::VettedScriptlet { name, args, .. } => {
                assert_eq!(name, "addEventListener-defuser");
                assert_eq!(args, "click, interstitial");
            }
            other => panic!("expected vetted scriptlet, got {other:?}"),
        }
    }

    #[test]
    fn bare_hostname_gap_only_matches_valid_host_literals() {
        assert!(super::is_bare_hostname("ads.example.com"));
        assert!(super::is_bare_hostname("xn--bcher-kva.example"));
        assert!(!super::is_bare_hostname("&ag_custom_vlmspot="));
        assert!(!super::is_bare_hostname(".go?pid=1"));
        assert!(!super::is_bare_hostname("localhost"));
        assert!(!super::is_bare_hostname("ads.example.com/path"));
    }
}
