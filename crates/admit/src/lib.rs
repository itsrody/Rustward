//! Golden-rule admission: fast-native, official, engine-trusted rules only.

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions},
    request::Request,
    resources::{PermissionMask, Resource},
};
use anyhow::{Context, Result};
use model::{
    AdmissionResult, Config, CosmeticPayload, DialectGap, Eligibility, ExclusionReason,
    ExclusionRecord, GapClass, NetworkRule, ParsedOutcome, ParsedRecord, ResourceCatalog,
    ResourceDecision, Rule, RuleState, ScriptletGrade, model::CosmeticRule, util::is_literal_arg,
};
use std::{collections::BTreeSet, path::Path};

pub fn admit(records: &[ParsedRecord], config: &Config, root: &Path) -> Result<AdmissionResult> {
    let catalog = load_catalog(config, root)?;
    let engine_resources = catalog.engine_resources();
    // `get_id()` already excludes the BAD_FILTER feature bit, so a parsed badfilter's
    // engine_id is the identity of the rule it cancels.
    let badfilter_targets: BTreeSet<u64> = records
        .iter()
        .filter_map(|record| match &record.outcome {
            ParsedOutcome::Network(rule) if rule.is_badfilter => Some(rule.engine_id),
            _ => None,
        })
        .collect();
    let mut accepted = Vec::new();
    let mut baseline = Vec::new();
    let mut excluded = Vec::new();
    let mut resource_decisions = Vec::new();

    for record in records {
        if let Some(family) = record.outcome.family() {
            if config.admit.exclude_families.contains(&family) {
                excluded.push(ExclusionRecord {
                    source_id: record.source_id.clone(),
                    line_no: record.line_no,
                    dialect: record.dialect,
                    text: record.raw_text.clone(),
                    reason: ExclusionReason::BatchExcluded(family.as_str().to_string()),
                });
                continue;
            }
        }
        if let Some(kind) = record
            .outcome
            .unaccepted_semantic_gap(&config.admit.accepted_semantic_gaps)
        {
            excluded.push(ExclusionRecord {
                source_id: record.source_id.clone(),
                line_no: record.line_no,
                dialect: record.dialect,
                text: record.raw_text.clone(),
                reason: ExclusionReason::SemanticGap(kind.to_string()),
            });
            continue;
        }
        match &record.outcome {
            ParsedOutcome::Network(rule) => match admit_network(
                rule,
                config,
                &catalog,
                &engine_resources,
                &mut resource_decisions,
            ) {
                Ok(()) => {
                    let mut rule = rule.clone();
                    let engine_id = rule.engine_id;
                    let is_badfilter = rule.is_badfilter;
                    if is_badfilter {
                        rule.state = RuleState::Pinned;
                    }
                    let admitted = Rule::Network(rule);
                    baseline.push(admitted.clone());
                    if is_badfilter {
                        excluded.push(ExclusionRecord {
                            source_id: record.source_id.clone(),
                            line_no: record.line_no,
                            dialect: record.dialect,
                            text: record.raw_text.clone(),
                            reason: ExclusionReason::BadfilterResolved,
                        });
                    } else if badfilter_targets.contains(&engine_id) {
                        excluded.push(ExclusionRecord {
                            source_id: record.source_id.clone(),
                            line_no: record.line_no,
                            dialect: record.dialect,
                            text: record.raw_text.clone(),
                            reason: ExclusionReason::BadfilterTarget(format!(
                                "cancelled by $badfilter (id={})",
                                engine_id
                            )),
                        });
                    } else {
                        accepted.push(admitted);
                    }
                }
                Err(reason) => excluded.push(ExclusionRecord {
                    source_id: record.source_id.clone(),
                    line_no: record.line_no,
                    dialect: record.dialect,
                    text: record.raw_text.clone(),
                    reason,
                }),
            },
            ParsedOutcome::Cosmetic(rule) => match admit_cosmetic(
                rule,
                config,
                &catalog,
                &engine_resources,
                &mut resource_decisions,
            ) {
                Ok(admitted_rule) => {
                    // Preparse rewrites keep their original ABP extended form in the baseline so
                    // VERIFY compares the engine's behavior before and after the normalization.
                    baseline.push(
                        record
                            .baseline_rule
                            .clone()
                            .unwrap_or_else(|| Rule::Cosmetic(admitted_rule.clone())),
                    );
                    accepted.push(Rule::Cosmetic(admitted_rule));
                }
                Err(reason) => excluded.push(ExclusionRecord {
                    source_id: record.source_id.clone(),
                    line_no: record.line_no,
                    dialect: record.dialect,
                    text: record.raw_text.clone(),
                    reason,
                }),
            },
            ParsedOutcome::Unsupported { reason, .. } => excluded.push(ExclusionRecord {
                source_id: record.source_id.clone(),
                line_no: record.line_no,
                dialect: record.dialect,
                text: record.raw_text.clone(),
                reason: reason.clone(),
            }),
            ParsedOutcome::Empty
            | ParsedOutcome::Comment
            | ParsedOutcome::Metadata
            | ParsedOutcome::Directive
            | ParsedOutcome::Skipped { .. } => {}
        }
    }

    Ok(AdmissionResult {
        accepted,
        baseline,
        badfilter_targets,
        excluded,
        resource_decisions,
    })
}

fn load_catalog(config: &Config, root: &Path) -> Result<ResourceCatalog> {
    let Some(resources) = &config.resources else {
        return Ok(ResourceCatalog::empty());
    };
    let ubo = &resources.ubo;
    let Some(path) = ubo.snapshot_path.as_ref() else {
        return Ok(ResourceCatalog::empty());
    };
    let mut snapshot =
        model::ResourceSnapshot::load_verified(&root.join(path), &ubo.snapshot_sha256)
            .with_context(|| "failed to load uBO official resource snapshot")?;
    if let Some(brave) = resources.brave.as_ref() {
        if let Some(brave_path) = brave.snapshot_path.as_ref() {
            let brave_snapshot = model::ResourceSnapshot::load_verified(
                &root.join(brave_path),
                &brave.snapshot_sha256,
            )
            .with_context(|| "failed to load Brave official resource snapshot")?;
            snapshot = snapshot.merge(brave_snapshot);
        }
    }
    snapshot
        .into_catalog()
        .with_context(|| "failed to build official resource catalog")
}

fn admit_network(
    rule: &NetworkRule,
    config: &Config,
    catalog: &ResourceCatalog,
    engine_resources: &[Resource],
    decisions: &mut Vec<ResourceDecision>,
) -> std::result::Result<(), ExclusionReason> {
    if rule.eligibility != Eligibility::Eligible {
        return match &rule.eligibility {
            Eligibility::Ineligible(reason) => Err(reason.clone()),
            _ => Err(ExclusionReason::Policy(
                "rule arrived at ADMIT in a non-eligible state".to_string(),
            )),
        };
    }
    if has_unsupported_gap(&rule.dialect_gaps) {
        return Err(ExclusionReason::UnsupportedSyntax(
            rule.dialect_gaps
                .iter()
                .find(|gap| gap.class == GapClass::Unsupported)
                .map(|gap| gap.kind.clone())
                .unwrap_or_else(|| "unsupported syntax".to_string()),
        ));
    }
    let regex_excluded = rule.is_complete_regex
        || rule.is_hostname_regex
        || (rule.is_regex
            && !(config.admit.literal_boundary_regex && rule.is_literal_boundary_regex));
    if regex_excluded {
        return Err(ExclusionReason::Regex);
    }
    if rule.match_case {
        return Err(ExclusionReason::MatchCase);
    }
    if rule.is_redirect {
        if let Some(modifier) = &rule.modifier_option {
            qualify_resource(
                redirect_resource_name(modifier),
                rule,
                config,
                catalog,
                engine_resources,
                decisions,
                false,
            )?;
        }
    }
    Ok(())
}

fn admit_cosmetic(
    rule: &CosmeticRule,
    config: &Config,
    catalog: &ResourceCatalog,
    engine_resources: &[Resource],
    decisions: &mut Vec<ResourceDecision>,
) -> std::result::Result<CosmeticRule, ExclusionReason> {
    let mut rule = rule.clone();
    if rule.eligibility != Eligibility::Eligible {
        return match &rule.eligibility {
            Eligibility::Ineligible(reason) => Err(reason.clone()),
            _ => Err(ExclusionReason::Policy(
                "rule arrived at ADMIT in a non-eligible state".to_string(),
            )),
        };
    }
    if rule.action_detail.is_some() && !config.cosmetic.allow_action_operators {
        return Err(ExclusionReason::ActionOperator);
    }
    if has_unsupported_gap(&rule.dialect_gaps) {
        return Err(ExclusionReason::UnsupportedSyntax(
            rule.dialect_gaps
                .iter()
                .find(|gap| gap.class == GapClass::Unsupported)
                .map(|gap| gap.kind.clone())
                .unwrap_or_else(|| "unsupported syntax".to_string()),
        ));
    }

    if rule.script_inject {
        if !config.cosmetic.allow_vetted_scriptlets {
            return Err(ExclusionReason::Policy(
                "scriptlets are disabled".to_string(),
            ));
        }
        let name = match &rule.payload {
            CosmeticPayload::VettedScriptlet { name, .. } => name.clone(),
            _ => {
                return Err(ExclusionReason::UnsupportedSyntax(
                    "scriptlet invocation was not parsed".to_string(),
                ));
            }
        };
        qualify_resource(
            &name,
            &rule,
            config,
            catalog,
            engine_resources,
            decisions,
            true,
        )?;
        if let Some(resource) = catalog.find(&name) {
            if let CosmeticPayload::VettedScriptlet {
                grade,
                resource_digest,
                permission,
                ..
            } = &mut rule.payload
            {
                *grade = resource.grade;
                *resource_digest = resource.digest;
                *permission = resource.permission;
            }
        }
        return Ok(rule);
    }

    match &rule.payload {
        CosmeticPayload::NativeCss(_) => {
            if !config.cosmetic.allow_native_css {
                return Err(ExclusionReason::Policy(
                    "native CSS is disabled".to_string(),
                ));
            }
            if rule.selector_ops != ["css-selector"] {
                return Err(ExclusionReason::SlowCosmetic(rule.selector_ops.join(",")));
            }
        }
        CosmeticPayload::LightProcedural { op, .. } => {
            if !config
                .cosmetic
                .light_procedural_allowlist
                .iter()
                .any(|name| name == op.name())
            {
                return Err(ExclusionReason::SlowCosmetic(op.name().to_string()));
            }
            let value = match op {
                model::FastOperator::HasText(value) => value,
                model::FastOperator::MatchesAttr(value) => value,
            };
            if !config.cosmetic.allow_regex_procedural_args && !is_literal_arg(value) {
                return Err(ExclusionReason::SlowCosmetic(format!(
                    "{} uses a non-literal argument",
                    op.name()
                )));
            }
        }
        CosmeticPayload::VettedScriptlet { .. } => unreachable!(),
    }
    Ok(rule)
}

fn has_unsupported_gap(gaps: &[DialectGap]) -> bool {
    gaps.iter().any(|gap| gap.class == GapClass::Unsupported)
}

trait ResourceRule {
    fn resource_rule_fields(&self) -> (String, String, u8, bool, Vec<String>);
    fn realize_redirect(&self, _permissions: u8, _resources: &[Resource]) -> bool {
        false
    }
}

impl ResourceRule for NetworkRule {
    fn resource_rule_fields(&self) -> (String, String, u8, bool, Vec<String>) {
        (
            self.source_id.clone(),
            self.text.clone(),
            self.source_permissions,
            self.source_trusted,
            self.hostname.clone().into_iter().collect(),
        )
    }

    fn realize_redirect(&self, permissions: u8, resources: &[Resource]) -> bool {
        realize_redirect(self, permissions, resources)
    }
}

impl ResourceRule for CosmeticRule {
    fn resource_rule_fields(&self) -> (String, String, u8, bool, Vec<String>) {
        let hosts = if self.hosts.is_empty() {
            self.entities.clone()
        } else {
            self.hosts.clone()
        };
        (
            self.source_id.clone(),
            self.text.clone(),
            self.source_permissions,
            self.source_trusted,
            hosts,
        )
    }
}

fn qualify_resource<R: ResourceRule>(
    requested_name: &str,
    rule: &R,
    config: &Config,
    catalog: &ResourceCatalog,
    engine_resources: &[Resource],
    decisions: &mut Vec<ResourceDecision>,
    scriptlet: bool,
) -> std::result::Result<(), ExclusionReason> {
    let resource_label = if scriptlet {
        "scriptlet"
    } else {
        "redirect resource"
    };
    let Some(resources) = &config.resources else {
        return Err(ExclusionReason::UnknownResource(format!(
            "{resource_label} {requested_name}: no resource snapshot configured"
        )));
    };
    let ubo = &resources.ubo;
    let (source_id, rule_text, source_permissions, source_trusted, hosts) =
        rule.resource_rule_fields();
    let effective_permissions = source_permissions & config.engine.permissions;

    let resource = catalog.find(requested_name).ok_or_else(|| {
        ExclusionReason::UnknownResource(format!("{resource_label} {requested_name}"))
    })?;
    let canonical_name = resource.name.clone();
    let mut decision = ResourceDecision {
        name: requested_name.to_string(),
        canonical_name: canonical_name.clone(),
        grade: resource.grade,
        digest: hex::encode(resource.digest),
        permission: resource.permission,
        source_id: source_id.clone(),
        source_permissions,
        decision: "pending".to_string(),
        reason: None,
    };

    let result = (|| -> std::result::Result<(), ExclusionReason> {
        let grade_ok = match resource.grade {
            ScriptletGrade::Standard => ubo.allow_standard,
            ScriptletGrade::Trusted => ubo.allow_trusted && source_trusted,
        };
        if !grade_ok {
            return Err(ExclusionReason::Trust(format!(
                "{resource_label} {canonical_name} grade {} is not allowed for source {source_id}",
                resource.grade.as_str(),
            )));
        }
        let closure = catalog
            .dependency_closure(&canonical_name)
            .map_err(|error| {
                ExclusionReason::UnknownResource(format!(
                    "{resource_label} {canonical_name}: {error}"
                ))
            })?;
        let source_mask = PermissionMask::from_bits(effective_permissions);
        for item in &closure {
            let permission = PermissionMask::from_bits(item.permission);
            if !permission.is_injectable_by(source_mask) {
                return Err(ExclusionReason::Trust(format!(
                    "{resource_label} {} requires permission {:?} but source grants {:?}",
                    item.name, item.permission, source_mask
                )));
            }
            let kind_ok = if scriptlet {
                item.kind == model::ResourceKind::Template
                    || item.kind == model::ResourceKind::ApplicationJavascript
                    || item.kind == model::ResourceKind::FnJavascript
            } else {
                item.permission == 0
            };
            if !kind_ok {
                return Err(ExclusionReason::Trust(format!(
                    "{resource_label} {} cannot be used for {}",
                    item.name,
                    if scriptlet {
                        "script injection"
                    } else {
                        "redirect"
                    }
                )));
            }
        }
        if ubo.require_realization {
            let realized = if scriptlet {
                realize_scriptlet(&rule_text, effective_permissions, engine_resources, &hosts)
            } else {
                rule.realize_redirect(effective_permissions, engine_resources)
            };
            if !realized {
                return Err(ExclusionReason::Trust(format!(
                    "engine did not realize {resource_label} {canonical_name}"
                )));
            }
        }
        Ok(())
    })();

    match &result {
        Ok(()) => decision.decision = "admitted".to_string(),
        Err(reason) => {
            decision.decision = "excluded".to_string();
            decision.reason = Some(reason.to_string());
        }
    }
    decisions.push(decision);
    result
}

fn build_engine(rule_text: &str, permissions: u8, resources: &[Resource]) -> Engine {
    let mut set = FilterSet::new(false);
    set.add_filter_list(
        rule_text.to_string(),
        ParseOptions {
            permissions: PermissionMask::from_bits(permissions),
            ..Default::default()
        },
    );
    let mut engine = Engine::new_with_filter_set(set);
    engine.use_resources(resources.iter().cloned());
    engine
}

fn realize_scriptlet(
    rule_text: &str,
    permissions: u8,
    resources: &[Resource],
    hosts: &[String],
) -> bool {
    let engine = build_engine(rule_text, permissions, resources);
    let host = hosts.first().map(String::as_str).unwrap_or("example.com");
    let url = if host.contains("://") {
        host.to_string()
    } else {
        format!("https://{host}/")
    };
    !engine
        .url_cosmetic_resources(&url)
        .injected_script
        .is_empty()
}

fn realize_redirect(rule: &NetworkRule, permissions: u8, resources: &[Resource]) -> bool {
    let engine = build_engine(&rule.text, permissions, resources);
    let options = rule_options(&rule.text);

    let mut source_hosts: Vec<String> = rule
        .domains
        .iter()
        .map(|host| clean_probe_host(host))
        .collect();
    if source_hosts.is_empty() {
        source_hosts.push("site.example".to_string());
    }

    let mut target_hosts: Vec<String> = rule
        .to_domains
        .iter()
        .map(|host| clean_probe_host(host))
        .collect();
    if let Some(host) = &rule.hostname {
        target_hosts.push(clean_probe_host(host));
    } else {
        // Patterns such as `*/fuckadblock-` have no hostname; let the source host
        // act as the request host in addition to the generic fallback below.
        target_hosts.extend(source_hosts.iter().cloned());
    }
    target_hosts.push("ads.example".to_string());
    target_hosts.sort();
    target_hosts.dedup();

    let request_types = redirect_request_types(&options);
    let methods = redirect_methods(&options);
    let paths = redirect_probe_paths(rule);

    for source in &source_hosts {
        let source_url = format!("https://{source}/");
        for target in &target_hosts {
            for path in &paths {
                let url = format!("https://{target}{path}");
                for request_type in &request_types {
                    for method in &methods {
                        let request = match Request::new(&url, &source_url, request_type, method) {
                            Ok(request) => request,
                            Err(_) => continue,
                        };
                        if engine.check_network_request(&request).redirect.is_some() {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Builds concrete URL paths that a literal redirect filter can match. The engine remains the
/// oracle: these are only probe candidates, and admission still requires the engine to return a
/// redirect. Complex regex bodies fall back to the generic probe rather than being approximated.
fn redirect_probe_paths(rule: &NetworkRule) -> Vec<String> {
    literal_probe_paths(
        Some(rule.body.as_str()),
        !rule.is_complete_regex && !rule.is_hostname_regex,
    )
}

fn literal_probe_paths(body: Option<&str>, simple: bool) -> Vec<String> {
    const FALLBACK: &str = "/rs-probe.js";
    if !simple {
        return vec![FALLBACK.to_string()];
    }
    let Some(body) = body.filter(|body| !body.is_empty()) else {
        return vec![FALLBACK.to_string()];
    };
    if body.starts_with('^')
        || body.starts_with("/^")
        || body
            .chars()
            .any(|ch| matches!(ch, '[' | ']' | '(' | ')' | '{' | '}' | '|' | '\\'))
    {
        return vec![FALLBACK.to_string()];
    }

    let mut exact = String::new();
    let mut separated = String::new();
    for ch in body.chars() {
        match ch {
            '^' => separated.push_str("/probe"),
            '*' => {
                exact.push_str("probe");
                separated.push_str("probe");
            }
            other => {
                exact.push(other);
                separated.push(other);
            }
        }
    }
    if !exact.starts_with('/') {
        exact.insert(0, '/');
    }
    if !separated.starts_with('/') {
        separated.insert(0, '/');
    }

    let mut paths = vec![exact];
    if separated != paths[0] {
        paths.push(separated);
    }
    paths
}

/// adblock encodes the redirect "apply after N requests" option as a trailing `:N`
/// in `modifier_option` (e.g. `noopjs:10`). The engine parses this suffix as an `i32`.
/// Official resource names may themselves contain colons (`abp-resource:blank-js`),
/// so only a trailing colon followed by an integer is treated as an option suffix.
fn redirect_resource_name(modifier: &str) -> &str {
    if let Some((stem, priority)) = modifier.rsplit_once(':') {
        if !stem.is_empty() && priority.parse::<i32>().is_ok() {
            return stem;
        }
    }
    modifier
}

fn rule_options(text: &str) -> Vec<String> {
    let Some((_, options)) = text.rsplit_once('$') else {
        return Vec::new();
    };
    options
        .split(',')
        .map(|option| option.trim().to_ascii_lowercase())
        .filter(|option| !option.is_empty())
        .collect()
}

fn clean_probe_host(value: &str) -> String {
    let mut host = value.trim();
    if let Some((_, rest)) = host.split_once("://") {
        host = rest;
    }
    host = host
        .trim_start_matches("||")
        .trim_start_matches("*.")
        .split('/')
        .next()
        .unwrap_or(host)
        .trim_end_matches('^')
        .trim_end_matches('.');
    if host.is_empty() {
        "ads.example".to_string()
    } else {
        host.to_ascii_lowercase()
    }
}

fn redirect_request_types(options: &[String]) -> Vec<String> {
    let aliases = [
        ("beacon", "beacon"),
        ("csp_report", "csp_report"),
        ("document", "document"),
        ("main_frame", "document"),
        ("fetch", "fetch"),
        ("font", "font"),
        ("image", "image"),
        ("imageset", "image"),
        ("media", "media"),
        ("object", "object"),
        ("object_subrequest", "object"),
        ("ping", "ping"),
        ("script", "script"),
        ("stylesheet", "stylesheet"),
        ("sub_frame", "subdocument"),
        ("subdocument", "subdocument"),
        ("websocket", "websocket"),
        ("xhr", "xhr"),
        ("xmlhttprequest", "xhr"),
    ];
    let mut types: Vec<String> = options
        .iter()
        .filter(|option| !option.starts_with('~') && !option.contains('='))
        .filter_map(|option| {
            aliases
                .iter()
                .find(|(alias, _)| *alias == option.as_str())
                .map(|(_, canonical)| (*canonical).to_string())
        })
        .collect();
    if types.is_empty() {
        types.push("script".to_string());
    }
    types.sort();
    types.dedup();
    types
}

fn redirect_methods(options: &[String]) -> Vec<String> {
    let mut methods: Vec<String> = options
        .iter()
        .filter_map(|option| option.strip_prefix("method="))
        .flat_map(|value| value.split('|'))
        .filter(|value| !value.starts_with('~') && !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
        .collect();
    if methods.is_empty() {
        methods.push("GET".to_string());
    }
    methods.sort();
    methods.dedup();
    methods
}

#[cfg(test)]
mod tests {
    use super::{clean_probe_host, literal_probe_paths, redirect_resource_name};

    #[test]
    fn redirect_suffix_is_stripped_without_touching_colon_names() {
        assert_eq!(redirect_resource_name("noopjs:10"), "noopjs");
        assert_eq!(
            redirect_resource_name("fuckadblock.js-3.2.0:5"),
            "fuckadblock.js-3.2.0"
        );
        assert_eq!(redirect_resource_name("noop-1s.mp4:10"), "noop-1s.mp4");
        assert_eq!(
            redirect_resource_name("abp-resource:blank-js"),
            "abp-resource:blank-js"
        );
        assert_eq!(redirect_resource_name("gemius"), "gemius");
        assert_eq!(redirect_resource_name("noopjs:"), "noopjs:");
    }

    #[test]
    fn redirect_probe_paths_cover_literal_and_boundary_bodies() {
        assert_eq!(
            literal_probe_paths(Some("/pagead/js/adsbygoogle.js^"), true),
            vec![
                "/pagead/js/adsbygoogle.js",
                "/pagead/js/adsbygoogle.js/probe"
            ]
        );
        assert_eq!(
            literal_probe_paths(Some("/path/*/banner.js^"), true),
            vec!["/path/probe/banner.js", "/path/probe/banner.js/probe"]
        );
        assert_eq!(
            literal_probe_paths(Some("/fuckadblock-"), true),
            vec!["/fuckadblock-"]
        );
        assert_eq!(literal_probe_paths(None, true), vec!["/rs-probe.js"]);
        assert_eq!(
            literal_probe_paths(Some("/^https:\\/\\/ads.example/.*/"), false),
            vec!["/rs-probe.js"]
        );
        assert_eq!(
            literal_probe_paths(Some("/[a-z]+/ad.js"), true),
            vec!["/rs-probe.js"]
        );
    }

    #[test]
    fn probe_hosts_strip_redirect_boundary_markers() {
        assert_eq!(clean_probe_host("||redirect.example^"), "redirect.example");
        assert_eq!(
            clean_probe_host("||redirect.example^/script.js"),
            "redirect.example"
        );
        assert_eq!(clean_probe_host("||ads.example."), "ads.example");
    }
}
