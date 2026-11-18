//! Conservative rewrite catalog with structural, reparse, and differential checks.

use adblock::lists::ParseOptions;
use anyhow::Result;
use model::{
    Config, CosmeticPayload, Eligibility, NetworkRule, Origin, RewriteReceipt, Rule, RuleState,
    util::sha256_hex,
};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct RewriteResult {
    pub rules: Vec<Rule>,
    pub receipts: Vec<RewriteReceipt>,
}

pub fn rewrite(rules: Vec<Rule>, config: &Config) -> Result<RewriteResult> {
    let mut rules = rules;
    let mut receipts = Vec::new();
    let badfilter_targets: HashSet<u64> = rules
        .iter()
        .filter_map(|rule| match rule {
            Rule::Network(network) if network.is_badfilter => Some(network.engine_id),
            _ => None,
        })
        .collect();

    if config.rewrite_enabled("type_union") {
        rewrite_network(
            &mut rules,
            config,
            "type_union",
            &badfilter_targets,
            &mut receipts,
        )?;
    }
    if config.rewrite_enabled("domain_union") {
        rewrite_network(
            &mut rules,
            config,
            "domain_union",
            &badfilter_targets,
            &mut receipts,
        )?;
    }
    if config.rewrite_enabled("to_domain_union") {
        rewrite_network(
            &mut rules,
            config,
            "to_domain_union",
            &badfilter_targets,
            &mut receipts,
        )?;
    }
    if config.rewrite_enabled("cosmetic_host_union") {
        rewrite_cosmetic(&mut rules, config, &mut receipts)?;
    }

    Ok(RewriteResult { rules, receipts })
}

#[derive(Debug, Clone)]
struct OptionSplit {
    prefix: String,
    options: Vec<String>,
}

fn split_network_options(text: &str) -> Option<OptionSplit> {
    let (prefix, options) = text.rsplit_once('$')?;
    if prefix.contains('$') || options.is_empty() || options.contains('$') || text.starts_with("@@")
    {
        return None;
    }
    Some(OptionSplit {
        prefix: prefix.to_string(),
        options: options.split(',').map(str::to_string).collect(),
    })
}

const TYPE_OPTIONS: &[&str] = &[
    "script",
    "image",
    "stylesheet",
    "subdocument",
    "xmlhttprequest",
    "font",
    "media",
    "object",
    "ping",
    "websocket",
    "other",
];

fn rewrite_network(
    rules: &mut Vec<Rule>,
    config: &Config,
    family: &str,
    badfilter_targets: &HashSet<u64>,
    receipts: &mut Vec<RewriteReceipt>,
) -> Result<()> {
    let mut groups: BTreeMap<(String, String), Vec<NetworkRule>> = BTreeMap::new();

    for rule in rules.iter() {
        let Rule::Network(network) = rule else {
            continue;
        };
        if network.is_badfilter
            || badfilter_targets.contains(&network.engine_id)
            || network.eligibility != Eligibility::Eligible
            || network.state != RuleState::Active
        {
            continue;
        }
        let Some(split) = split_network_options(&network.text) else {
            continue;
        };
        let accepted = match family {
            "type_union" => split.options.iter().all(|option| {
                let key = option.split('=').next().unwrap_or("");
                TYPE_OPTIONS.contains(&key.to_ascii_lowercase().as_str())
            }),
            "domain_union" => split.options.iter().all(|option| {
                matches!(
                    option
                        .split('=')
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .as_str(),
                    "domain" | "from"
                ) && option.contains('=')
            }),
            "to_domain_union" => split.options.iter().all(|option| {
                option
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("to")
                    && option.contains('=')
            }),
            _ => false,
        };
        if !accepted || split.options.is_empty() {
            continue;
        }

        let key = match family {
            "type_union" => format!(
                "{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{}",
                split.prefix,
                network.mask
                    & !adblock::filters::network::NetworkFilterMask::FROM_NETWORK_TYPES.bits(),
                network.features,
                network.domain_hashes,
                network.to_domain_hashes,
                network.modifier_option,
                network.tag,
                network.source_permissions,
            ),
            "domain_union" => format!(
                "{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{}",
                split.prefix,
                network.mask,
                network.features,
                network.not_domain_hashes,
                network.to_domain_hashes,
                network.modifier_option,
                network.tag,
                network.source_permissions,
            ),
            "to_domain_union" => format!(
                "{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{}",
                split.prefix,
                network.mask,
                network.features,
                network.domain_hashes,
                network.not_domain_hashes,
                network.modifier_option,
                network.tag,
                network.source_permissions,
            ),
            _ => unreachable!(),
        };
        groups
            .entry((key, family.to_string()))
            .or_default()
            .push(network.clone());
    }

    for ((_, family_name), group) in groups {
        if group.len() < 2 {
            continue;
        }
        let candidate = match build_network_candidate(&group, &family_name) {
            Some(candidate) => candidate,
            None => continue,
        };
        let debug = std::env::var_os("RUSTSHIELD_DEBUG_REWRITE").is_some();
        if debug {
            eprintln!(
                "[{family_name}] candidate={candidate} masks={:?}",
                group.iter().map(|rule| rule.mask).collect::<Vec<_>>()
            );
        }
        if !structural_check_network(&group, &family_name, &candidate) {
            if debug {
                eprintln!("[{family_name}] structural check failed");
            }
            continue;
        }
        let before: Vec<String> = group.iter().map(|rule| rule.text.clone()).collect();
        if !verify::network_equivalence(&before, &candidate, group[0].source_permissions)? {
            if debug {
                eprintln!("[{family_name}] engine equivalence failed");
            }
            continue;
        }
        let id = format!(
            "{family_name}-{}",
            &sha256_hex(before.join("||").as_bytes())[..12]
        );
        let representative = group
            .iter()
            .max_by_key(|rule| (rule.source_priority, std::cmp::Reverse(rule.text.len())))
            .cloned()
            .unwrap();
        let mut merged = representative;
        merged.text = candidate.clone();
        merged.provenance = group
            .iter()
            .flat_map(|rule| rule.provenance.iter().cloned())
            .collect();
        merged.provenance.sort_by(|a, b| {
            a.source_id
                .cmp(&b.source_id)
                .then(a.line_no.cmp(&b.line_no))
        });
        merged.state = RuleState::Rewritten(id.clone());

        let before_texts: HashSet<&str> = group.iter().map(|rule| rule.text.as_str()).collect();
        rules.retain(|rule| match rule {
            Rule::Network(network) => !before_texts.contains(network.text.as_str()),
            _ => true,
        });
        rules.push(Rule::Network(merged));
        receipts.push(RewriteReceipt {
            id: id.clone(),
            family: family_name,
            before,
            after: candidate,
            source_id: group[0].source_id.clone(),
            checks: vec![
                "structural-equality".to_string(),
                "reparse-equal".to_string(),
                "engine-differential".to_string(),
                "golden-rule-postcondition".to_string(),
            ],
        });
    }
    let _ = config;
    Ok(())
}

fn build_network_candidate(group: &[NetworkRule], family: &str) -> Option<String> {
    let first = split_network_options(&group[0].text)?;
    let mut before = Vec::new();
    for rule in group {
        let split = split_network_options(&rule.text)?;
        before.push(split);
    }
    let options = match family {
        "type_union" => {
            let mut options: Vec<String> = before
                .iter()
                .flat_map(|split| split.options.iter().cloned())
                .collect();
            options.sort();
            options.dedup();
            options
        }
        "domain_union" | "to_domain_union" => {
            let key = if family == "domain_union" {
                "domain"
            } else {
                "to"
            };
            let mut values = Vec::new();
            for split in &before {
                for option in &split.options {
                    let value = option.split_once('=')?.1;
                    values.extend(value.split('|').map(str::to_string));
                }
            }
            values.sort();
            values.dedup();
            vec![format!("{}={}", key, values.join("|"))]
        }
        _ => return None,
    };
    Some(format!("{}${}", first.prefix, options.join(",")))
}

fn structural_check_network(group: &[NetworkRule], family: &str, candidate: &str) -> bool {
    let Ok(parsed) = adblock::lists::parse_filter(candidate, false, ParseOptions::default()) else {
        return false;
    };
    let adblock::lists::ParsedLine::Network(after) = parsed else {
        return false;
    };
    let first = &group[0];
    let expected_mask = if family == "type_union" {
        group.iter().fold(0u32, |acc, rule| acc | rule.mask)
    } else {
        first.mask
    };
    if after.mask.bits() != expected_mask || after.features_mask.bits() != first.features {
        return false;
    }
    if after.hostname.as_deref() != first.hostname.as_deref()
        || after.filter.string_view().unwrap_or_default() != first.body
    {
        return false;
    }
    if after.modifier_option.map(str::to_string) != first.modifier_option {
        return false;
    }
    if family == "type_union" {
        return sorted(after.opt_domains.as_deref()) == first.domain_hashes
            && sorted(after.opt_not_domains.as_deref()) == first.not_domain_hashes
            && sorted(after.opt_to_domains.as_deref()) == first.to_domain_hashes
            && sorted(after.opt_not_to_domains.as_deref()) == first.not_to_domain_hashes;
    }
    if family == "domain_union" {
        let expected: Vec<u64> = group
            .iter()
            .flat_map(|rule| rule.domain_hashes.iter().copied())
            .collect();
        return sorted(after.opt_domains.as_deref()) == sorted(Some(&expected))
            && sorted(after.opt_not_domains.as_deref()) == first.not_domain_hashes;
    }
    if family == "to_domain_union" {
        let expected: Vec<u64> = group
            .iter()
            .flat_map(|rule| rule.to_domain_hashes.iter().copied())
            .collect();
        return sorted(after.opt_to_domains.as_deref()) == sorted(Some(&expected))
            && sorted(after.opt_not_to_domains.as_deref()) == first.not_to_domain_hashes;
    }
    false
}

fn sorted(values: Option<&[u64]>) -> Vec<u64> {
    let mut values = values.unwrap_or_default().to_vec();
    values.sort_unstable();
    values
}

fn rewrite_cosmetic(
    rules: &mut Vec<Rule>,
    config: &Config,
    receipts: &mut Vec<RewriteReceipt>,
) -> Result<()> {
    let mut groups: BTreeMap<(String, u8), Vec<model::CosmeticRule>> = BTreeMap::new();
    for rule in rules.iter() {
        let Rule::Cosmetic(cosmetic) = rule else {
            continue;
        };
        if cosmetic.eligibility != Eligibility::Eligible
            || cosmetic.state != RuleState::Active
            || cosmetic.script_inject
            || cosmetic.action_detail.is_some()
            || cosmetic.action != model::HideOrUnhide::Hide
            || cosmetic.hosts.is_empty()
            || !cosmetic.not_hosts.is_empty()
            || !cosmetic.entities.is_empty()
            || !cosmetic.not_entities.is_empty()
        {
            continue;
        }
        let Some((_, separator, selector)) = split_cosmetic(&cosmetic.text) else {
            continue;
        };
        if separator != "##" {
            continue;
        }
        let payload_key = serde_json::to_string(&cosmetic.payload)?;
        groups
            .entry((
                format!("{payload_key}|{selector}|{:?}", cosmetic.selector_ops),
                cosmetic.source_permissions,
            ))
            .or_default()
            .push(cosmetic.clone());
    }

    for ((_, _), group) in groups {
        if group.len() < 2 {
            continue;
        }
        let selector = split_cosmetic(&group[0].text)
            .map(|(_, _, selector)| selector.to_string())
            .unwrap_or_default();
        let mut hosts: Vec<String> = group
            .iter()
            .flat_map(|rule| rule.hosts.iter().cloned())
            .collect();
        hosts.sort();
        hosts.dedup();
        let candidate = format!("{}##{}", hosts.join(","), selector);
        if !structural_check_cosmetic(&group, &candidate) {
            continue;
        }
        let before: Vec<String> = group.iter().map(|rule| rule.text.clone()).collect();
        if !verify::cosmetic_equivalence(&before, &candidate, group[0].source_permissions)? {
            continue;
        }
        let id = format!(
            "cosmetic_host_union-{}",
            &sha256_hex(before.join("||").as_bytes())[..12]
        );
        let representative = group
            .iter()
            .max_by_key(|rule| (rule.source_priority, std::cmp::Reverse(rule.text.len())))
            .cloned()
            .unwrap();
        let mut merged = representative;
        merged.text = candidate.clone();
        merged.hosts = hosts;
        merged.provenance = group
            .iter()
            .flat_map(|rule| rule.provenance.iter().cloned())
            .collect();
        merged.state = RuleState::Rewritten(id.clone());

        let before_texts: HashSet<&str> = group.iter().map(|rule| rule.text.as_str()).collect();
        rules.retain(|rule| match rule {
            Rule::Cosmetic(cosmetic) => !before_texts.contains(cosmetic.text.as_str()),
            _ => true,
        });
        rules.push(Rule::Cosmetic(merged));
        receipts.push(RewriteReceipt {
            id,
            family: "cosmetic_host_union".to_string(),
            before,
            after: candidate,
            source_id: group[0].source_id.clone(),
            checks: vec![
                "selector-equality".to_string(),
                "reparse-equal".to_string(),
                "engine-differential".to_string(),
            ],
        });
    }
    let _ = config;
    Ok(())
}

fn structural_check_cosmetic(group: &[model::CosmeticRule], candidate: &str) -> bool {
    let Ok(parsed) = adblock::lists::parse_filter(candidate, false, ParseOptions::default()) else {
        return false;
    };
    let adblock::lists::ParsedLine::Cosmetic(after) = parsed else {
        return false;
    };
    let first = &group[0];
    let mut expected_ops: Vec<u64> = group
        .iter()
        .flat_map(|rule| {
            rule.hosts
                .iter()
                .map(|host| adblock::utils::fast_hash(host))
        })
        .collect();
    expected_ops.sort_unstable();
    expected_ops.dedup();
    let mut actual_hosts: Vec<u64> = after.hostnames.clone().unwrap_or_default();
    actual_hosts.sort_unstable();
    if actual_hosts != expected_ops {
        return false;
    }
    if after.selector != group[0].selector_from_payload() {
        return false;
    }
    if after.mask.bits() != first.action_mask() {
        return false;
    }
    true
}

trait CosmeticCheckExt {
    fn selector_from_payload(&self) -> Vec<adblock::filters::cosmetic::CosmeticFilterOperator>;
    fn action_mask(&self) -> u8;
}

impl CosmeticCheckExt for model::CosmeticRule {
    fn selector_from_payload(&self) -> Vec<adblock::filters::cosmetic::CosmeticFilterOperator> {
        use adblock::filters::cosmetic::CosmeticFilterOperator;
        match &self.payload {
            CosmeticPayload::NativeCss(css) => {
                vec![CosmeticFilterOperator::CssSelector(css.clone())]
            }
            CosmeticPayload::LightProcedural { css, op } => match op {
                model::FastOperator::HasText(value) => vec![
                    CosmeticFilterOperator::CssSelector(css.clone()),
                    CosmeticFilterOperator::HasText(value.clone()),
                ],
                model::FastOperator::MatchesAttr(value) => vec![
                    CosmeticFilterOperator::CssSelector(css.clone()),
                    CosmeticFilterOperator::MatchesAttr(value.clone()),
                ],
            },
            CosmeticPayload::VettedScriptlet { .. } => Vec::new(),
        }
    }

    fn action_mask(&self) -> u8 {
        match self.action {
            model::HideOrUnhide::Hide => 0,
            model::HideOrUnhide::Unhide => 1,
        }
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

#[allow(dead_code)]
fn merge_origins(existing: &[Origin], additional: &[Origin]) -> Vec<Origin> {
    let mut origins = existing.to_vec();
    for origin in additional {
        if !origins.contains(origin) {
            origins.push(origin.clone());
        }
    }
    origins
}
