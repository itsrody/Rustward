//! Canonical rule IR and report models.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::config::Dialect;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Origin {
    pub source_id: String,
    pub line_no: usize,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GapClass {
    EngineNative,
    Canonicalized,
    SemanticGap,
    Unsupported,
}

impl GapClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EngineNative => "ENGINE_NATIVE",
            Self::Canonicalized => "CANONICALIZED",
            Self::SemanticGap => "SEMANTIC_GAP",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DialectGap {
    pub kind: String,
    pub class: GapClass,
    pub detail: String,
}

impl DialectGap {
    pub fn new(kind: impl Into<String>, class: GapClass, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            class,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExclusionReason {
    ParseError(String),
    UnsupportedSyntax(String),
    Regex,
    MatchCase,
    SlowCosmetic(String),
    ActionOperator,
    UnknownResource(String),
    Trust(String),
    BadfilterResolved,
    BadfilterTarget(String),
    Policy(String),
    RewriteFailed(String),
    BatchExcluded(String),
    SemanticGap(String),
}

impl ExclusionReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ParseError(_) => "PARSE_ERROR",
            Self::UnsupportedSyntax(_) => "UNSUPPORTED_SYNTAX",
            Self::Regex => "REGEX",
            Self::MatchCase => "MATCH_CASE",
            Self::SlowCosmetic(_) => "SLOW_COSMETIC_OPERATOR",
            Self::ActionOperator => "ACTION_OPERATOR",
            Self::UnknownResource(_) => "UNKNOWN_RESOURCE",
            Self::Trust(_) => "ENGINE_TRUST",
            Self::BadfilterResolved => "BADFILTER_RESOLVED",
            Self::BadfilterTarget(_) => "BADFILTER_TARGET",
            Self::Policy(_) => "POLICY",
            Self::RewriteFailed(_) => "REWRITE_FAILED",
            Self::BatchExcluded(_) => "BATCH_EXCLUDED",
            Self::SemanticGap(_) => "SEMANTIC_GAP_POLICY",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::ParseError(s)
            | Self::UnsupportedSyntax(s)
            | Self::SlowCosmetic(s)
            | Self::UnknownResource(s)
            | Self::Trust(s)
            | Self::Policy(s)
            | Self::RewriteFailed(s) => s,
            Self::BadfilterResolved => "badfilter resolved at build time and omitted from output",
            Self::BadfilterTarget(detail) => detail,
            Self::Regex => "regex rules are not fast-native",
            Self::MatchCase => "match-case requires regex machinery",
            Self::ActionOperator => "DOM action operators are excluded",
            Self::BatchExcluded(s) => s,
            Self::SemanticGap(s) => s,
        }
    }
}

impl std::fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Eligibility {
    Eligible,
    RewritableToEligible,
    Ineligible(ExclusionReason),
}

impl Eligibility {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleState {
    Active,
    Pinned,
    Excluded(ExclusionReason),
    Rewritten(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HideOrUnhide {
    Hide,
    Unhide,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FastOperator {
    HasText(String),
    MatchesAttr(String),
}

impl FastOperator {
    pub fn name(&self) -> &'static str {
        match self {
            Self::HasText(_) => "has-text",
            Self::MatchesAttr(_) => "matches-attr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptletGrade {
    Standard,
    Trusted,
}

impl ScriptletGrade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Trusted => "trusted",
        }
    }
}

/// A slow or complex rule class that can be excluded in one batch from `admit.exclude_families`.
/// Plain network rules and plain native CSS have no family and are never batch-excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleFamily {
    Regex,
    LiteralBoundaryRegex,
    NestedProcedural,
    LightProcedural,
    VettedScriptlet,
    ActionOperator,
    SemanticGap,
}

impl RuleFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::LiteralBoundaryRegex => "literal_boundary_regex",
            Self::NestedProcedural => "nested_procedural",
            Self::LightProcedural => "light_procedural",
            Self::VettedScriptlet => "vetted_scriptlet",
            Self::ActionOperator => "action_operator",
            Self::SemanticGap => "semantic_gap",
        }
    }
}

impl std::fmt::Display for RuleFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CosmeticPayload {
    NativeCss(String),
    LightProcedural {
        css: String,
        op: FastOperator,
    },
    VettedScriptlet {
        name: String,
        args: String,
        grade: ScriptletGrade,
        resource_digest: [u8; 32],
        permission: u8,
    },
}

impl CosmeticPayload {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NativeCss(_) => "native_css",
            Self::LightProcedural { .. } => "light_procedural",
            Self::VettedScriptlet { .. } => "vetted_scriptlet",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub engine_id: u64,
    pub mask: u32,
    pub features: u32,
    pub hostname: Option<String>,
    pub body: String,
    pub left_anchor: bool,
    pub right_anchor: bool,
    pub hostname_anchor: bool,
    pub is_regex: bool,
    /// `IS_REGEX` caused only by `^` separators, with no true regex metacharacters.
    pub is_literal_boundary_regex: bool,
    pub is_complete_regex: bool,
    pub is_hostname_regex: bool,
    pub is_exception: bool,
    pub important: bool,
    pub match_case: bool,
    pub is_badfilter: bool,
    pub is_redirect: bool,
    pub is_csp: bool,
    pub is_removeparam: bool,
    pub is_generic_hide: bool,
    pub domains: Vec<String>,
    pub not_domains: Vec<String>,
    pub to_domains: Vec<String>,
    pub not_to_domains: Vec<String>,
    pub domain_hashes: Vec<u64>,
    pub not_domain_hashes: Vec<u64>,
    pub to_domain_hashes: Vec<u64>,
    pub not_to_domain_hashes: Vec<u64>,
    pub modifier_option: Option<String>,
    pub tag: Option<String>,
    pub text: String,
    pub source_id: String,
    pub line_no: usize,
    pub dialect: Dialect,
    pub source_trusted: bool,
    pub source_permissions: u8,
    pub source_priority: i32,
    pub eligibility: Eligibility,
    pub state: RuleState,
    pub dialect_gaps: Vec<DialectGap>,
    pub provenance: Vec<Origin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmeticRule {
    pub hosts: Vec<String>,
    pub not_hosts: Vec<String>,
    pub entities: Vec<String>,
    pub not_entities: Vec<String>,
    pub payload: CosmeticPayload,
    pub selector_ops: Vec<String>,
    pub action: HideOrUnhide,
    pub action_detail: Option<String>,
    pub generic: bool,
    pub script_inject: bool,
    pub permission: u8,
    pub text: String,
    pub source_id: String,
    pub line_no: usize,
    pub dialect: Dialect,
    pub source_trusted: bool,
    pub source_permissions: u8,
    pub source_priority: i32,
    pub eligibility: Eligibility,
    pub state: RuleState,
    pub dialect_gaps: Vec<DialectGap>,
    pub provenance: Vec<Origin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rule {
    Network(NetworkRule),
    Cosmetic(CosmeticRule),
}

impl Rule {
    pub fn text(&self) -> &str {
        match self {
            Self::Network(rule) => &rule.text,
            Self::Cosmetic(rule) => &rule.text,
        }
    }

    pub fn source_id(&self) -> &str {
        match self {
            Self::Network(rule) => &rule.source_id,
            Self::Cosmetic(rule) => &rule.source_id,
        }
    }

    pub fn line_no(&self) -> usize {
        match self {
            Self::Network(rule) => rule.line_no,
            Self::Cosmetic(rule) => rule.line_no,
        }
    }

    pub fn source_permissions(&self) -> u8 {
        match self {
            Self::Network(rule) => rule.source_permissions,
            Self::Cosmetic(rule) => rule.source_permissions,
        }
    }

    pub fn dialect(&self) -> Dialect {
        match self {
            Self::Network(rule) => rule.dialect,
            Self::Cosmetic(rule) => rule.dialect,
        }
    }

    pub fn eligibility(&self) -> &Eligibility {
        match self {
            Self::Network(rule) => &rule.eligibility,
            Self::Cosmetic(rule) => &rule.eligibility,
        }
    }

    pub fn state(&self) -> &RuleState {
        match self {
            Self::Network(rule) => &rule.state,
            Self::Cosmetic(rule) => &rule.state,
        }
    }

    pub fn set_state(&mut self, state: RuleState) {
        match self {
            Self::Network(rule) => rule.state = state,
            Self::Cosmetic(rule) => rule.state = state,
        }
    }

    pub fn is_badfilter(&self) -> bool {
        matches!(self, Self::Network(rule) if rule.is_badfilter)
    }

    /// Classify slow or complex rules so callers can exclude whole families at once.
    /// Returns `None` for plain network rules and plain native CSS.
    pub fn family(&self) -> Option<RuleFamily> {
        match self {
            Self::Network(network) => network_family(network),
            Self::Cosmetic(cosmetic) => cosmetic_family(cosmetic),
        }
    }

    pub fn provenance(&self) -> &[Origin] {
        match self {
            Self::Network(rule) => &rule.provenance,
            Self::Cosmetic(rule) => &rule.provenance,
        }
    }

    pub fn dialect_gaps(&self) -> &[DialectGap] {
        match self {
            Self::Network(rule) => &rule.dialect_gaps,
            Self::Cosmetic(rule) => &rule.dialect_gaps,
        }
    }

    /// First semantic gap that is not explicitly accepted by the admission policy.
    pub fn unaccepted_semantic_gap(&self, accepted: &[String]) -> Option<&str> {
        self.dialect_gaps()
            .iter()
            .filter(|gap| gap.class == GapClass::SemanticGap)
            .map(|gap| gap.kind.as_str())
            .find(|kind| !accepted.iter().any(|accepted| accepted == kind))
    }
}

/// adblock folds nested procedural operators into a single `CssSelector`, so a cosmetic rule can
/// carry slow machinery while still looking like plain native CSS to the engine. Detect those
/// tokens in the original text; a top-level operator is already handled by `selector_ops`.
fn network_family(network: &NetworkRule) -> Option<RuleFamily> {
    if network.is_complete_regex
        || network.is_hostname_regex
        || (network.is_regex && !network.is_literal_boundary_regex)
    {
        Some(RuleFamily::Regex)
    } else if network.is_literal_boundary_regex {
        Some(RuleFamily::LiteralBoundaryRegex)
    } else if network
        .dialect_gaps
        .iter()
        .any(|gap| gap.class == GapClass::SemanticGap)
    {
        Some(RuleFamily::SemanticGap)
    } else {
        None
    }
}

fn cosmetic_family(cosmetic: &CosmeticRule) -> Option<RuleFamily> {
    if cosmetic.action_detail.is_some() {
        Some(RuleFamily::ActionOperator)
    } else if matches!(cosmetic.payload, CosmeticPayload::VettedScriptlet { .. }) {
        Some(RuleFamily::VettedScriptlet)
    } else if matches!(cosmetic.payload, CosmeticPayload::LightProcedural { .. }) {
        Some(RuleFamily::LightProcedural)
    } else if has_nested_slow_operator(&cosmetic.text) {
        Some(RuleFamily::NestedProcedural)
    } else {
        None
    }
}

fn has_nested_slow_operator(text: &str) -> bool {
    const MARKERS: &[&str] = &[
        ":matches-css",
        ":matches-path",
        ":min-text-length",
        ":upward",
        ":xpath",
        ":-abp-",
        "#?#",
        ":has-text(/",
        ":matches-attr(/",
    ];
    MARKERS.iter().any(|marker| text.contains(marker))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRecord {
    pub source_id: String,
    pub line_no: usize,
    pub raw_text: String,
    pub effective_text: Option<String>,
    pub dialect: Dialect,
    pub outcome: ParsedOutcome,
    /// Rewrites applied before ADMIT, with the original upstream rule text in `before`.
    #[serde(default)]
    pub preparse_receipts: Vec<RewriteReceipt>,
    /// The pre-rewrite rule shape used as the VERIFY baseline when one exists.
    #[serde(default)]
    pub baseline_rule: Option<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParsedOutcome {
    Network(NetworkRule),
    Cosmetic(CosmeticRule),
    Comment,
    Metadata,
    Directive,
    Empty,
    /// Expected hosts-file entries that are deliberately not converted to rules.
    Skipped {
        reason: String,
    },
    Unsupported {
        reason: ExclusionReason,
        gap: Option<DialectGap>,
    },
}

impl ParsedOutcome {
    pub fn family(&self) -> Option<RuleFamily> {
        match self {
            Self::Network(network) => network_family(network),
            Self::Cosmetic(cosmetic) => cosmetic_family(cosmetic),
            _ => None,
        }
    }

    pub fn unaccepted_semantic_gap(&self, accepted: &[String]) -> Option<&str> {
        let gaps = match self {
            Self::Network(network) => &network.dialect_gaps,
            Self::Cosmetic(cosmetic) => &cosmetic.dialect_gaps,
            _ => return None,
        };
        gaps.iter()
            .filter(|gap| gap.class == GapClass::SemanticGap)
            .map(|gap| gap.kind.as_str())
            .find(|kind| !accepted.iter().any(|accepted| accepted == kind))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResult {
    /// Rules that pass admission, after build-time `$badfilter` resolution.
    pub accepted: Vec<Rule>,
    /// Rules that would be visible to the engine before build-time `$badfilter` resolution.
    pub baseline: Vec<Rule>,
    /// Engine IDs cancelled by `$badfilter`; emission must never reintroduce them.
    pub badfilter_targets: BTreeSet<u64>,
    pub excluded: Vec<ExclusionRecord>,
    pub resource_decisions: Vec<ResourceDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRecord {
    pub source_id: String,
    pub line_no: usize,
    pub dialect: Dialect,
    pub text: String,
    pub reason: ExclusionReason,
}

impl ExclusionRecord {
    pub fn tsv_row(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.source_id,
            self.line_no,
            self.dialect.as_str(),
            self.reason.code(),
            self.reason.detail().replace('\t', " ").replace('\n', " "),
            self.text.replace('\t', " ").replace('\n', " ")
        )
    }
}

/// A rule removed by deterministic deduplication, not by admission policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedRecord {
    pub source_id: String,
    pub line_no: usize,
    pub dialect: Dialect,
    pub reason: String,
    pub detail: String,
    pub text: String,
}

impl DroppedRecord {
    pub fn tsv_row(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.source_id,
            self.line_no,
            self.dialect.as_str(),
            self.reason.replace('\t', " ").replace('\n', " "),
            self.detail.replace('\t', " ").replace('\n', " "),
            self.text.replace('\t', " ").replace('\n', " ")
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDecision {
    pub name: String,
    pub canonical_name: String,
    pub grade: ScriptletGrade,
    pub digest: String,
    pub permission: u8,
    pub source_id: String,
    pub source_permissions: u8,
    pub decision: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteReceipt {
    pub id: String,
    pub family: String,
    pub before: Vec<String>,
    pub after: String,
    pub source_id: String,
    pub checks: Vec<String>,
}

impl RewriteReceipt {
    pub fn tsv_row(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            self.id,
            self.family,
            self.before.join(" || ").replace('\t', " "),
            self.checks.join(";"),
            self.after.replace('\t', " ")
        )
    }
}

/// Metadata for a capped field in a machine-readable receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTruncation {
    pub bytes: usize,
    pub sha256: String,
}

/// A rewrite receipt with oversized payloads capped for `build.json`. The full receipt remains in
/// `rewrites.tsv`; truncation metadata records the original byte length and digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportReceipt {
    pub id: String,
    pub family: String,
    pub before: Vec<String>,
    pub after: String,
    pub source_id: String,
    pub checks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_truncated: Option<PayloadTruncation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_truncated: Option<PayloadTruncation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mismatch {
    pub case: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyCoverage {
    pub network_rules_total: usize,
    pub network_rules_probed: usize,
    pub rewrite_receipts_total: usize,
    pub rewrite_receipts_exercised: usize,
    pub cosmetic_hosts_total: usize,
    pub cosmetic_hosts_checked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub required: bool,
    pub mismatches: Vec<Mismatch>,
    pub cases_checked: usize,
    pub golden_rule_violations: usize,
    pub emit_order_violations: usize,
    #[serde(default)]
    pub coverage: VerifyCoverage,
}

impl Default for VerifyReport {
    fn default() -> Self {
        Self {
            required: false,
            mismatches: Vec::new(),
            cases_checked: 0,
            golden_rule_violations: 0,
            emit_order_violations: 0,
            coverage: VerifyCoverage::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub admitted_opt_bytes: usize,
    pub candidate_opt_bytes: usize,
    pub admitted_noopt_bytes: usize,
    pub candidate_noopt_bytes: usize,
    pub admitted_build_ms: u128,
    pub candidate_build_ms: u128,
    pub admitted_qps: f64,
    pub candidate_qps: f64,
    pub emit_order: String,
}

impl Default for BenchReport {
    fn default() -> Self {
        Self {
            admitted_opt_bytes: 0,
            candidate_opt_bytes: 0,
            admitted_noopt_bytes: 0,
            candidate_noopt_bytes: 0,
            admitted_build_ms: 0,
            candidate_build_ms: 0,
            admitted_qps: 0.0,
            candidate_qps: 0.0,
            emit_order: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReport {
    pub build_id: String,
    pub config_hash: String,
    pub profile_hash: String,
    pub lists_lock_hash: String,
    pub adblock_version: String,
    pub emit_order: String,
    pub metrics: BTreeMap<String, Value>,
    /// Deterministically sampled and payload-capped receipts for machine-readable reporting.
    pub receipts: Vec<ReportReceipt>,
    /// Number of receipts before sampling; the full set remains in `rewrites.tsv`.
    pub receipts_total: usize,
    /// SHA-256 of the canonical JSON for the full, uncapped receipt set.
    pub receipts_sha256: String,
    /// True when receipts were sampled or any receipt payload was capped.
    pub receipts_truncated: bool,
    pub verification: VerifyReport,
    pub bench: BenchReport,
}

impl BuildReport {
    pub fn new(
        build_id: String,
        config_hash: String,
        profile_hash: String,
        lists_lock_hash: String,
        config: &crate::Config,
    ) -> Self {
        Self {
            build_id,
            config_hash,
            profile_hash,
            lists_lock_hash,
            adblock_version: config.engine.adblock_version.clone(),
            emit_order: config.output.emit_order.clone(),
            metrics: BTreeMap::new(),
            receipts: Vec::new(),
            receipts_total: 0,
            receipts_sha256: String::new(),
            receipts_truncated: false,
            verification: VerifyReport::default(),
            bench: BenchReport::default(),
        }
    }

    pub fn metric(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.metrics.insert(key.into(), value.into());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub metrics: BTreeMap<String, Value>,
    pub dialects: BTreeMap<String, usize>,
    pub gaps: BTreeMap<String, usize>,
    pub eligibility: BTreeMap<String, usize>,
}

impl Default for AnalysisReport {
    fn default() -> Self {
        Self {
            metrics: BTreeMap::new(),
            dialects: BTreeMap::new(),
            gaps: BTreeMap::new(),
            eligibility: BTreeMap::new(),
        }
    }
}
