//! Configuration schema for RustShield.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use crate::util::sha256_hex;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Dialect {
    Abp,
    Adguard,
    Ubo,
    Hosts,
    Auto,
}

impl Default for Dialect {
    fn default() -> Self {
        Self::Auto
    }
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abp => "abp",
            Self::Adguard => "adguard",
            Self::Ubo => "ubo",
            Self::Hosts => "hosts",
            Self::Auto => "auto",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    Standard,
    Hosts,
}

impl Default for SourceFormat {
    fn default() -> Self {
        Self::Standard
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub profile: String,
    pub adblock_version: String,
    #[serde(default)]
    pub permissions: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub path: PathBuf,
    #[serde(default = "default_emit_order")]
    pub emit_order: String,
    #[serde(default)]
    pub inline_audit_comments: bool,
    #[serde(default = "default_list_title")]
    pub title: String,
    #[serde(default = "default_list_last_modified")]
    pub last_modified: String,
    #[serde(default = "default_list_expires")]
    pub expires: String,
    #[serde(default = "default_list_description")]
    pub description: String,
}

fn default_emit_order() -> String {
    "compiler-friendly-v1".to_string()
}

fn default_list_title() -> String {
    "RustShield".to_string()
}

fn default_list_last_modified() -> String {
    "Sat, 14 Nov 2026 13:05:16 +0000".to_string()
}

fn default_list_expires() -> String {
    "2 days".to_string()
}

fn default_list_description() -> String {
    "Verified unified filter list for Brave adblock-rust".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub corpus: Vec<String>,
    #[serde(default)]
    pub max_mismatches: usize,
    #[serde(default = "default_max_cases")]
    pub max_cases: usize,
    #[serde(default = "default_max_cosmetic_hosts")]
    pub max_cosmetic_hosts: usize,
    #[serde(default = "default_bench_iterations")]
    pub bench_iterations: usize,
}

fn default_max_cases() -> usize {
    5_000
}

fn default_max_cosmetic_hosts() -> usize {
    256
}

fn default_bench_iterations() -> usize {
    3
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            required: false,
            corpus: vec!["generated".to_string(), "fixtures".to_string()],
            max_mismatches: 0,
            max_cases: default_max_cases(),
            max_cosmetic_hosts: default_max_cosmetic_hosts(),
            bench_iterations: default_bench_iterations(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectivesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub include_root: Option<PathBuf>,
}

impl Default for DirectivesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            env: Vec::new(),
            include_root: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenRuleConfig {
    #[serde(default = "default_true")]
    pub require_fast_native: bool,
    #[serde(default = "default_true")]
    pub require_official_resources: bool,
    #[serde(default = "default_true")]
    pub require_engine_trust: bool,
    #[serde(default = "default_true")]
    pub rewrite_or_exclude: bool,
    #[serde(default = "default_true")]
    pub retain_eligible_non_fusable: bool,
    #[serde(default = "default_true")]
    pub zero_violations: bool,
}

fn default_true() -> bool {
    true
}

impl Default for GoldenRuleConfig {
    fn default() -> Self {
        Self {
            require_fast_native: true,
            require_official_resources: true,
            require_engine_trust: true,
            rewrite_or_exclude: true,
            retain_eligible_non_fusable: true,
            zero_violations: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesConfig {
    pub ubo: UboResourcesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UboResourcesConfig {
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub scriptlets_path: String,
    #[serde(default)]
    pub snapshot_path: Option<PathBuf>,
    #[serde(default)]
    pub snapshot_sha256: String,
    #[serde(default = "default_trust_bit")]
    pub trust_bit: u8,
    #[serde(default = "default_true")]
    pub allow_standard: bool,
    #[serde(default = "default_true")]
    pub allow_trusted: bool,
    #[serde(default = "default_true")]
    pub require_realization: bool,
}

fn default_trust_bit() -> u8 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmeticConfig {
    #[serde(default = "default_true")]
    pub allow_native_css: bool,
    #[serde(default = "default_light_operators")]
    pub light_procedural_allowlist: Vec<String>,
    #[serde(default)]
    pub allow_regex_procedural_args: bool,
    #[serde(default)]
    pub allow_chained_procedural: bool,
    #[serde(default)]
    pub allow_action_operators: bool,
    #[serde(default = "default_true")]
    pub allow_vetted_scriptlets: bool,
    #[serde(default)]
    pub allow_css_injection: bool,
    #[serde(default)]
    pub allow_js_injection: bool,
}

fn default_light_operators() -> Vec<String> {
    vec!["has-text".to_string(), "matches-attr".to_string()]
}

impl Default for CosmeticConfig {
    fn default() -> Self {
        Self {
            allow_native_css: true,
            light_procedural_allowlist: default_light_operators(),
            allow_regex_procedural_args: false,
            allow_chained_procedural: false,
            allow_action_operators: false,
            allow_vetted_scriptlets: true,
            allow_css_injection: false,
            allow_js_injection: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
    #[serde(default)]
    pub ubo_host_semantics: bool,
    #[serde(default)]
    pub regex_fusion: bool,
}

impl Default for RewriteConfig {
    fn default() -> Self {
        Self {
            enabled: Vec::new(),
            ubo_host_semantics: false,
            regex_fusion: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Pin for the raw source bytes. Required for HTTP(S) sources.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Pins for `!#include` files, keyed by the include token used in the list.
    #[serde(default)]
    pub include_sha256: BTreeMap<String, String>,
    #[serde(default)]
    pub dialect: Dialect,
    #[serde(default)]
    pub format: SourceFormat,
    #[serde(default)]
    pub host_semantics: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default)]
    pub permissions: u8,
    #[serde(default)]
    pub license: String,
}

fn default_priority() -> i32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub engine: EngineConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub verify: VerifyConfig,
    #[serde(default)]
    pub directives: DirectivesConfig,
    #[serde(default)]
    pub golden_rule: GoldenRuleConfig,
    #[serde(default)]
    pub resources: Option<ResourcesConfig>,
    #[serde(default)]
    pub cosmetic: CosmeticConfig,
    #[serde(default)]
    pub rewrite: RewriteConfig,
    #[serde(default)]
    pub source: Vec<SourceConfig>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("failed to read config {}", path.display()))?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("config {} is not UTF-8", path.display()))?;
        toml::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
    }

    pub fn config_hash(&self, path: &Path) -> Result<String> {
        let bytes = fs::read(path)?;
        let mut material = bytes;
        material.extend_from_slice(self.engine.adblock_version.as_bytes());
        material.extend_from_slice(self.output.emit_order.as_bytes());
        Ok(sha256_hex(&material))
    }

    pub fn profile_hash(&self, root: &Path) -> String {
        let profile_path = root.join("config/profiles.toml");
        let profile_bytes = fs::read(&profile_path).unwrap_or_default();
        let mut material = profile_bytes;
        material.extend_from_slice(self.engine.profile.as_bytes());
        material.extend_from_slice(&[self.engine.permissions]);
        sha256_hex(&material)
    }

    pub fn enabled_sources(&self) -> impl Iterator<Item = &SourceConfig> {
        self.source.iter().filter(|source| source.enabled)
    }

    pub fn rewrite_enabled(&self, family: &str) -> bool {
        self.rewrite.enabled.iter().any(|item| item == family)
    }
}
