//! Hashing, normalization, and small shared helpers.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

use crate::model::{CosmeticRule, NetworkRule, Rule};

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_digest(data))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Normalizes a downloaded list: UTF-8, BOM removal, CRLF -> LF, no trailing whitespace.
pub fn normalize_list(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("list is not valid UTF-8")?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    Ok(text
        .lines()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Conservative literal check for lightweight cosmetic operator arguments.
pub fn is_literal_arg(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if (value.starts_with('/') && value.ends_with('/')) || value.starts_with("regex:") {
        return false;
    }
    !value.chars().any(|c| {
        matches!(
            c,
            '\\' | '^' | '$' | '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        )
    })
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

pub fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text.as_bytes())?;
    Ok(())
}

pub fn write_tsv<T: AsRef<str>>(
    path: &Path,
    header: &str,
    rows: impl IntoIterator<Item = T>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = String::from(header);
    output.push('\n');
    for row in rows {
        output.push_str(row.as_ref());
        output.push('\n');
    }
    fs::write(path, output.as_bytes())?;
    Ok(())
}

pub fn network_semantic_key(rule: &NetworkRule) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(&rule.engine_id.to_be_bytes());
    data.extend_from_slice(rule.tag.as_deref().unwrap_or("").as_bytes());
    hex::encode(sha256_digest(&data))
}

pub fn cosmetic_semantic_key(rule: &CosmeticRule) -> Result<String> {
    let key = (
        &rule.hosts,
        &rule.not_hosts,
        &rule.entities,
        &rule.not_entities,
        &rule.payload,
        &rule.selector_ops,
        &rule.action,
        &rule.action_detail,
        rule.generic,
    );
    Ok(hex::encode(sha256_digest(&serde_json::to_vec(&key)?)))
}

pub fn semantic_key(rule: &Rule) -> Result<String> {
    match rule {
        Rule::Network(network) => Ok(network_semantic_key(network)),
        Rule::Cosmetic(cosmetic) => cosmetic_semantic_key(cosmetic),
    }
}

pub fn sorted_unique(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
