//! Hashing, normalization, and small shared helpers.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

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
    // A leading `/` is how uBO writes a regex literal, with optional flags after the closing
    // slash (`/download/i`). Reject the whole shape rather than only `/.../`, otherwise flagged
    // regex arguments are mistaken for literals.
    if value.starts_with('/') || value.starts_with("regex:") {
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
    // `engine_id` covers mask, features, modifier, all four domain lists, pattern, and
    // hostname. The engine deliberately omits `tag` and source list permissions, so add
    // them here to avoid collapsing rules that behave differently in the engine.
    let tag = rule.tag.as_deref().unwrap_or("");
    let mut data = Vec::with_capacity(8 + 1 + tag.len() + 4);
    data.extend_from_slice(&rule.engine_id.to_be_bytes());
    data.push(0);
    data.extend_from_slice(tag.as_bytes());
    data.push(0);
    data.extend_from_slice(&rule.source_permissions.to_be_bytes());
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
        rule.permission,
        rule.source_permissions,
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

/// Current UTC time in the RFC 2822 form used by filter-list metadata headers.
pub fn build_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    format_rfc2822(seconds)
}

/// Formats Unix seconds as `Thu, 19 Nov 2026 12:34:56 +0000`.
pub fn format_rfc2822(seconds: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        WEEKDAYS[days.rem_euclid(7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    )
}

/// Howard Hinnant's civil-from-days algorithm, valid for the Unix epoch and beyond.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{format_rfc2822, is_literal_arg};

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            format_rfc2822(1_794_661_516),
            "Sat, 14 Nov 2026 13:05:16 +0000"
        );
    }

    #[test]
    fn rejects_regex_literal_arguments_with_or_without_flags() {
        assert!(is_literal_arg("Sponsored"));
        assert!(is_literal_arg("href"));
        assert!(!is_literal_arg("/Sponsored/"));
        assert!(!is_literal_arg("/Sponsored/i"));
        assert!(!is_literal_arg("regex:Sponsored"));
    }
}
