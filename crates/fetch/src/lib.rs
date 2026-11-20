//! Deterministic source loading, pinning, caching, and lockfile generation.
//!
//! Local fixtures and `file://` URLs are read directly. HTTP(S) sources are content-addressed in
//! `cache/blobs/sha256/<digest>` and must carry a `sha256` pin in `config/sources.toml`, so a build
//! is reproducible and `--offline` can reuse a warm cache without network access.

use anyhow::{Context, Result, bail};
use model::{Config, Dialect, SourceConfig, SourceFormat};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use model::util::{format_rfc2822, normalize_list, sha256_hex};

const FETCHED_AT: &str = "1970-01-01T00:00:00Z";

/// Derives the aggregate `! Last modified` header from pinned source/include metadata. Only
/// parseable UTC dates contribute; the newest one wins so the list reflects its freshest input.
/// A lockfile with no parseable dates falls back to the Unix epoch rather than wall-clock time.
pub fn pinned_last_modified(lock: &ListsLock) -> String {
    let mut latest: Option<i64> = None;
    let entries = lock
        .sources
        .values()
        .chain(lock.includes.values().flat_map(|entries| entries.values()));
    for entry in entries {
        let Some(value) = &entry.last_modified else {
            continue;
        };
        if let Some(seconds) = parse_http_date(value) {
            latest = Some(latest.map_or(seconds, |current| current.max(seconds)));
        }
    }
    latest
        .map(format_rfc2822)
        .unwrap_or_else(|| format_rfc2822(0))
}

fn parse_http_date(value: &str) -> Option<i64> {
    let tokens: Vec<&str> = value.trim().split_whitespace().collect();
    if tokens.len() < 6 || !matches!(tokens[5], "GMT" | "UTC" | "+0000" | "-0000") {
        return None;
    }
    let day: i64 = tokens[1].parse().ok()?;
    if !(1..=31).contains(&day) {
        return None;
    }
    let month = match tokens[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = tokens[3].parse().ok()?;
    let mut clock = tokens[4].split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.parse().ok()?;
    if clock.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant's civil-to-days algorithm, valid for the Unix epoch and beyond.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchMode {
    Online,
    Offline,
}

#[derive(Debug, Clone)]
pub struct FetchedInclude {
    pub token: String,
    pub url: String,
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct FetchedSource {
    pub config: SourceConfig,
    pub text: String,
    pub sha256: String,
    pub final_url: String,
    pub includes: BTreeMap<String, FetchedInclude>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListsLock {
    #[serde(default)]
    pub sources: BTreeMap<String, LockEntry>,
    #[serde(default)]
    pub includes: BTreeMap<String, BTreeMap<String, LockEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub url: String,
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub fetched_at: String,
    pub dialect: Dialect,
    pub format: SourceFormat,
    pub priority: i32,
    pub enabled: bool,
    pub trusted: bool,
    pub permissions: u8,
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl ListsLock {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }
}

#[derive(Debug, Clone)]
struct Loaded {
    bytes: Vec<u8>,
    text: String,
    sha256: String,
    final_url: String,
    path: String,
    etag: Option<String>,
    last_modified: Option<String>,
}

struct Loader<'a> {
    root: &'a Path,
    mode: FetchMode,
    previous: ListsLock,
    client: Option<Client>,
}

impl<'a> Loader<'a> {
    fn new(root: &'a Path, mode: FetchMode, lock_path: &Path) -> Result<Self> {
        let previous = ListsLock::load(lock_path)?;
        let client = match mode {
            FetchMode::Online => Some(
                Client::builder()
                    .redirect(reqwest::redirect::Policy::limited(1))
                    .timeout(Duration::from_secs(30))
                    .user_agent(concat!("Rustward/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .context("failed to build HTTP client")?,
            ),
            FetchMode::Offline => None,
        };
        Ok(Self {
            root,
            mode,
            previous,
            client,
        })
    }

    fn load(
        &self,
        source: &SourceConfig,
        url: &str,
        expected: Option<&str>,
        previous: Option<&LockEntry>,
    ) -> Result<Loaded> {
        if url.starts_with("http://") || url.starts_with("https://") {
            self.load_remote(source, url, expected, previous)
        } else {
            self.load_local(source, url, expected)
        }
    }

    fn load_local(
        &self,
        source: &SourceConfig,
        url: &str,
        expected: Option<&str>,
    ) -> Result<Loaded> {
        let path = if let Some(local_path) = &source.path {
            self.root.join(local_path)
        } else if let Some(rest) = url.strip_prefix("file://") {
            self.root.join(rest)
        } else {
            bail!("unsupported local URL for source {}: {url}", source.id);
        };
        let bytes = fs::read(&path).with_context(|| {
            format!("failed to read source {} at {}", source.id, path.display())
        })?;
        let sha256 = verify_digest(&bytes, expected, &source.id)?;
        let text = normalize_list(&bytes)
            .with_context(|| format!("failed to normalize source {}", source.id))?;
        Ok(Loaded {
            bytes,
            text,
            sha256,
            final_url: url.to_string(),
            path: path.to_string_lossy().to_string(),
            etag: None,
            last_modified: source.last_modified.clone(),
        })
    }

    fn load_remote(
        &self,
        source: &SourceConfig,
        url: &str,
        expected: Option<&str>,
        previous: Option<&LockEntry>,
    ) -> Result<Loaded> {
        let expected =
            expected.with_context(|| format!("remote source {url} has no sha256 pin"))?;
        let cache_path = self.root.join("cache/blobs/sha256").join(expected);

        if let Ok(bytes) = fs::read(&cache_path) {
            let sha256 = verify_digest(&bytes, Some(expected), url)?;
            let text = normalize_list(&bytes)?;
            return Ok(Loaded {
                bytes,
                text,
                sha256,
                final_url: url.to_string(),
                path: cache_path.to_string_lossy().to_string(),
                etag: previous.and_then(|entry| entry.etag.clone()),
                last_modified: source
                    .last_modified
                    .clone()
                    .or_else(|| previous.and_then(|entry| entry.last_modified.clone())),
            });
        }
        if self.mode == FetchMode::Offline {
            bail!("offline build requires cached blob cache/blobs/sha256/{expected} for {url}");
        }
        let client = self
            .client
            .as_ref()
            .context("HTTP client is unavailable in offline mode")?;

        let mut request = client.get(url);
        if let Some(entry) = previous {
            if entry.sha256 == expected {
                if let Some(etag) = &entry.etag {
                    request = request.header(reqwest::header::IF_NONE_MATCH, etag);
                }
                if let Some(last_modified) = &entry.last_modified {
                    request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
                }
            }
        }

        let mut response = request
            .send()
            .with_context(|| format!("failed to fetch {url}"))?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(entry) = previous {
                let cached = PathBuf::from(&entry.path);
                if let Ok(bytes) = fs::read(&cached) {
                    let sha256 = verify_digest(&bytes, Some(expected), url)?;
                    let text = normalize_list(&bytes)?;
                    return Ok(Loaded {
                        bytes,
                        text,
                        sha256,
                        final_url: entry.url.clone(),
                        path: cached.to_string_lossy().to_string(),
                        etag: entry.etag.clone(),
                        last_modified: source
                            .last_modified
                            .clone()
                            .or_else(|| entry.last_modified.clone()),
                    });
                }
            }
            response = client
                .get(url)
                .send()
                .with_context(|| format!("failed to re-fetch {url} after 304"))?;
        }
        if !response.status().is_success() {
            bail!("fetch {url} returned HTTP {}", response.status());
        }
        let final_url = response.url().to_string();
        let etag = header_string(response.headers(), reqwest::header::ETAG);
        let last_modified = source
            .last_modified
            .clone()
            .or_else(|| header_string(response.headers(), reqwest::header::LAST_MODIFIED));
        let bytes = response
            .bytes()
            .with_context(|| format!("failed to read {url}"))?
            .to_vec();
        let sha256 = verify_digest(&bytes, Some(expected), url)?;
        let text = normalize_list(&bytes)?;
        write_cache_blob(&cache_path, &bytes)?;
        Ok(Loaded {
            bytes,
            text,
            sha256,
            final_url,
            path: cache_path.to_string_lossy().to_string(),
            etag,
            last_modified,
        })
    }
}

fn header_string(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn verify_digest(bytes: &[u8], expected: Option<&str>, label: &str) -> Result<String> {
    let actual = sha256_hex(bytes);
    if let Some(expected) = expected {
        if actual != expected {
            bail!(
                "sha256 pin mismatch for {label}: expected {expected}, got {actual}; update the pin after review"
            );
        }
    }
    Ok(actual)
}

fn write_cache_blob(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn lock_entry(source: &SourceConfig, loaded: &Loaded) -> LockEntry {
    LockEntry {
        url: loaded.final_url.clone(),
        path: loaded.path.clone(),
        sha256: loaded.sha256.clone(),
        bytes: loaded.bytes.len(),
        fetched_at: FETCHED_AT.to_string(),
        dialect: source.dialect,
        format: source.format,
        priority: source.priority,
        enabled: source.enabled,
        trusted: source.trusted,
        permissions: source.permissions,
        license: source.license.clone(),
        etag: loaded.etag.clone(),
        last_modified: loaded.last_modified.clone(),
    }
}

fn include_tokens(text: &str) -> Vec<String> {
    let mut tokens = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(token) = trimmed.strip_prefix("!#include ") {
            let token = token.trim().trim_matches('"').trim();
            if !token.is_empty() {
                tokens.insert(token.to_string());
            }
        }
    }
    tokens.into_iter().collect()
}

fn resolve_include_url(base_url: &str, root: &Path, token: &str) -> Result<String> {
    if token.starts_with("http://") || token.starts_with("https://") {
        return Ok(token.to_string());
    }
    if let Some(rest) = base_url.strip_prefix("file://") {
        let base_path = root.join(rest);
        let parent = base_path.parent().unwrap_or(root);
        return Ok(format!("file://{}", parent.join(token).display()));
    }
    let base =
        reqwest::Url::parse(base_url).with_context(|| format!("invalid base URL {base_url}"))?;
    Ok(base
        .join(token)
        .with_context(|| format!("failed to resolve include {token} against {base_url}"))?
        .to_string())
}

/// Fetches the current raw bytes of a URL and returns their digest without consulting pins/cache.
pub fn current_sha256(url: &str) -> Result<String> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::limited(1))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("Rustward/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to fetch {url}"))?;
    if !response.status().is_success() {
        bail!("fetch {url} returned HTTP {}", response.status());
    }
    let bytes = response
        .bytes()
        .with_context(|| format!("failed to read {url}"))?;
    Ok(sha256_hex(&bytes))
}

pub fn fetch_all(config: &Config, root: &Path) -> Result<(Vec<FetchedSource>, ListsLock)> {
    fetch_all_with_mode(config, root, FetchMode::Online)
}

/// Path of the lockfile belonging to the configured output directory.
pub fn lock_path(root: &Path, config: &Config) -> PathBuf {
    config
        .output
        .path
        .parent()
        .map(|parent| root.join(parent).join("lists.lock"))
        .unwrap_or_else(|| root.join("lists.lock"))
}

pub fn fetch_all_with_mode(
    config: &Config,
    root: &Path,
    mode: FetchMode,
) -> Result<(Vec<FetchedSource>, ListsLock)> {
    let loader = Loader::new(root, mode, &lock_path(root, config))?;
    let mut sources = Vec::new();
    let mut lock = ListsLock::default();

    for source in config.enabled_sources() {
        let previous = loader.previous.sources.get(&source.id);
        let loaded = loader.load(source, &source.url, source.sha256.as_deref(), previous)?;
        let (includes, include_locks) = load_includes(&loader, source, &loaded.text)?;
        let entry = lock_entry(source, &loaded);
        let sha256 = loaded.sha256.clone();
        let final_url = loaded.final_url.clone();
        sources.push(FetchedSource {
            config: source.clone(),
            text: loaded.text,
            sha256,
            final_url,
            includes,
        });
        lock.sources.insert(source.id.clone(), entry);
        lock.includes.insert(source.id.clone(), include_locks);
    }

    Ok((sources, lock))
}

fn load_includes(
    loader: &Loader<'_>,
    source: &SourceConfig,
    text: &str,
) -> Result<(
    BTreeMap<String, FetchedInclude>,
    BTreeMap<String, LockEntry>,
)> {
    let mut includes = BTreeMap::new();
    let mut locks = BTreeMap::new();
    let mut pending = VecDeque::new();
    let mut seen_urls = BTreeSet::new();

    for token in include_tokens(text) {
        let url = resolve_include_url(&source.url, loader.root, &token)?;
        pending.push_back((token, url));
    }

    while let Some((token, url)) = pending.pop_front() {
        if !seen_urls.insert(url.clone()) {
            continue;
        }
        let expected = source
            .include_sha256
            .get(&token)
            .or_else(|| source.include_sha256.get(&url))
            .cloned();
        let include_source = SourceConfig {
            id: format!("{}::include::{}", source.id, token),
            url: url.clone(),
            path: None,
            sha256: expected.clone(),
            include_sha256: BTreeMap::new(),
            dialect: source.dialect,
            format: source.format,
            host_semantics: source.host_semantics.clone(),
            priority: source.priority,
            enabled: source.enabled,
            trusted: source.trusted,
            permissions: source.permissions,
            license: source.license.clone(),
            last_modified: source.last_modified.clone(),
        };
        let previous = loader
            .previous
            .includes
            .get(&source.id)
            .and_then(|entries| entries.get(&token));
        let loaded = loader.load(&include_source, &url, expected.as_deref(), previous)?;
        for nested in include_tokens(&loaded.text) {
            let nested_url = resolve_include_url(&url, loader.root, &nested)?;
            pending.push_back((nested, nested_url));
        }
        includes.insert(
            token.clone(),
            FetchedInclude {
                token: token.clone(),
                url: url.clone(),
                path: loaded.path.clone(),
                sha256: loaded.sha256.clone(),
                bytes: loaded.bytes.len(),
                text: loaded.text.clone(),
            },
        );
        locks.insert(token, lock_entry(&include_source, &loaded));
    }

    Ok((includes, locks))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(last_modified: Option<&str>) -> LockEntry {
        LockEntry {
            url: "https://example.test/list.txt".to_string(),
            path: "cache/blobs/sha256/example".to_string(),
            sha256: "example".to_string(),
            bytes: 1,
            fetched_at: FETCHED_AT.to_string(),
            dialect: Dialect::Ubo,
            format: SourceFormat::Standard,
            priority: 50,
            enabled: true,
            trusted: false,
            permissions: 0,
            license: "test".to_string(),
            etag: None,
            last_modified: last_modified.map(str::to_string),
        }
    }

    #[test]
    fn parses_http_dates_in_utc_only() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Sat, 14 Nov 2026 13:05:16 +0000"),
            Some(1_794_661_516)
        );
        assert_eq!(parse_http_date("Sat, 14 Nov 2026 13:05:16 EST"), None);
        assert_eq!(parse_http_date("not a date"), None);
    }

    #[test]
    fn pinned_last_modified_uses_newest_parseable_pinned_date() {
        let mut lock = ListsLock::default();
        lock.sources.insert(
            "old".to_string(),
            entry(Some("Fri, 20 Nov 2026 03:49:29 GMT")),
        );
        lock.sources.insert(
            "new".to_string(),
            entry(Some("Sat, 21 Nov 2026 03:49:29 GMT")),
        );
        lock.sources
            .insert("bad".to_string(), entry(Some("not a date")));
        assert_eq!(
            pinned_last_modified(&lock),
            "Sat, 21 Nov 2026 03:49:29 +0000"
        );
    }

    #[test]
    fn pinned_last_modified_falls_back_to_epoch() {
        let lock = ListsLock::default();
        assert_eq!(
            pinned_last_modified(&lock),
            "Thu, 01 Jan 1970 00:00:00 +0000"
        );
    }
}
