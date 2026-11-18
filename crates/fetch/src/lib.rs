//! Offline source loading and reproducible lockfile generation.
//!
//! Milestone M0 intentionally supports local fixtures and `file://` URLs. Remote fetching is
//! added behind the same [`FetchedSource`] boundary later.

use anyhow::{Context, Result, bail};
use model::{Config, Dialect, SourceConfig, SourceFormat};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use model::util::{normalize_list, sha256_hex};

#[derive(Debug, Clone)]
pub struct FetchedSource {
    pub config: SourceConfig,
    pub text: String,
    pub sha256: String,
    pub final_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListsLock {
    #[serde(default)]
    pub sources: BTreeMap<String, LockEntry>,
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

pub fn fetch_all(config: &Config, root: &Path) -> Result<(Vec<FetchedSource>, ListsLock)> {
    let mut sources = Vec::new();
    let mut lock = ListsLock::default();

    for source in config.enabled_sources() {
        let path = resolve_path(root, source)?;
        let bytes = fs::read(&path).with_context(|| {
            format!("failed to read source {} at {}", source.id, path.display())
        })?;
        let text = normalize_list(&bytes)
            .with_context(|| format!("failed to normalize source {}", source.id))?;
        let digest = sha256_hex(&bytes);
        sources.push(FetchedSource {
            config: source.clone(),
            text,
            sha256: digest.clone(),
            final_url: source.url.clone(),
        });
        lock.sources.insert(
            source.id.clone(),
            LockEntry {
                url: source.url.clone(),
                path: path.to_string_lossy().to_string(),
                sha256: digest,
                bytes: bytes.len(),
                fetched_at: "1970-01-01T00:00:00Z".to_string(),
                dialect: source.dialect,
                format: source.format,
                priority: source.priority,
                enabled: source.enabled,
                trusted: source.trusted,
                permissions: source.permissions,
                license: source.license.clone(),
            },
        );
    }

    Ok((sources, lock))
}

fn resolve_path(root: &Path, source: &SourceConfig) -> Result<PathBuf> {
    if let Some(path) = &source.path {
        return Ok(root.join(path));
    }
    if let Some(rest) = source.url.strip_prefix("file://") {
        return Ok(root.join(rest));
    }
    bail!(
        "source {} has no local path; remote fetching is not implemented in M0",
        source.id
    );
}
