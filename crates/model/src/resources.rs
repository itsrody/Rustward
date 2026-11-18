//! Pinned official resource snapshot model.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use crate::{
    model::ScriptletGrade,
    util::{sha256_digest, sha256_hex},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Template,
    #[serde(rename = "application/javascript")]
    ApplicationJavascript,
    #[serde(rename = "fn/javascript")]
    FnJavascript,
    Other,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::ApplicationJavascript => "application/javascript",
            Self::FnJavascript => "fn/javascript",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficialResource {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub grade: ScriptletGrade,
    pub kind: ResourceKind,
    pub content: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub permission: u8,
    #[serde(default)]
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub commit: String,
    pub resources: Vec<OfficialResource>,
}

impl ResourceSnapshot {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read resource snapshot {}", path.display()))?;
        Self::from_bytes(&bytes, path)
    }

    /// Loads a snapshot only when its bytes match the digest pinned in the build config.
    pub fn load_verified(path: &Path, expected_sha256: &str) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read resource snapshot {}", path.display()))?;
        if !expected_sha256.is_empty() {
            let actual = sha256_hex(&bytes);
            if actual != expected_sha256 {
                bail!(
                    "resource snapshot digest mismatch for {}: expected {expected_sha256}, got {actual}",
                    path.display()
                );
            }
        }
        Self::from_bytes(&bytes, path)
    }

    fn from_bytes(bytes: &[u8], path: &Path) -> Result<Self> {
        let mut snapshot: Self = serde_json::from_slice(bytes)
            .with_context(|| format!("failed to parse resource snapshot {}", path.display()))?;
        for resource in &mut snapshot.resources {
            resource.digest = resource.compute_digest();
        }
        Ok(snapshot)
    }

    pub fn into_catalog(self) -> Result<ResourceCatalog> {
        ResourceCatalog::new(self)
    }
}

impl OfficialResource {
    pub fn compute_digest(&self) -> [u8; 32] {
        let canonical = (
            &self.name,
            &self.aliases,
            self.grade.as_str(),
            self.kind.as_str(),
            &self.content,
            &self.dependencies,
            self.permission,
        );
        sha256_digest(&serde_json::to_vec(&canonical).unwrap_or_default())
    }

    pub fn engine_resource(&self) -> adblock::resources::Resource {
        let kind = match self.kind {
            ResourceKind::Template => adblock::resources::ResourceType::Template,
            ResourceKind::ApplicationJavascript => adblock::resources::ResourceType::Mime(
                adblock::resources::MimeType::ApplicationJavascript,
            ),
            ResourceKind::FnJavascript => {
                adblock::resources::ResourceType::Mime(adblock::resources::MimeType::FnJavascript)
            }
            ResourceKind::Other => adblock::resources::ResourceType::Mime(
                adblock::resources::MimeType::from_extension(&self.name),
            ),
        };
        adblock::resources::Resource {
            name: self.name.clone(),
            aliases: self.aliases.clone(),
            kind,
            content: base64::engine::general_purpose::STANDARD.encode(self.content.as_bytes()),
            dependencies: self.dependencies.clone(),
            permission: adblock::resources::PermissionMask::from_bits(self.permission),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceCatalog {
    pub source: String,
    pub commit: String,
    pub resources: Vec<OfficialResource>,
    by_name: BTreeMap<String, usize>,
}

impl ResourceCatalog {
    pub fn new(snapshot: ResourceSnapshot) -> Result<Self> {
        let mut by_name = BTreeMap::new();
        for (index, resource) in snapshot.resources.iter().enumerate() {
            for name in std::iter::once(resource.name.as_str())
                .chain(resource.aliases.iter().map(String::as_str))
            {
                if let Some(existing) = by_name.insert(name.to_string(), index) {
                    if existing != index {
                        bail!("duplicate official resource name or alias: {name}");
                    }
                }
            }
        }
        Ok(Self {
            source: snapshot.source,
            commit: snapshot.commit,
            resources: snapshot.resources,
            by_name,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        ResourceSnapshot::load(path)?.into_catalog()
    }

    pub fn load_verified(path: &Path, expected_sha256: &str) -> Result<Self> {
        ResourceSnapshot::load_verified(path, expected_sha256)?.into_catalog()
    }

    pub fn empty() -> Self {
        Self {
            source: String::new(),
            commit: String::new(),
            resources: Vec::new(),
            by_name: BTreeMap::new(),
        }
    }

    pub fn find(&self, name: &str) -> Option<&OfficialResource> {
        self.by_name
            .get(name)
            .and_then(|index| self.resources.get(*index))
    }

    pub fn engine_resources(&self) -> Vec<adblock::resources::Resource> {
        self.resources
            .iter()
            .map(OfficialResource::engine_resource)
            .collect()
    }

    /// Returns the requested resource plus every transitive dependency, or an error if any name
    /// is missing from the official snapshot.
    pub fn dependency_closure(&self, name: &str) -> Result<Vec<&OfficialResource>> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![name.to_string()];
        let mut result = Vec::new();
        while let Some(current) = stack.pop() {
            let canonical = self
                .find(&current)
                .with_context(|| format!("resource {current} is not in the official snapshot"))?;
            if !seen.insert(canonical.name.clone()) {
                continue;
            }
            for dependency in &canonical.dependencies {
                stack.push(dependency.clone());
            }
            result.push(canonical);
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }
}
