use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audit::osv::Vulnerability;

const DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60; // 24h

/// Disk-backed cache for OSV vulnerability lookups, keyed by `group:artifact:version`.
/// One JSON file per coordinate. Lives in the user's cache dir so it's shared across projects.
pub struct OsvCache {
    dir: PathBuf,
    ttl_seconds: u64,
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    vulns: Vec<Vulnerability>,
}

impl OsvCache {
    /// Construct a cache rooted under the OS cache dir, e.g.
    /// `%LOCALAPPDATA%/depintel/osv` on Windows or `~/.cache/depintel/osv` on Linux.
    pub fn default_location() -> Result<Self> {
        let base = dirs_cache_dir().context("Could not determine user cache directory")?;
        let dir = base.join("depintel").join("osv");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create cache dir {}", dir.display()))?;
        Ok(Self {
            dir,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        })
    }

    #[cfg(test)]
    pub fn with_ttl(mut self, seconds: u64) -> Self {
        self.ttl_seconds = seconds;
        self
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        self.dir.join(format!("{}.json", &hash[..32]))
    }

    /// Load cached vulns if present and still fresh.
    pub fn get(&self, key: &str) -> Result<Option<Vec<Vulnerability>>> {
        let path = self.path_for(key);
        if !path.exists() {
            return Ok(None);
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let entry: CacheEntry = match serde_json::from_str(&raw) {
            Ok(e) => e,
            Err(_) => return Ok(None), // corrupt entry — treat as miss
        };
        if now_unix().saturating_sub(entry.fetched_at) >= self.ttl_seconds {
            return Ok(None);
        }
        Ok(Some(entry.vulns))
    }

    /// Persist a lookup result. Best-effort: errors are surfaced so the caller can choose
    /// to ignore them, but cache failure shouldn't be fatal in audit flows.
    pub fn put(&self, key: &str, vulns: &[Vulnerability]) -> Result<()> {
        let entry = CacheEntry {
            fetched_at: now_unix(),
            vulns: vulns.to_vec(),
        };
        let path = self.path_for(key);
        let body = serde_json::to_string(&entry)?;
        std::fs::write(&path, body)
            .with_context(|| format!("Failed to write cache file {}", path.display()))?;
        Ok(())
    }

    /// Wipe every cached file. Used by --fresh.
    pub fn clear(&self) -> Result<()> {
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Locate a cross-platform cache directory without pulling in the `dirs` crate.
fn dirs_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(p) = std::env::var("LOCALAPPDATA") {
            return Some(PathBuf::from(p));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(p) = std::env::var("HOME") {
            return Some(PathBuf::from(p).join("Library").join("Caches"));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(p) = std::env::var("XDG_CACHE_HOME") {
            return Some(PathBuf::from(p));
        }
        if let Ok(p) = std::env::var("HOME") {
            return Some(PathBuf::from(p).join(".cache"));
        }
    }
    Some(std::env::temp_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::osv::VulnSeverity;

    fn temp_cache() -> OsvCache {
        let dir = tempfile::tempdir().unwrap().into_path();
        OsvCache {
            dir,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }

    #[test]
    fn put_then_get_roundtrip() {
        let cache = temp_cache();
        let v = Vulnerability {
            id: "GHSA-test".to_string(),
            aliases: vec!["CVE-1999-9999".to_string()],
            summary: "Test".to_string(),
            severity: VulnSeverity::High,
            cvss_score: Some(7.5),
            fixed_versions: vec!["1.0.1".to_string()],
            sources: vec!["GHSA".to_string()],
        };
        cache.put("g:a:1.0.0", &[v.clone()]).unwrap();
        let loaded = cache.get("g:a:1.0.0").unwrap().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "GHSA-test");
        assert_eq!(loaded[0].severity, VulnSeverity::High);
    }

    #[test]
    fn miss_returns_none() {
        let cache = temp_cache();
        assert!(cache.get("g:a:1.0.0").unwrap().is_none());
    }

    #[test]
    fn ttl_expired_returns_none() {
        let cache = temp_cache().with_ttl(0);
        cache.put("g:a:1.0.0", &[]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        // ttl=0 → anything older than now is expired
        assert!(cache.get("g:a:1.0.0").unwrap().is_none());
    }
}
