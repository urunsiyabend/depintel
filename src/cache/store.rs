use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const CACHE_DIR: &str = ".depintel";

/// Cached Maven output data.
pub struct CachedData {
    pub effective_pom: String,
    pub verbose_tree: String,
    pub dep_list: String,
}

/// Get the cache directory path for a project.
pub fn cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(CACHE_DIR)
}

/// Check if cache is valid by comparing fingerprints.
/// Returns the cached data if valid, None if cache miss.
pub fn load_if_valid(project_dir: &Path, current_fingerprint: &str) -> Result<Option<CachedData>> {
    let dir = cache_dir(project_dir);

    let fp_path = dir.join("fingerprint");
    if !fp_path.exists() {
        return Ok(None);
    }

    let stored_fp = std::fs::read_to_string(&fp_path)
        .context("Failed to read cached fingerprint")?;

    if stored_fp.trim() != current_fingerprint {
        return Ok(None);
    }

    // Fingerprint matches — load cached files
    let effective_pom = read_cache_file(&dir, "effective-pom.xml")?;
    let verbose_tree = read_cache_file(&dir, "verbose-tree.txt")?;
    let dep_list = read_cache_file(&dir, "dep-list.txt")?;

    match (effective_pom, verbose_tree, dep_list) {
        (Some(ep), Some(vt), Some(dl)) => Ok(Some(CachedData {
            effective_pom: ep,
            verbose_tree: vt,
            dep_list: dl,
        })),
        _ => Ok(None), // Partial cache, treat as miss
    }
}

/// Save Maven output and fingerprint to cache.
pub fn save(
    project_dir: &Path,
    fingerprint: &str,
    effective_pom: &str,
    verbose_tree: &str,
    dep_list: &str,
) -> Result<()> {
    let dir = cache_dir(project_dir);
    std::fs::create_dir_all(&dir)?;

    std::fs::write(dir.join("fingerprint"), fingerprint)?;
    std::fs::write(dir.join("effective-pom.xml"), effective_pom)?;
    std::fs::write(dir.join("verbose-tree.txt"), verbose_tree)?;
    std::fs::write(dir.join("dep-list.txt"), dep_list)?;

    Ok(())
}

/// Partial cache — each field is Some if that file exists and fingerprint matches.
pub struct PartialCache {
    pub effective_pom: Option<String>,
    pub verbose_tree: Option<String>,
    pub dep_list: Option<String>,
}

/// Load whatever cache files exist (even if not all 3 are present).
/// Returns None values for missing files. Checks fingerprint first.
pub fn load_partial(project_dir: &Path, current_fingerprint: &str) -> Result<PartialCache> {
    let dir = cache_dir(project_dir);

    let fp_path = dir.join("fingerprint");
    if fp_path.exists() {
        let stored_fp = std::fs::read_to_string(&fp_path)?;
        if stored_fp.trim() != current_fingerprint {
            // Fingerprint mismatch — nothing is valid
            return Ok(PartialCache {
                effective_pom: None,
                verbose_tree: None,
                dep_list: None,
            });
        }
    } else {
        return Ok(PartialCache {
            effective_pom: None,
            verbose_tree: None,
            dep_list: None,
        });
    }

    Ok(PartialCache {
        effective_pom: read_cache_file(&dir, "effective-pom.xml")?,
        verbose_tree: read_cache_file(&dir, "verbose-tree.txt")?,
        dep_list: read_cache_file(&dir, "dep-list.txt")?,
    })
}

/// Delete the entire cache directory.
pub fn invalidate(project_dir: &Path) -> Result<()> {
    let dir = cache_dir(project_dir);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).context("Failed to remove cache directory")?;
    }
    Ok(())
}

fn read_cache_file(cache_dir: &Path, filename: &str) -> Result<Option<String>> {
    let path = cache_dir.join(filename);
    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read cache file: {}", filename))?;
        // Treat empty files as missing — a previous partial run may have written a placeholder.
        if content.is_empty() {
            Ok(None)
        } else {
            Ok(Some(content))
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        save(project, "abc123", "<pom/>", "tree output", "dep list").unwrap();

        let cached = load_if_valid(project, "abc123").unwrap();
        assert!(cached.is_some());

        let data = cached.unwrap();
        assert_eq!(data.effective_pom, "<pom/>");
        assert_eq!(data.verbose_tree, "tree output");
        assert_eq!(data.dep_list, "dep list");
    }

    #[test]
    fn test_load_fingerprint_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        save(project, "abc123", "<pom/>", "tree", "list").unwrap();

        let cached = load_if_valid(project, "different").unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn test_invalidate() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        save(project, "abc123", "<pom/>", "tree", "list").unwrap();
        assert!(cache_dir(project).exists());

        invalidate(project).unwrap();
        assert!(!cache_dir(project).exists());
    }
}
