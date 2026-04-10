use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use walkdir::WalkDir;

/// Compute a fingerprint of all pom.xml files in the project directory.
///
/// Process:
/// 1. Find all pom.xml files recursively
/// 2. Hash each file's contents with SHA-256
/// 3. Sort hashes to ensure deterministic order
/// 4. Concatenate and hash again for a single fingerprint
pub fn compute_fingerprint(project_dir: &Path) -> Result<String> {
    let mut pom_hashes: Vec<String> = Vec::new();

    for entry in WalkDir::new(project_dir)
        .into_iter()
        .filter_entry(|e| {
            // Always allow the root directory itself
            if e.depth() == 0 {
                return true;
            }
            let name = e.file_name().to_string_lossy();
            // Skip hidden dirs, target dirs, and .depintel cache
            !name.starts_with('.') && name != "target" && name != "node_modules"
        })
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && entry.file_name() == "pom.xml" {
            let contents = std::fs::read(entry.path())?;
            let hash = Sha256::digest(&contents);
            pom_hashes.push(hex::encode(hash));
        }
    }

    if pom_hashes.is_empty() {
        anyhow::bail!("No pom.xml files found in {}", project_dir.display());
    }

    // Sort for deterministic fingerprint
    pom_hashes.sort();

    // Combine all hashes into one
    let combined = pom_hashes.join("\n");
    let fingerprint = Sha256::digest(combined.as_bytes());

    Ok(hex::encode(fingerprint))
}

// Inline hex encoding to avoid adding a `hex` dependency
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_fingerprint_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(&pom, "<project></project>").unwrap();

        let fp1 = compute_fingerprint(dir.path()).unwrap();
        let fp2 = compute_fingerprint(dir.path()).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_changes_on_edit() {
        let dir = tempfile::tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(&pom, "<project>v1</project>").unwrap();

        let fp1 = compute_fingerprint(dir.path()).unwrap();

        fs::write(&pom, "<project>v2</project>").unwrap();
        let fp2 = compute_fingerprint(dir.path()).unwrap();

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_no_pom() {
        let dir = tempfile::tempdir().unwrap();
        let result = compute_fingerprint(dir.path());
        assert!(result.is_err());
    }
}
