use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

/// A parsed reference into a GitHub repository.
#[derive(Debug)]
struct GithubRef {
    owner: String,
    repo: String,
    /// None means "use the default branch".
    branch: Option<String>,
    /// Path inside the repo to a directory or pom.xml file. Empty = repo root.
    sub_path: String,
}

/// Resolve a remote URL to a local directory containing a pom.xml.
///
/// Supported URL forms:
///   * `https://raw.githubusercontent.com/owner/repo/branch/path/to/pom.xml`
///   * `https://github.com/owner/repo`
///   * `https://github.com/owner/repo/blob/branch/path/to/pom.xml`
///   * `https://github.com/owner/repo/tree/branch/path/to/dir`
///
/// Strategy: shallow-clone the repository into a stable temp directory keyed by
/// (owner, repo, branch). Subsequent runs against the same repo reuse the clone.
///
/// If `offline` is true, will only return a cached clone — never hits the network.
pub fn fetch_pom_to_tempdir(url: &str, offline: bool) -> Result<PathBuf> {
    let gh = parse_github_url(url)
        .with_context(|| format!("Could not parse '{}' as a supported GitHub URL", url))?;

    // Cache directory keyed by owner+repo+branch (sub-path doesn't affect the clone).
    let mut hasher = Sha256::new();
    hasher.update(gh.owner.as_bytes());
    hasher.update(b"/");
    hasher.update(gh.repo.as_bytes());
    hasher.update(b"@");
    hasher.update(gh.branch.as_deref().unwrap_or("").as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    let clone_dir = std::env::temp_dir()
        .join("depintel-remote")
        .join(&hash[..16]);

    // Clone if not already present, otherwise reuse.
    if !clone_dir.join(".git").exists() {
        if offline {
            anyhow::bail!(
                "No cached clone for {}/{} (branch {:?}) and --offline prevents fetching.\n\
                 Run once without --offline to populate the cache, or omit --offline.",
                gh.owner,
                gh.repo,
                gh.branch
            );
        }
        if clone_dir.exists() {
            // Half-baked dir from a previous failure — wipe it.
            let _ = std::fs::remove_dir_all(&clone_dir);
        }
        std::fs::create_dir_all(clone_dir.parent().unwrap()).ok();

        ensure_git_available()?;

        let repo_url = format!("https://github.com/{}/{}.git", gh.owner, gh.repo);
        eprintln!(
            "Sparse-cloning {} (only {} + parent POMs)...",
            repo_url,
            if gh.sub_path.is_empty() { "/" } else { &gh.sub_path }
        );

        // Step 1: clone with --no-checkout, sparse, blobless. This skips the working tree
        // entirely so we don't pay for huge repos like Apache Druid.
        let mut clone_cmd = Command::new("git");
        clone_cmd
            .arg("-c")
            .arg("core.longpaths=true")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--filter=blob:none")
            .arg("--sparse")
            .arg("--no-checkout");
        if let Some(ref b) = gh.branch {
            clone_cmd.arg("--branch").arg(b);
        }
        clone_cmd.arg(&repo_url).arg(&clone_dir);

        let out = clone_cmd
            .output()
            .with_context(|| format!("Failed to invoke git for {}", repo_url))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_dir_all(&clone_dir);
            bail!(
                "git clone failed for {}{}:\n{}",
                repo_url,
                gh.branch
                    .as_deref()
                    .map(|b| format!(" (branch '{}')", b))
                    .unwrap_or_default(),
                stderr.trim()
            );
        }

        // Step 2: pull EVERY pom.xml in the repo. Maven needs the full parent chain
        // (and in monorepos like Hadoop the parent can live in a sibling subtree, not
        // along the target path), so it's simpler and more reliable to include them all.
        // POMs are tiny — even huge repos like Druid have <200 of them, total ~MB.
        // We deliberately exclude src/ etc. so we don't pay for the actual source tree.
        let patterns: Vec<String> = vec!["**/pom.xml".to_string()];

        let mut sc_cmd = Command::new("git");
        sc_cmd
            .arg("-C")
            .arg(&clone_dir)
            .arg("sparse-checkout")
            .arg("set")
            .arg("--no-cone");
        for p in &patterns {
            sc_cmd.arg(p);
        }
        let out = sc_cmd
            .output()
            .with_context(|| "Failed to set sparse-checkout patterns")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_dir_all(&clone_dir);
            bail!("git sparse-checkout failed:\n{}", stderr.trim());
        }

        // Step 3: actually materialize the working tree.
        let out = Command::new("git")
            .arg("-c")
            .arg("core.longpaths=true")
            .arg("-C")
            .arg(&clone_dir)
            .arg("checkout")
            .output()
            .with_context(|| "Failed to invoke git checkout")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_dir_all(&clone_dir);
            bail!("git checkout failed:\n{}", stderr.trim());
        }

        eprintln!("Cloned (sparse) to {}", clone_dir.display());
    } else {
        eprintln!("Reusing cached clone at {}", clone_dir.display());
    }

    // Locate the pom.xml inside the clone.
    locate_pom(&clone_dir, &gh.sub_path)
}

/// Parse a github.com / raw.githubusercontent.com URL into its components.
fn parse_github_url(url: &str) -> Option<GithubRef> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, rest) = stripped.split_once('/')?;
    let parts: Vec<&str> = rest.split('/').collect();

    match host {
        "raw.githubusercontent.com" => {
            // owner/repo/branch/...path
            if parts.len() < 3 {
                return None;
            }
            let owner = parts[0].to_string();
            let repo = parts[1].to_string();
            let branch = parts[2].to_string();
            let sub_path = parts[3..].join("/");
            Some(GithubRef {
                owner,
                repo,
                branch: Some(branch),
                sub_path,
            })
        }
        "github.com" => {
            if parts.len() < 2 {
                return None;
            }
            let owner = parts[0].to_string();
            let repo = parts[1].trim_end_matches(".git").to_string();
            // Forms:
            //   github.com/owner/repo
            //   github.com/owner/repo/tree/branch/...
            //   github.com/owner/repo/blob/branch/...
            if parts.len() == 2 {
                return Some(GithubRef {
                    owner,
                    repo,
                    branch: None,
                    sub_path: String::new(),
                });
            }
            let kind = parts[2];
            if (kind == "tree" || kind == "blob") && parts.len() >= 4 {
                let branch = parts[3].to_string();
                let sub_path = parts[4..].join("/");
                Some(GithubRef {
                    owner,
                    repo,
                    branch: Some(branch),
                    sub_path,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Find pom.xml inside a clone given an optional sub-path.
fn locate_pom(clone_dir: &std::path::Path, sub_path: &str) -> Result<PathBuf> {
    if sub_path.is_empty() {
        let pom = clone_dir.join("pom.xml");
        if pom.exists() {
            return Ok(clone_dir.to_path_buf());
        }
        bail!(
            "No pom.xml found at clone root {}. Use a URL that points to a specific module directory.",
            clone_dir.display()
        );
    }

    let target = clone_dir.join(sub_path);
    if target.is_file() && target.file_name().and_then(|n| n.to_str()) == Some("pom.xml") {
        // URL pointed at a pom.xml file directly — return its parent directory.
        return Ok(target.parent().unwrap().to_path_buf());
    }
    if target.is_dir() {
        let pom = target.join("pom.xml");
        if pom.exists() {
            return Ok(target);
        }
        bail!(
            "No pom.xml found in {} (sub-path '{}'). Check the URL points to a Maven module.",
            target.display(),
            sub_path
        );
    }
    bail!(
        "Path '{}' does not exist inside cloned repo at {}",
        sub_path,
        clone_dir.display()
    );
}

fn ensure_git_available() -> Result<()> {
    match Command::new("git").arg("--version").output() {
        Ok(out) if out.status.success() => Ok(()),
        _ => bail!(
            "git is required to fetch remote POMs but was not found on PATH.\n\
             Install git from https://git-scm.com or use --pom <local-dir> instead."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_raw_github_url() {
        let r = parse_github_url(
            "https://raw.githubusercontent.com/apache/spark/master/core/pom.xml",
        )
        .unwrap();
        assert_eq!(r.owner, "apache");
        assert_eq!(r.repo, "spark");
        assert_eq!(r.branch.as_deref(), Some("master"));
        assert_eq!(r.sub_path, "core/pom.xml");
    }

    #[test]
    fn parse_github_blob_url() {
        let r = parse_github_url(
            "https://github.com/apache/druid/blob/master/extensions-core/avro-extensions/pom.xml",
        )
        .unwrap();
        assert_eq!(r.owner, "apache");
        assert_eq!(r.repo, "druid");
        assert_eq!(r.branch.as_deref(), Some("master"));
        assert_eq!(r.sub_path, "extensions-core/avro-extensions/pom.xml");
    }

    #[test]
    fn parse_github_tree_url() {
        let r = parse_github_url(
            "https://github.com/apache/druid/tree/master/extensions-core/avro-extensions",
        )
        .unwrap();
        assert_eq!(r.branch.as_deref(), Some("master"));
        assert_eq!(r.sub_path, "extensions-core/avro-extensions");
    }

    #[test]
    fn parse_github_root_url() {
        let r = parse_github_url("https://github.com/spring-projects/spring-petclinic").unwrap();
        assert_eq!(r.owner, "spring-projects");
        assert_eq!(r.repo, "spring-petclinic");
        assert_eq!(r.branch, None);
        assert_eq!(r.sub_path, "");
    }

    #[test]
    fn parse_github_url_strips_dot_git() {
        let r = parse_github_url("https://github.com/apache/spark.git").unwrap();
        assert_eq!(r.repo, "spark");
    }

    #[test]
    fn parse_unsupported_host_returns_none() {
        assert!(parse_github_url("https://gitlab.com/foo/bar").is_none());
        assert!(parse_github_url("not a url").is_none());
    }
}
