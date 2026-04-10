//! Orchestrates running Maven against a mutated pom.xml.
//!
//! The original pom.xml is backed up, rewritten with the override, and restored
//! when [`PomBackup`] is dropped. The rename-based backup also handles abnormal
//! termination: if the tool crashes mid-run, the `.depintel-pom-backup` file is
//! left behind as evidence and future runs detect it.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bump::mutator::{discover_module_poms, mutate_pom_xml, try_patch_in_place};
use crate::collector::maven::{self, CollectGoals, MavenOutput};

/// Result of running `mvn compile` to verify a bump.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub success: bool,
    /// First ~20 lines of error output if the build failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_output: Option<String>,
}

/// Combined result from override collection + optional build verification.
pub struct OverrideResult {
    pub maven_output: MavenOutput,
    pub verify: Option<VerifyResult>,
}

const BACKUP_SUFFIX: &str = ".depintel-bump-backup";

fn backup_path_for(pom: &Path) -> PathBuf {
    let mut s = pom.as_os_str().to_os_string();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

/// RAII guard that restores one or more `pom.xml` files from sibling backups
/// when dropped. Used for multi-module projects where a bump may touch several
/// pom.xml files at once — all of them must be restored atomically on any
/// exit path (success, error, or panic).
pub struct MultiPomBackup {
    entries: Vec<(PathBuf, PathBuf)>, // (pom_path, backup_path)
    active: bool,
}

impl MultiPomBackup {
    /// Back up every pom file listed. Fails if ANY backup already exists.
    pub fn create(pom_files: &[PathBuf]) -> Result<Self> {
        // Pre-flight: refuse if any leftover backup is lying around. We want
        // the user to notice (and either delete or investigate) before we start
        // spraying mutations across modules.
        for pom in pom_files {
            let bkp = backup_path_for(pom);
            if bkp.exists() {
                anyhow::bail!(
                    "A leftover backup already exists at {}.\n\
                     This usually means a previous `depintel bump` run was interrupted before it could restore the original pom.xml.\n\
                     Verify that {} is the file you expect (diff against the backup), then delete the backup and retry.",
                    bkp.display(),
                    pom.display()
                );
            }
        }

        let mut entries: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(pom_files.len());
        for pom in pom_files {
            let bkp = backup_path_for(pom);
            if let Err(e) = std::fs::copy(pom, &bkp) {
                // Roll back any backups we've already created before bailing.
                for (_, done) in &entries {
                    let _ = std::fs::remove_file(done);
                }
                return Err(e).with_context(|| {
                    format!("Failed to back up {} to {}", pom.display(), bkp.display())
                });
            }
            entries.push((pom.clone(), bkp));
        }

        Ok(Self { entries, active: true })
    }

    /// Overwrite a specific pom file with new content.
    pub fn write_mutated(&self, pom_path: &Path, content: &str) -> Result<()> {
        std::fs::write(pom_path, content).with_context(|| {
            format!("Failed to write mutated pom.xml to {}", pom_path.display())
        })
    }

    /// Restore all files immediately (instead of waiting for Drop). Stops at
    /// the first failure and returns it, leaving any un-restored files in
    /// place with their backups so the user can recover manually.
    pub fn restore(mut self) -> Result<()> {
        self.active = false;
        for (pom, bkp) in &self.entries {
            std::fs::copy(bkp, pom)
                .with_context(|| format!("Failed to restore {}", pom.display()))?;
            let _ = std::fs::remove_file(bkp);
        }
        Ok(())
    }
}

impl Drop for MultiPomBackup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Best-effort restore on panic / early return.
        for (pom, bkp) in &self.entries {
            if let Err(e) = std::fs::copy(bkp, pom) {
                eprintln!(
                    "WARNING: failed to restore {} from backup {} during unwind: {}.\n\
                     The original file is preserved at the backup path — restore manually.",
                    pom.display(),
                    bkp.display(),
                    e
                );
                continue;
            }
            let _ = std::fs::remove_file(bkp);
        }
    }
}

/// Run Maven against `pom_dir` with the given override pin applied.
/// Writes Maven output files to `override_output_dir` so the main .depintel
/// cache is not disturbed.
///
/// In a multi-module project, every reachable pom.xml is probed: children
/// that already declare the target artifact are patched in place, so the
/// override actually takes effect regardless of where the original version
/// was set. If no module declares the artifact, a fallback
/// `<dependencyManagement>` entry is added to the root pom.xml instead.
pub fn collect_with_override(
    pom_dir: &Path,
    override_output_dir: &Path,
    group: &str,
    artifact: &str,
    target_version: &str,
    goals: CollectGoals,
    verify: bool,
) -> Result<OverrideResult> {
    // Discover every reachable pom.xml in the reactor.
    let module_poms = discover_module_poms(pom_dir).with_context(|| {
        format!("Failed to enumerate module poms under {}", pom_dir.display())
    })?;
    if module_poms.is_empty() {
        anyhow::bail!("No pom.xml found under {}", pom_dir.display());
    }

    // Refuse to proceed if any pom already has a leftover backup.
    for pom in &module_poms {
        let bkp = backup_path_for(pom);
        if bkp.exists() {
            anyhow::bail!(
                "Leftover bump backup detected at {}.\n\
                 A previous `depintel bump` run did not finish cleanly.\n\
                 Verify {} is correct, then delete the backup file.",
                bkp.display(),
                pom.display()
            );
        }
    }

    // Decide what to mutate in which file.
    // Pass 1: try to patch any existing declaration in any module.
    let mut mutations: Vec<(PathBuf, String)> = Vec::new(); // (path, new_content)
    let mut any_patched = false;
    for pom in &module_poms {
        let original = std::fs::read_to_string(pom)
            .with_context(|| format!("Failed to read {}", pom.display()))?;
        match try_patch_in_place(&original, group, artifact, target_version)? {
            Some(patched) => {
                any_patched = true;
                mutations.push((pom.clone(), patched));
            }
            None => {}
        }
    }

    // Pass 2: if nothing matched, inject a fallback `<dependencyManagement>`
    // override at the root pom. Maven will propagate it to every module that
    // inherits from the root parent, covering the common transitive-only case.
    if !any_patched {
        let root_pom = &module_poms[0];
        let original = std::fs::read_to_string(root_pom)
            .with_context(|| format!("Failed to read {}", root_pom.display()))?;
        let mutated = mutate_pom_xml(&original, group, artifact, target_version)?;
        mutations.push((root_pom.clone(), mutated));
    }

    // Set up the multi-file backup *before* we write anything.
    let files_to_backup: Vec<PathBuf> = mutations.iter().map(|(p, _)| p.clone()).collect();
    let backup = MultiPomBackup::create(&files_to_backup)?;
    for (path, new_content) in &mutations {
        backup.write_mutated(path, new_content)?;
    }

    // Run Maven. Errors propagate; Drop restores all POMs.
    let result = maven::collect_to(pom_dir, override_output_dir, goals);

    // If Maven succeeded and verify is requested, run `mvn compile` while POM is still mutated.
    let verify_result = if verify && result.is_ok() {
        match maven::discover_mvn(pom_dir) {
            Ok(mvn) => {
                eprintln!("Verifying build with mutated POM...");
                let output = Command::new(&mvn)
                    .args(["compile", "-q", "-B"])
                    .current_dir(pom_dir)
                    .output();
                match output {
                    Ok(o) => {
                        if o.status.success() {
                            Some(VerifyResult {
                                success: true,
                                error_output: None,
                            })
                        } else {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            let stdout = String::from_utf8_lossy(&o.stdout);
                            let combined = format!("{}\n{}", stdout, stderr);
                            let truncated: String = combined
                                .lines()
                                .filter(|l| l.contains("[ERROR]") || l.contains("COMPILATION ERROR"))
                                .take(20)
                                .collect::<Vec<_>>()
                                .join("\n");
                            Some(VerifyResult {
                                success: false,
                                error_output: Some(if truncated.is_empty() {
                                    combined.lines().take(20).collect::<Vec<_>>().join("\n")
                                } else {
                                    truncated
                                }),
                            })
                        }
                    }
                    Err(e) => Some(VerifyResult {
                        success: false,
                        error_output: Some(format!("Failed to run mvn compile: {}", e)),
                    }),
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };

    // Restore explicitly so we get a proper error instead of a silent drop.
    match (result, backup.restore()) {
        (Ok(out), Ok(())) => Ok(OverrideResult {
            maven_output: out,
            verify: verify_result,
        }),
        (Err(maven_err), Ok(())) => Err(maven_err.context(format!(
            "Maven failed while analysing override {}:{} → {}. \
             The original pom.xml has been restored.",
            group, artifact, target_version
        ))),
        (Ok(_), Err(restore_err)) => Err(restore_err.context(
            "Maven succeeded but restoring the original pom.xml failed — \
             check the backup file in the project directory.",
        )),
        (Err(maven_err), Err(restore_err)) => Err(maven_err.context(format!(
            "Maven failed AND restoring the original pom.xml also failed: {:#}. \
             The mutated pom.xml may still be on disk — check the .depintel-bump-backup file.",
            restore_err
        ))),
    }
}
