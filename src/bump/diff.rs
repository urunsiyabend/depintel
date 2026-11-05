//! Graph + CVE diff between baseline and override analyses.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::audit::osv::{VulnSeverity, Vulnerability};
use crate::audit::report::AuditReport;
use crate::graph::builder::DepGraph;
use crate::graph::conflict::{self, ConflictReport};
use crate::model::ArtifactKey;

#[derive(Debug, Clone, Serialize)]
pub struct VersionChange {
    pub group: String,
    pub artifact: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactRef {
    pub group: String,
    pub artifact: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct GraphDiff {
    pub version_changes: Vec<VersionChange>,
    pub added: Vec<ArtifactRef>,
    pub removed: Vec<ArtifactRef>,
}

#[derive(Debug, Serialize)]
pub struct ConflictDiff {
    pub new: Vec<ConflictSummary>,
    pub resolved: Vec<ConflictSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictSummary {
    pub artifact: String,
    pub severity: String,
    pub selected: String,
    pub overridden: Vec<String>,
    pub version_jump: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveEntry {
    pub id: String,
    pub severity: String,
    pub summary: String,
    pub artifact: String,
}

#[derive(Debug, Serialize)]
pub struct CveDelta {
    pub fixed: Vec<CveEntry>,
    pub introduced: Vec<CveEntry>,
    pub unchanged_count: usize,
}

/// Build a map from ArtifactKey → distinct selected versions by walking
/// version_requests. A combined multi-module graph can select several.
fn selected_versions(g: &DepGraph) -> HashMap<ArtifactKey, Vec<String>> {
    let mut out: HashMap<ArtifactKey, Vec<String>> = HashMap::new();
    for (key, requests) in &g.version_requests {
        let mut versions: Vec<String> = requests
            .iter()
            .filter(|r| r.selected)
            .map(|r| r.version.clone())
            .collect();
        if versions.is_empty() {
            continue;
        }
        versions.sort();
        versions.dedup();
        out.insert(key.clone(), versions);
    }
    out
}

pub fn diff_graphs(baseline: &DepGraph, override_: &DepGraph) -> GraphDiff {
    let b = selected_versions(baseline);
    let o = selected_versions(override_);

    let b_keys: HashSet<&ArtifactKey> = b.keys().collect();
    let o_keys: HashSet<&ArtifactKey> = o.keys().collect();

    let mut version_changes: Vec<VersionChange> = Vec::new();
    let mut added: Vec<ArtifactRef> = Vec::new();
    let mut removed: Vec<ArtifactRef> = Vec::new();

    for k in b_keys.intersection(&o_keys) {
        let bv = &b[*k];
        let ov = &o[*k];
        let lost: Vec<&String> = bv.iter().filter(|v| !ov.contains(*v)).collect();
        let gained: Vec<&String> = ov.iter().filter(|v| !bv.contains(*v)).collect();
        if lost.is_empty() && gained.is_empty() {
            continue;
        }
        // Module identity is gone at this level, so pairing is best effort. When only
        // one side changed, a module moved from or to a version another module keeps.
        let from: Vec<&String> = if lost.is_empty() {
            bv.iter().rev().take(1).collect()
        } else {
            lost
        };
        let to: Vec<&String> = if gained.is_empty() {
            ov.iter().rev().take(1).collect()
        } else {
            gained
        };
        for i in 0..from.len().max(to.len()) {
            version_changes.push(VersionChange {
                group: k.group_id.clone(),
                artifact: k.artifact_id.clone(),
                from: from[i.min(from.len() - 1)].clone(),
                to: to[i.min(to.len() - 1)].clone(),
            });
        }
    }
    for k in o_keys.difference(&b_keys) {
        for version in &o[*k] {
            added.push(ArtifactRef {
                group: k.group_id.clone(),
                artifact: k.artifact_id.clone(),
                version: version.clone(),
            });
        }
    }
    for k in b_keys.difference(&o_keys) {
        for version in &b[*k] {
            removed.push(ArtifactRef {
                group: k.group_id.clone(),
                artifact: k.artifact_id.clone(),
                version: version.clone(),
            });
        }
    }

    version_changes.sort_by(|a, b| format!("{}:{}", a.group, a.artifact).cmp(&format!("{}:{}", b.group, b.artifact)));
    added.sort_by(|a, b| format!("{}:{}", a.group, a.artifact).cmp(&format!("{}:{}", b.group, b.artifact)));
    removed.sort_by(|a, b| format!("{}:{}", a.group, a.artifact).cmp(&format!("{}:{}", b.group, b.artifact)));

    GraphDiff {
        version_changes,
        added,
        removed,
    }
}

pub fn diff_conflicts(baseline: &DepGraph, override_: &DepGraph) -> ConflictDiff {
    let b_reports = conflict::detect_conflicts(baseline, &[]);
    let o_reports = conflict::detect_conflicts(override_, &[]);

    let b_keys: HashSet<String> = b_reports.iter().map(|r| r.key.to_string()).collect();
    let o_keys: HashSet<String> = o_reports.iter().map(|r| r.key.to_string()).collect();

    let to_summary = |r: &ConflictReport| ConflictSummary {
        artifact: r.key.to_string(),
        severity: r.severity.as_str().to_string(),
        selected: r.selected_version.clone(),
        overridden: r.overridden_versions.clone(),
        version_jump: r.version_jump.as_str().to_string(),
    };

    let new: Vec<ConflictSummary> = o_reports
        .iter()
        .filter(|r| !b_keys.contains(&r.key.to_string()))
        .map(to_summary)
        .collect();
    let resolved: Vec<ConflictSummary> = b_reports
        .iter()
        .filter(|r| !o_keys.contains(&r.key.to_string()))
        .map(to_summary)
        .collect();

    ConflictDiff { new, resolved }
}

pub fn diff_cves(baseline: &AuditReport, override_: &AuditReport) -> CveDelta {
    let sev_rank = |s: &str| match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    };

    // Build (artifact_coord, cve_id) → entry maps for both sides.
    let mut b_map: HashMap<(String, String), CveEntry> = HashMap::new();
    let mut o_map: HashMap<(String, String), CveEntry> = HashMap::new();

    let ingest = |map: &mut HashMap<(String, String), CveEntry>, r: &AuditReport| {
        for f in &r.findings {
            let coord = format!("{}:{}", f.group, f.artifact);
            for v in &f.vulnerabilities {
                let id = preferred_id(v);
                let key = (coord.clone(), id.clone());
                let entry = map.entry(key).or_insert_with(|| CveEntry {
                    id: id.clone(),
                    severity: v.severity.as_str().to_string(),
                    summary: v.summary.lines().next().unwrap_or("").trim().to_string(),
                    artifact: coord.clone(),
                });
                // Several advisory records can share a CVE; the worst rating decides risk.
                if sev_rank(v.severity.as_str()) < sev_rank(&entry.severity) {
                    entry.severity = v.severity.as_str().to_string();
                }
            }
        }
    };
    ingest(&mut b_map, baseline);
    ingest(&mut o_map, override_);

    let b_keys: HashSet<&(String, String)> = b_map.keys().collect();
    let o_keys: HashSet<&(String, String)> = o_map.keys().collect();

    // Per-(artifact, cve_id) resolution. A CVE that affects multiple artifacts
    // and is cleared for one of them must show up under `fixed` even if the
    // same ID still hits another artifact. Previously we compared IDs globally
    // and lost that fidelity.
    let mut fixed: Vec<CveEntry> = b_map
        .iter()
        .filter(|(k, _)| !o_keys.contains(k))
        .map(|(_, v)| v.clone())
        .collect();
    let mut introduced: Vec<CveEntry> = o_map
        .iter()
        .filter(|(k, _)| !b_keys.contains(k))
        .map(|(_, v)| v.clone())
        .collect();

    let unchanged_count = b_keys.intersection(&o_keys).count();

    fixed.sort_by(|a, b| sev_rank(&a.severity).cmp(&sev_rank(&b.severity)).then_with(|| a.id.cmp(&b.id)));
    introduced.sort_by(|a, b| sev_rank(&a.severity).cmp(&sev_rank(&b.severity)).then_with(|| a.id.cmp(&b.id)));

    CveDelta {
        fixed,
        introduced,
        unchanged_count,
    }
}

/// Prefer a human-friendly CVE id when available.
fn preferred_id(v: &Vulnerability) -> String {
    if let Some(cve) = v.aliases.iter().find(|a| a.starts_with("CVE-")) {
        return cve.clone();
    }
    v.id.clone()
}

/// Used by the scorer.
pub fn any_critical_or_high_in(entries: &[CveEntry]) -> bool {
    entries
        .iter()
        .any(|e| e.severity == "CRITICAL" || e.severity == "HIGH")
}

pub fn any_medium_in(entries: &[CveEntry]) -> bool {
    entries.iter().any(|e| e.severity == "MEDIUM")
}

// Explicit re-export to silence unused-import warnings when compiling.
#[allow(dead_code)]
pub const _VULN_SEVERITY_USED: Option<VulnSeverity> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::report::{AuditFinding, AuditSummary};
    use crate::collector::verbose_tree::parse_verbose_tree;
    use crate::graph::builder::build_combined_graph;

    fn graph(input: &str) -> DepGraph {
        build_combined_graph(&parse_verbose_tree(input).unwrap())
    }

    fn report(vulnerabilities: Vec<Vulnerability>) -> AuditReport {
        AuditReport {
            module: "test".to_string(),
            summary: AuditSummary::default(),
            findings: vec![AuditFinding {
                group: "org.example".to_string(),
                artifact: "lib".to_string(),
                version: "1.0".to_string(),
                scope: "compile".to_string(),
                direct: true,
                paths: vec![],
                vulnerabilities,
                max_severity: VulnSeverity::Critical,
            }],
            artifacts_scanned: 1,
        }
    }

    fn record(id: &str, severity: VulnSeverity) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            summary: String::new(),
            severity,
            cvss_score: None,
            fixed_versions: vec![],
            sources: vec![],
            unfixed_from: vec![],
            last_affected: vec![],
        }
    }

    #[test]
    fn duplicate_cve_records_report_highest_severity() {
        let empty = AuditReport {
            module: "test".to_string(),
            summary: AuditSummary::default(),
            findings: vec![],
            artifacts_scanned: 0,
        };
        let introduced = report(vec![
            record("GHSA-unrated", VulnSeverity::Unknown),
            record("OSV-rated", VulnSeverity::Critical),
        ]);
        let delta = diff_cves(&empty, &introduced);
        assert_eq!(delta.introduced.len(), 1);
        assert_eq!(delta.introduced[0].severity, "CRITICAL");
        assert!(any_critical_or_high_in(&delta.introduced));
    }

    #[test]
    fn version_change_in_any_module_is_reported() {
        let baseline = graph(
            "org.fixture:module-a:jar:1.0\n\\- org.example:lib:jar:1.0:compile\n\
             org.fixture:module-b:jar:1.0\n\\- org.example:lib:jar:2.0:compile",
        );
        let override_ = graph(
            "org.fixture:module-a:jar:1.0\n\\- org.example:lib:jar:1.0:compile\n\
             org.fixture:module-b:jar:1.0\n\\- org.example:lib:jar:3.0:compile",
        );
        let diff = diff_graphs(&baseline, &override_);
        assert_eq!(diff.version_changes.len(), 1);
        assert_eq!(diff.version_changes[0].from, "2.0");
        assert_eq!(diff.version_changes[0].to, "3.0");
        assert!(diff.added.is_empty() && diff.removed.is_empty());
    }

    #[test]
    fn module_diverging_from_shared_version_is_reported() {
        let baseline = graph(
            "org.fixture:module-a:jar:1.0\n\\- org.example:lib:jar:1.0:compile\n\
             org.fixture:module-b:jar:1.0\n\\- org.example:lib:jar:1.0:compile",
        );
        let override_ = graph(
            "org.fixture:module-a:jar:1.0\n\\- org.example:lib:jar:1.0:compile\n\
             org.fixture:module-b:jar:1.0\n\\- org.example:lib:jar:3.0:compile",
        );
        let diff = diff_graphs(&baseline, &override_);
        assert_eq!(diff.version_changes.len(), 1);
        assert_eq!(diff.version_changes[0].from, "1.0");
        assert_eq!(diff.version_changes[0].to, "3.0");
    }

    #[test]
    fn single_module_version_change_is_unchanged() {
        let baseline = graph("org.fixture:app:jar:1.0\n\\- org.example:lib:jar:1.0:compile");
        let override_ = graph("org.fixture:app:jar:1.0\n\\- org.example:lib:jar:2.0:compile");
        let diff = diff_graphs(&baseline, &override_);
        assert_eq!(diff.version_changes.len(), 1);
        assert_eq!(diff.version_changes[0].from, "1.0");
        assert_eq!(diff.version_changes[0].to, "2.0");
    }

    fn changes(baseline: &str, override_: &str) -> Vec<(String, String)> {
        diff_graphs(&graph(baseline), &graph(override_))
            .version_changes
            .into_iter()
            .map(|c| (c.from, c.to))
            .collect()
    }

    fn modules(versions: &[&str]) -> String {
        versions
            .iter()
            .enumerate()
            .map(|(i, v)| format!("org.fixture:m{i}:jar:1.0\n\\- org.example:lib:jar:{v}:compile"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn several_module_changes_do_not_invent_version_pairs() {
        let pair = |a: &str, b: &str| (a.to_string(), b.to_string());
        assert_eq!(
            changes(&modules(&["1.0", "2.0"]), &modules(&["3.0", "4.0"])),
            vec![pair("1.0", "3.0"), pair("2.0", "4.0")]
        );
        assert_eq!(
            changes(&modules(&["1.0", "2.0"]), &modules(&["3.0", "3.0"])),
            vec![pair("1.0", "3.0"), pair("2.0", "3.0")]
        );
        assert_eq!(
            changes(
                &modules(&["1.0", "2.0", "2.0"]),
                &modules(&["1.0", "2.0", "3.0"])
            ),
            vec![pair("2.0", "3.0")]
        );
    }
}
