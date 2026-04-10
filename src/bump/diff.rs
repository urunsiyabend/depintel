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

/// Build a map from ArtifactKey → selected version by walking version_requests.
fn selected_versions(g: &DepGraph) -> HashMap<ArtifactKey, String> {
    let mut out = HashMap::new();
    for (key, requests) in &g.version_requests {
        if let Some(sel) = requests.iter().find(|r| r.selected) {
            out.insert(key.clone(), sel.version.clone());
        }
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
        if bv != ov {
            version_changes.push(VersionChange {
                group: k.group_id.clone(),
                artifact: k.artifact_id.clone(),
                from: bv.clone(),
                to: ov.clone(),
            });
        }
    }
    for k in o_keys.difference(&b_keys) {
        added.push(ArtifactRef {
            group: k.group_id.clone(),
            artifact: k.artifact_id.clone(),
            version: o[*k].clone(),
        });
    }
    for k in b_keys.difference(&o_keys) {
        removed.push(ArtifactRef {
            group: k.group_id.clone(),
            artifact: k.artifact_id.clone(),
            version: b[*k].clone(),
        });
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
    // Build (artifact_coord, cve_id) → entry maps for both sides.
    let mut b_map: HashMap<(String, String), CveEntry> = HashMap::new();
    let mut o_map: HashMap<(String, String), CveEntry> = HashMap::new();

    let ingest = |map: &mut HashMap<(String, String), CveEntry>, r: &AuditReport| {
        for f in &r.findings {
            let coord = format!("{}:{}", f.group, f.artifact);
            for v in &f.vulnerabilities {
                let id = preferred_id(v);
                let key = (coord.clone(), id.clone());
                map.entry(key).or_insert_with(|| CveEntry {
                    id: id.clone(),
                    severity: v.severity.as_str().to_string(),
                    summary: v.summary.lines().next().unwrap_or("").trim().to_string(),
                    artifact: coord.clone(),
                });
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

    let sev_rank = |s: &str| match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    };
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
