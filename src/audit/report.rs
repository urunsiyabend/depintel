use anyhow::Result;
use serde::Serialize;
use std::collections::HashSet;

use crate::audit::osv::{OsvClient, OsvQuery, VulnSeverity, Vulnerability};
use crate::graph::builder::DepGraph;
use crate::model::ArtifactKey;

/// One artifact instance with attached vulnerabilities and the paths it reaches the root from.
#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub group: String,
    pub artifact: String,
    pub version: String,
    pub scope: String,
    pub direct: bool,
    pub paths: Vec<Vec<String>>,
    pub vulnerabilities: Vec<Vulnerability>,
    /// The most severe vuln on this artifact, used for ranking.
    pub max_severity: VulnSeverity,
}

/// Per-module audit result.
#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub module: String,
    pub summary: AuditSummary,
    pub findings: Vec<AuditFinding>,
    pub artifacts_scanned: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct AuditSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

impl AuditSummary {
    pub fn bump(&mut self, sev: VulnSeverity) {
        match sev {
            VulnSeverity::Critical => self.critical += 1,
            VulnSeverity::High => self.high += 1,
            VulnSeverity::Medium => self.medium += 1,
            VulnSeverity::Low => self.low += 1,
            VulnSeverity::Unknown => self.unknown += 1,
        }
    }
}

/// Build an audit report by scanning every distinct (artifact, version) in the graph
/// against OSV.dev and joining results back to graph context (paths, scope).
pub fn build_report(
    graph: &DepGraph,
    client: &OsvClient,
    include_test: bool,
) -> Result<AuditReport> {
    // Collect distinct selected (key, version) pairs from the graph.
    // We only check what was actually selected — overridden versions don't end up on classpath.
    let mut seen: HashSet<(ArtifactKey, String)> = HashSet::new();
    let mut queries: Vec<OsvQuery> = Vec::new();
    let mut query_meta: Vec<(ArtifactKey, String, String, bool, Vec<Vec<String>>)> = Vec::new();

    for (key, requests) in &graph.version_requests {
        let selected = match requests.iter().find(|r| r.selected) {
            Some(r) => r,
            None => continue,
        };
        let pair = (key.clone(), selected.version.clone());
        if !seen.insert(pair.clone()) {
            continue;
        }

        let scope = graph
            .find_node_versioned(key, &selected.version)
            .map(|idx| graph.graph[idx].scope.to_string())
            .unwrap_or_else(|| "compile".to_string());

        if !include_test && scope == "test" {
            continue;
        }

        // Direct = path length 2 (root + this artifact).
        let direct = selected.path.len() <= 2;

        // Collect *all* paths to this artifact (real + virtual reconstructed).
        let mut paths: Vec<Vec<String>> = requests
            .iter()
            .filter(|r| r.version == selected.version)
            .map(|r| r.path.clone())
            .collect();
        paths.sort();
        paths.dedup();

        queries.push(OsvQuery {
            group: key.group_id.clone(),
            artifact: key.artifact_id.clone(),
            version: selected.version.clone(),
        });
        query_meta.push((key.clone(), selected.version.clone(), scope, direct, paths));
    }

    let artifacts_scanned = queries.len();
    let results = client.query_batch(&queries)?;

    let mut findings: Vec<AuditFinding> = Vec::new();
    let mut summary = AuditSummary::default();

    for ((key, version, scope, direct, paths), vulns) in query_meta.into_iter().zip(results) {
        if vulns.is_empty() {
            continue;
        }
        let max_severity = vulns
            .iter()
            .map(|v| v.severity)
            .max()
            .unwrap_or(VulnSeverity::Unknown);
        // Count *each* vulnerability, not just the artifact, so the summary reflects
        // how much real triage work is on the table.
        for v in &vulns {
            summary.bump(v.severity);
        }

        findings.push(AuditFinding {
            group: key.group_id.clone(),
            artifact: key.artifact_id.clone(),
            version,
            scope,
            direct,
            paths,
            vulnerabilities: vulns,
            max_severity,
        });
    }

    // Severity desc, then artifact name asc.
    findings.sort_by(|a, b| {
        b.max_severity
            .cmp(&a.max_severity)
            .then_with(|| format!("{}:{}", a.group, a.artifact).cmp(&format!("{}:{}", b.group, b.artifact)))
    });

    Ok(AuditReport {
        module: graph.root_label(),
        summary,
        findings,
        artifacts_scanned,
    })
}
