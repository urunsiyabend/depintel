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
    // A combined multi-module graph can select a different version in each module.
    let mut seen: HashSet<(ArtifactKey, String)> = HashSet::new();
    let mut queries: Vec<OsvQuery> = Vec::new();
    let mut query_meta: Vec<(ArtifactKey, String, String, bool, Vec<Vec<String>>)> = Vec::new();

    for (key, requests) in &graph.version_requests {
        for selected in requests.iter().filter(|r| r.selected) {
            let pair = (key.clone(), selected.version.clone());
            if !seen.insert(pair) {
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
            .then_with(|| a.version.cmp(&b.version))
    });

    Ok(AuditReport {
        module: graph.root_label(),
        summary,
        findings,
        artifacts_scanned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::cache::OsvCache;
    use crate::collector::verbose_tree::parse_verbose_tree;
    use crate::graph::builder::{build_combined_graph, build_graph};

    fn vuln(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            aliases: vec![],
            summary: String::new(),
            severity: VulnSeverity::High,
            cvss_score: None,
            fixed_versions: vec![],
            sources: vec![],
        }
    }

    fn client_with(entries: &[(&str, &str)]) -> (tempfile::TempDir, OsvClient) {
        let dir = tempfile::tempdir().unwrap();
        let cache = OsvCache::in_directory(dir.path().to_path_buf());
        for (key, id) in entries {
            let vulns = if id.is_empty() {
                vec![]
            } else {
                vec![vuln(id)]
            };
            cache.put(key, &vulns).unwrap();
        }
        (dir, OsvClient::new(cache))
    }

    #[test]
    fn combined_graph_audits_every_selected_version() {
        let trees = parse_verbose_tree(
            "org.fixture:module-a:jar:1.0\n\\- org.example:lib:jar:1.0:compile\n\
             org.fixture:module-b:jar:1.0\n\\- org.example:lib:jar:2.0:compile",
        )
        .unwrap();
        let graph = build_combined_graph(&trees);
        let (_dir, client) = client_with(&[
            ("org.example:lib:1.0", "GHSA-old"),
            ("org.example:lib:2.0", "GHSA-new"),
        ]);
        let report = build_report(&graph, &client, false).unwrap();
        let mut versions: Vec<_> = report.findings.iter().map(|f| f.version.as_str()).collect();
        versions.sort_unstable();
        assert_eq!(versions, vec!["1.0", "2.0"]);
        assert_eq!(report.artifacts_scanned, 2);
    }

    #[test]
    fn compile_dependency_is_audited_when_first_seen_as_test_duplicate() {
        let trees = parse_verbose_tree(
            "org.fixture:app:jar:1.0\n\
             +- org.fixture:helper:jar:1.0:test\n\
             |  \\- (org.example:lib:jar:1.0:test - omitted for duplicate)\n\
             \\- org.example:lib:jar:1.0:compile",
        )
        .unwrap();
        let graph = build_graph(&trees[0]);
        let (_dir, client) = client_with(&[("org.example:lib:1.0", "GHSA-live")]);
        let report = build_report(&graph, &client, false).unwrap();
        assert_eq!(report.findings.len(), 1, "compile dependency was skipped");
        assert_eq!(report.findings[0].scope, "compile");
    }
}
