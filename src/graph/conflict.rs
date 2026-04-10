use std::collections::HashSet;

use crate::collector::effective_pom::ManagedDependency;
use crate::graph::builder::{DepGraph, VersionRequest};
use crate::model::ArtifactKey;

/// A detected version conflict for a single artifact.
#[derive(Debug, Clone)]
pub struct ConflictReport {
    pub key: ArtifactKey,
    pub selected_version: String,
    pub overridden_versions: Vec<String>,
    pub severity: Severity,
    pub version_jump: VersionJump,
    pub resolution: String,
    pub scope: String,
    /// True if dependencyManagement / a BOM explicitly set this version (intentional).
    pub managed: bool,
    /// True if the selected version is OLDER than at least one overridden version.
    /// Downgrades are extra risky because they remove APIs that callers may use.
    pub is_downgrade: bool,
    pub risk_factors: Vec<String>,
    /// Human-readable risk explanation (one sentence, optional).
    pub risk_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }

    fn down(self) -> Self {
        match self {
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low => Severity::Low,
        }
    }

    fn up(self) -> Self {
        match self {
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High => Severity::High,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionJump {
    Major,
    Minor,
    Patch,
    None,
}

impl VersionJump {
    pub fn as_str(&self) -> &'static str {
        match self {
            VersionJump::Major => "major",
            VersionJump::Minor => "minor",
            VersionJump::Patch => "patch",
            VersionJump::None => "none",
        }
    }
}

/// Scan a graph and produce a ranked list of conflicts.
pub fn detect_conflicts(
    graph: &DepGraph,
    managed_deps: &[ManagedDependency],
) -> Vec<ConflictReport> {
    let mut reports: Vec<ConflictReport> = Vec::new();

    for key in graph.conflicted_artifacts() {
        let requests = match graph.get_requests(key) {
            Some(r) => r,
            None => continue,
        };

        let distinct_versions: HashSet<&str> =
            requests.iter().map(|r| r.version.as_str()).collect();
        if distinct_versions.len() < 2 {
            continue;
        }

        let selected = match requests.iter().find(|r| r.selected) {
            Some(r) => r,
            None => continue,
        };
        let selected_version = selected.version.clone();

        // Sort overridden versions deterministically (newest-first by semver)
        let mut overridden_versions: Vec<String> = distinct_versions
            .iter()
            .filter(|v| **v != selected_version)
            .map(|v| v.to_string())
            .collect();
        overridden_versions.sort_by(|a, b| parse_semver(b).cmp(&parse_semver(a)));

        // Find the largest jump between selected and any overridden version,
        // and detect downgrades (selected older than any override).
        let mut max_jump = VersionJump::None;
        let mut max_minor_gap: u32 = 0;
        let mut is_downgrade = false;
        let sel_parsed = parse_semver(&selected_version);
        for ov in &overridden_versions {
            let ov_parsed = parse_semver(ov);
            if ov_parsed > sel_parsed {
                is_downgrade = true;
            }
            let jump = if sel_parsed.0 != ov_parsed.0 {
                VersionJump::Major
            } else if sel_parsed.1 != ov_parsed.1 {
                let gap = (sel_parsed.1 as i32 - ov_parsed.1 as i32).unsigned_abs();
                max_minor_gap = max_minor_gap.max(gap);
                VersionJump::Minor
            } else if sel_parsed.2 != ov_parsed.2 {
                VersionJump::Patch
            } else {
                VersionJump::None
            };
            max_jump = max_jump_of(max_jump, jump);
        }

        let mut severity = match max_jump {
            VersionJump::Major => Severity::High,
            VersionJump::Minor if max_minor_gap >= 5 => Severity::Medium,
            VersionJump::Minor => Severity::Low,
            VersionJump::Patch => Severity::Low,
            VersionJump::None => Severity::Low,
        };

        // Downgrade bumps severity up one notch (missing-API risk).
        if is_downgrade {
            severity = severity.up();
        }

        let scope = graph
            .find_node_versioned(key, &selected_version)
            .map(|idx| graph.graph[idx].scope.to_string())
            .unwrap_or_else(|| "compile".to_string());

        // test scope: knock severity down a notch
        if scope == "test" {
            severity = severity.down();
        }

        // Managed by dependencyManagement / BOM: knock down (intentional override)
        let managed = managed_deps.iter().any(|md| &md.key == key)
            || requests.iter().any(|r| r.managed_from.is_some());
        if managed {
            severity = severity.down();
        }

        let resolution = determine_resolution_label(requests, &selected_version);

        let mut risk_factors: Vec<String> = Vec::new();
        if matches!(max_jump, VersionJump::Major) {
            risk_factors.push("major_version_mismatch".to_string());
        }
        if is_downgrade {
            risk_factors.push("downgrade".to_string());
        }
        if managed {
            risk_factors.push("managed_override".to_string());
        }
        if scope == "test" {
            risk_factors.push("test_scope_only".to_string());
        }

        // Pick the "worst" overridden version to feature in the risk note:
        // for downgrades, the highest version (most likely to use new APIs missing in selected);
        // otherwise, the version with the largest major-version gap.
        let worst_override = requests
            .iter()
            .filter(|r| !r.selected && r.version != selected_version)
            .filter(|r| r.path.len() >= 2)
            .max_by(|a, b| {
                let pa = parse_semver(&a.version);
                let pb = parse_semver(&b.version);
                if is_downgrade {
                    pa.cmp(&pb)
                } else {
                    let ga = (pa.0 as i32 - sel_parsed.0 as i32).abs();
                    let gb = (pb.0 as i32 - sel_parsed.0 as i32).abs();
                    ga.cmp(&gb)
                }
            });

        let risk_note = if is_downgrade && matches!(max_jump, VersionJump::Major) {
            worst_override.map(|r| {
                let consumer = &r.path[r.path.len() - 2];
                format!(
                    "DOWNGRADED: {} expects {} but resolved to {} — APIs may be missing at runtime",
                    consumer, r.version, selected_version
                )
            })
        } else if is_downgrade {
            worst_override.map(|r| {
                let consumer = &r.path[r.path.len() - 2];
                format!(
                    "Downgrade: {} expects {} but resolved to older {}",
                    consumer, r.version, selected_version
                )
            })
        } else if matches!(max_jump, VersionJump::Major) {
            worst_override.map(|r| {
                let r_major = parse_semver(&r.version).0;
                format!(
                    "{} compiled against {}.x ({}) — resolved to {}.x, runtime errors possible",
                    r.path[r.path.len() - 2],
                    r_major,
                    r.version,
                    sel_parsed.0
                )
            })
        } else {
            None
        };

        reports.push(ConflictReport {
            key: key.clone(),
            selected_version,
            overridden_versions,
            severity,
            version_jump: max_jump,
            resolution,
            scope,
            managed,
            is_downgrade,
            risk_factors,
            risk_note,
        });
    }

    // Sort: severity desc, then artifact name asc
    reports.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.key.to_string().cmp(&b.key.to_string()))
    });

    reports
}

fn max_jump_of(a: VersionJump, b: VersionJump) -> VersionJump {
    let rank = |j: VersionJump| match j {
        VersionJump::Major => 3,
        VersionJump::Minor => 2,
        VersionJump::Patch => 1,
        VersionJump::None => 0,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

fn determine_resolution_label(requests: &[VersionRequest], selected_version: &str) -> String {
    if requests.iter().any(|r| r.managed_from.is_some()) {
        return "dependency_management".to_string();
    }
    let selected_depth = requests
        .iter()
        .find(|r| r.selected)
        .map(|r| r.path.len())
        .unwrap_or(0);
    let other_depths: Vec<usize> = requests
        .iter()
        .filter(|r| !r.selected && r.version != selected_version)
        .map(|r| r.path.len())
        .collect();
    let max_other_depth = other_depths.iter().copied().max().unwrap_or(0);
    let min_other_depth = other_depths.iter().copied().min().unwrap_or(0);

    if max_other_depth > selected_depth {
        "nearest_wins".to_string()
    } else if min_other_depth == selected_depth && selected_depth > 0 {
        "first_declaration_wins".to_string()
    } else if selected_depth > 0 && min_other_depth > 0 && selected_depth > min_other_depth {
        // Selected is deeper than at least one override — Maven kept it because it appeared
        // earlier in the POM declaration order despite being further from root.
        "first_declaration_wins".to_string()
    } else {
        "first_declaration_wins".to_string()
    }
}

fn parse_semver(version: &str) -> (u32, u32, u32) {
    let parts: Vec<&str> = version.split('.').collect();
    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts
        .get(2)
        .and_then(|s| s.split('-').next().and_then(|n| n.parse().ok()))
        .unwrap_or(0);
    (major, minor, patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::verbose_tree::parse_verbose_tree;
    use crate::graph::builder::build_graph;

    #[test]
    fn test_detect_major_conflict_high() {
        let input = r#"com.test:app:jar:1.0.0
+- com.google.inject:guice:jar:4.0:compile
|  +- (com.google.guava:guava:jar:16.0.1:compile - omitted for conflict with 32.1.3-jre)
+- com.google.guava:guava:jar:32.1.3-jre:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.key.artifact_id, "guava");
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.version_jump, VersionJump::Major);
        assert_eq!(r.resolution, "nearest_wins");
        assert!(r.risk_factors.contains(&"major_version_mismatch".to_string()));
        assert!(r.risk_note.is_some());
    }

    #[test]
    fn test_detect_minor_conflict_low() {
        let input = r#"com.test:app:jar:1.0.0
+- com.fasterxml.jackson.core:jackson-databind:jar:2.15.3:compile
+- some.other:lib:jar:1.0:compile
|  +- (com.fasterxml.jackson.core:jackson-databind:jar:2.14.0:compile - omitted for conflict with 2.15.3)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].severity, Severity::Low);
        assert_eq!(reports[0].version_jump, VersionJump::Minor);
    }

    #[test]
    fn test_managed_lowers_severity() {
        let input = r#"com.test:app:jar:1.0.0
+- com.google.inject:guice:jar:4.0:compile
|  +- (com.google.guava:guava:jar:16.0.1:compile - omitted for conflict with 32.1.3-jre)
+- com.google.guava:guava:jar:32.1.3-jre:compile (managed from 30.0-jre)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        // Major jump → HIGH, but managed → MEDIUM
        assert_eq!(reports[0].severity, Severity::Medium);
        assert!(reports[0].managed);
    }

    #[test]
    fn test_severity_sort_order() {
        let input = r#"com.test:app:jar:1.0.0
+- a:major-conflict:jar:2.0:compile
|  +- (z:lib:jar:1.0:compile - omitted for conflict with 2.0)
+- z:lib:jar:2.0:compile
+- b:minor-conflict:jar:1.0:compile
|  +- (y:other:jar:1.0:compile - omitted for conflict with 1.1)
+- y:other:jar:1.1:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        assert_eq!(reports.len(), 2);
        // HIGH (major) should come first
        assert_eq!(reports[0].severity, Severity::High);
        assert_eq!(reports[1].severity, Severity::Low);
    }

    #[test]
    fn test_downgrade_bumps_severity_and_flags() {
        // selected = 20.0 (older), overridden = 27.0-jre (newer transitively)
        let input = r#"com.test:app:jar:1.0.0
+- com.google.guava:guava:jar:20.0:compile
+- org.apache.hadoop:hadoop-common:jar:3.3.6:compile
|  +- (com.google.guava:guava:jar:27.0-jre:compile - omitted for conflict with 20.0)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert!(r.is_downgrade, "should detect downgrade");
        // Major jump → HIGH; downgrade → already HIGH (capped)
        assert_eq!(r.severity, Severity::High);
        assert!(r.risk_factors.contains(&"downgrade".to_string()));
        let note = r.risk_note.as_ref().expect("risk note expected");
        assert!(note.contains("DOWNGRADED"), "expected DOWNGRADED in: {}", note);
        assert!(note.contains("hadoop-common"));
    }

    #[test]
    fn test_overridden_versions_sorted_newest_first() {
        let input = r#"com.test:app:jar:1.0.0
+- a:foo:jar:1.0:compile
|  +- (org.lib:x:jar:2.5.0:compile - omitted for conflict with 3.0.0)
+- b:bar:jar:1.0:compile
|  +- (org.lib:x:jar:1.7.0:compile - omitted for conflict with 3.0.0)
+- org.lib:x:jar:3.0.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        assert_eq!(reports.len(), 1);
        // Newest first
        assert_eq!(reports[0].overridden_versions, vec!["2.5.0", "1.7.0"]);
    }

    #[test]
    fn test_no_conflict_returns_empty() {
        let input = r#"com.test:app:jar:1.0.0
+- com.google.guava:guava:jar:32.1.3-jre:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let reports = detect_conflicts(&graph, &[]);

        assert!(reports.is_empty());
    }
}
