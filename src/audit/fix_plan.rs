//! Compute a fix plan: the minimum set of version upgrades to close the maximum
//! number of CVEs from an audit report.

use serde::Serialize;
use std::collections::HashMap;

use crate::audit::osv::{VulnSeverity, Vulnerability};
use crate::audit::report::AuditReport;

#[derive(Debug, Serialize)]
pub struct FixPlan {
    pub upgrades: Vec<UpgradeAction>,
    pub total_cves_fixed: usize,
    pub total_cves_remaining: usize,
}

#[derive(Debug, Serialize)]
pub struct UpgradeAction {
    pub group: String,
    pub artifact: String,
    pub from_version: String,
    pub to_version: String,
    pub cves_fixed: Vec<String>,
    pub cves_fixed_count: usize,
    pub cves_remaining: Vec<String>,
    pub severity_summary: String,
}

/// Compute the fix plan from one or more audit reports.
pub fn compute_fix_plan(reports: &[AuditReport]) -> FixPlan {
    let mut upgrades: Vec<UpgradeAction> = Vec::new();
    let mut total_fixed = 0usize;
    let mut total_remaining = 0usize;

    for report in reports {
        for finding in &report.findings {
            if finding.vulnerabilities.is_empty() {
                continue;
            }

            let mut unfixable: Vec<String> = finding
                .vulnerabilities
                .iter()
                .filter(|vuln| vuln.fixed_versions.is_empty())
                .map(|vuln| preferred_id(vuln).to_string())
                .collect();
            unfixable.sort();
            unfixable.dedup();

            let best_version = match best_fixed_version(&finding.vulnerabilities, &finding.version)
            {
                Some(version) => version,
                None => {
                    // All CVEs are unfixable
                    total_remaining += unfixable.len();
                    upgrades.push(UpgradeAction {
                        group: finding.group.clone(),
                        artifact: finding.artifact.clone(),
                        from_version: finding.version.clone(),
                        to_version: "(no fix available)".to_string(),
                        cves_fixed: Vec::new(),
                        cves_fixed_count: 0,
                        cves_remaining: unfixable,
                        severity_summary: String::new(),
                    });
                    continue;
                }
            };

            // Determine which CVEs are fixed by this version
            let fixed_ids: Vec<String> = fixed_ids_for(&finding.vulnerabilities, &best_version)
                .into_iter()
                .map(String::from)
                .collect();

            // CVEs NOT fixed by the best version (either unfixable or need a different version)
            let mut remaining = unfixable;
            remaining.retain(|id| !fixed_ids.contains(id));
            for vuln in &finding.vulnerabilities {
                let vid = preferred_id(vuln);
                if !fixed_ids.contains(&vid.to_string())
                    && !remaining.contains(&vid.to_string())
                    && !vuln.fixed_versions.is_empty()
                {
                    remaining.push(vid.to_string());
                }
            }

            // Severity summary
            let severity_summary = build_severity_summary(&finding.vulnerabilities, &fixed_ids);

            total_fixed += fixed_ids.len();
            total_remaining += remaining.len();

            upgrades.push(UpgradeAction {
                group: finding.group.clone(),
                artifact: finding.artifact.clone(),
                from_version: finding.version.clone(),
                to_version: best_version,
                cves_fixed_count: fixed_ids.len(),
                cves_fixed: fixed_ids,
                cves_remaining: remaining,
                severity_summary,
            });
        }
    }

    // Sort by CVEs fixed (descending), then by severity
    upgrades.sort_by(|a, b| b.cves_fixed_count.cmp(&a.cves_fixed_count));

    // Remove entries with no fixes and no remaining
    upgrades.retain(|u| u.cves_fixed_count > 0 || !u.cves_remaining.is_empty());

    FixPlan {
        upgrades,
        total_cves_fixed: total_fixed,
        total_cves_remaining: total_remaining,
    }
}

/// Pick the fixed version closing the most CVEs. Versions newer than `current`
/// come first, so a backport on an older branch is never preferred over a real
/// upgrade. On ties, prefer the version OSV names explicitly for the most CVEs,
/// then the newest one. This is not a Maven range check.
pub fn best_fixed_version(vulns: &[Vulnerability], current: &str) -> Option<String> {
    let mut candidates: Vec<&str> = vulns
        .iter()
        .flat_map(|vuln| vuln.fixed_versions.iter().map(String::as_str))
        .collect();
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.iter().any(|c| supersedes(c, current)) {
        candidates.retain(|c| supersedes(c, current));
    }
    candidates
        .into_iter()
        .max_by(|a, b| {
            let rank = |version: &str| {
                let mut named: Vec<&str> = vulns
                    .iter()
                    .filter(|vuln| vuln.fixed_versions.iter().any(|fixed| fixed == version))
                    .map(preferred_id)
                    .collect();
                named.sort_unstable();
                named.dedup();
                (fixed_ids_for(vulns, version).len(), named.len())
            };
            rank(a).cmp(&rank(b)).then_with(|| {
                if supersedes(a, b) {
                    std::cmp::Ordering::Greater
                } else if supersedes(b, a) {
                    std::cmp::Ordering::Less
                } else {
                    compare_versions(a, b)
                }
            })
        })
        .map(String::from)
}

/// CVE identities closed by `target`, deduplicated across advisory records:
/// OSV can return several records with the same CVE alias.
fn fixed_ids_for<'a>(vulns: &'a [Vulnerability], target: &str) -> Vec<&'a str> {
    let mut ids: Vec<&str> = vulns
        .iter()
        .filter(|vuln| {
            // A release newer than every fix event carries all of them. A target
            // between events may sit on another release branch, so it needs an
            // exact match to count.
            !vuln.fixed_versions.is_empty()
                && (vuln.fixed_versions.iter().any(|fixed| fixed == target)
                    || vuln
                        .fixed_versions
                        .iter()
                        .all(|fixed| supersedes(target, fixed)))
        })
        .map(preferred_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Whether `candidate` is known to be released after `fixed`. Numeric parts decide
/// first. With equal numbers, only a release following a qualified build counts:
/// 2.0.0 and 4.1.0.Final follow their release candidates, while unrelated
/// qualifiers such as -jre and -android are not ordered.
fn supersedes(candidate: &str, fixed: &str) -> bool {
    let (candidate_numbers, candidate_qualifier) = split_qualifier(candidate);
    let (fixed_numbers, fixed_qualifier) = split_qualifier(fixed);
    match compare_versions(candidate_numbers, fixed_numbers) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            is_release_qualifier(candidate_qualifier) && !is_release_qualifier(fixed_qualifier)
        }
    }
}

fn split_qualifier(version: &str) -> (&str, &str) {
    let end = version
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(version.len());
    let (numbers, qualifier) = version.split_at(end);
    (
        numbers.trim_end_matches('.'),
        qualifier.trim_start_matches(['-', '.', '_']),
    )
}

fn is_release_qualifier(qualifier: &str) -> bool {
    qualifier.is_empty()
        || ["final", "release", "ga"]
            .iter()
            .any(|known| qualifier.eq_ignore_ascii_case(known))
}

/// Natural ordering for upgrade tie-breaking, not Maven range evaluation.
/// Compare digit runs without integer parsing so long version numbers cannot overflow.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut left, mut right) = (a.as_bytes(), b.as_bytes());
    while !left.is_empty() && !right.is_empty() {
        let order = if left[0].is_ascii_digit() && right[0].is_ascii_digit() {
            let left_end = left.iter().take_while(|c| c.is_ascii_digit()).count();
            let right_end = right.iter().take_while(|c| c.is_ascii_digit()).count();
            let left_number = &left[..left_end];
            let right_number = &right[..right_end];
            let left_number =
                &left_number[left_number.iter().take_while(|c| **c == b'0').count()..];
            let right_number =
                &right_number[right_number.iter().take_while(|c| **c == b'0').count()..];
            let order = left_number
                .len()
                .cmp(&right_number.len())
                .then_with(|| left_number.cmp(right_number));
            left = &left[left_end..];
            right = &right[right_end..];
            order
        } else {
            let order = left[0].cmp(&right[0]);
            left = &left[1..];
            right = &right[1..];
            order
        };
        if !order.is_eq() {
            return order;
        }
    }
    left.len().cmp(&right.len()).then_with(|| a.cmp(b))
}

fn preferred_id(vuln: &Vulnerability) -> &str {
    vuln.aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .map(|s| s.as_str())
        .unwrap_or(&vuln.id)
}

fn build_severity_summary(vulns: &[Vulnerability], fixed_ids: &[String]) -> String {
    let mut crit = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    let mut severities: HashMap<&str, VulnSeverity> = HashMap::new();
    for v in vulns {
        let vid = preferred_id(v);
        if !fixed_ids.contains(&vid.to_string()) {
            continue;
        }
        severities
            .entry(vid)
            .and_modify(|severity| *severity = (*severity).max(v.severity))
            .or_insert(v.severity);
    }
    for severity in severities.values() {
        match severity {
            VulnSeverity::Critical => crit += 1,
            VulnSeverity::High => high += 1,
            VulnSeverity::Medium => med += 1,
            VulnSeverity::Low => low += 1,
            VulnSeverity::Unknown => {}
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if crit > 0 {
        parts.push(format!("{} CRITICAL", crit));
    }
    if high > 0 {
        parts.push(format!("{} HIGH", high));
    }
    if med > 0 {
        parts.push(format!("{} MEDIUM", med));
    }
    if low > 0 {
        parts.push(format!("{} LOW", low));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::report::{AuditFinding, AuditReport, AuditSummary};

    fn make_vuln(id: &str, severity: VulnSeverity, fixed: Vec<&str>) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            aliases: if id.starts_with("CVE-") {
                vec![id.to_string()]
            } else {
                vec![]
            },
            summary: format!("Test vuln {}", id),
            severity,
            cvss_score: None,
            fixed_versions: fixed.into_iter().map(String::from).collect(),
            sources: vec![],
        }
    }

    #[test]
    fn test_basic_fix_plan() {
        let report = AuditReport {
            module: "test".to_string(),
            summary: AuditSummary {
                critical: 1,
                high: 1,
                medium: 0,
                low: 0,
                unknown: 0,
            },
            findings: vec![AuditFinding {
                group: "org.example".to_string(),
                artifact: "lib".to_string(),
                version: "1.0".to_string(),
                scope: "compile".to_string(),
                direct: true,
                paths: vec![],
                vulnerabilities: vec![
                    make_vuln("CVE-2024-001", VulnSeverity::Critical, vec!["1.1", "2.0"]),
                    make_vuln("CVE-2024-002", VulnSeverity::High, vec!["1.1"]),
                ],
                max_severity: VulnSeverity::Critical,
            }],
            artifacts_scanned: 10,
        };

        let plan = compute_fix_plan(&[report]);
        assert_eq!(plan.upgrades.len(), 1);
        assert_eq!(plan.upgrades[0].to_version, "1.1");
        assert_eq!(plan.upgrades[0].cves_fixed_count, 2);
        assert_eq!(plan.total_cves_fixed, 2);
    }

    #[test]
    fn shared_cve_alias_is_counted_once_in_fix_plan() {
        let cve = "CVE-2024-001";
        let mut ghsa = make_vuln("GHSA-test", VulnSeverity::High, vec!["1.1"]);
        ghsa.aliases.push(cve.to_string());
        let report = AuditReport {
            module: "test".to_string(),
            summary: AuditSummary::default(),
            findings: vec![AuditFinding {
                group: "org.example".to_string(),
                artifact: "lib".to_string(),
                version: "1.0".to_string(),
                scope: "compile".to_string(),
                direct: true,
                paths: vec![],
                vulnerabilities: vec![ghsa, make_vuln(cve, VulnSeverity::Critical, vec!["1.1"])],
                max_severity: VulnSeverity::High,
            }],
            artifacts_scanned: 1,
        };

        let plan = compute_fix_plan(&[report]);
        assert_eq!(plan.total_cves_fixed, 1);
        assert_eq!(plan.total_cves_remaining, 0);
        assert_eq!(plan.upgrades[0].cves_fixed, vec![cve]);
        assert_eq!(plan.upgrades[0].cves_fixed_count, 1);
        assert_eq!(plan.upgrades[0].severity_summary, "1 CRITICAL");
    }

    #[test]
    fn fixed_version_ties_prefer_numerically_newer_release() {
        for (older, newer) in [("2.9", "2.10"), ("9.0.0", "10.0.0"), ("1.0.9", "1.0.10")] {
            let report = AuditReport {
                module: "test".to_string(),
                summary: AuditSummary::default(),
                findings: vec![AuditFinding {
                    group: "org.example".to_string(),
                    artifact: "lib".to_string(),
                    version: "1.0".to_string(),
                    scope: "compile".to_string(),
                    direct: true,
                    paths: vec![],
                    vulnerabilities: vec![make_vuln(
                        "CVE-2024-001",
                        VulnSeverity::High,
                        vec![older, newer],
                    )],
                    max_severity: VulnSeverity::High,
                }],
                artifacts_scanned: 1,
            };
            let plan = compute_fix_plan(&[report]);
            assert_eq!(plan.upgrades[0].to_version, newer);
            assert_eq!(plan.total_cves_fixed, 1);
            assert_eq!(plan.total_cves_remaining, 0);
        }
    }

    #[test]
    fn test_unfixable_cves() {
        let report = AuditReport {
            module: "test".to_string(),
            summary: AuditSummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                unknown: 0,
            },
            findings: vec![AuditFinding {
                group: "org.example".to_string(),
                artifact: "lib".to_string(),
                version: "1.0".to_string(),
                scope: "compile".to_string(),
                direct: true,
                paths: vec![],
                vulnerabilities: vec![make_vuln("CVE-2024-001", VulnSeverity::High, vec![])],
                max_severity: VulnSeverity::High,
            }],
            artifacts_scanned: 5,
        };

        let plan = compute_fix_plan(&[report]);
        assert_eq!(plan.total_cves_remaining, 1);
        assert_eq!(plan.total_cves_fixed, 0);
    }

    fn plan_for(vulnerabilities: Vec<Vulnerability>) -> FixPlan {
        compute_fix_plan(&[AuditReport {
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
                max_severity: VulnSeverity::High,
            }],
            artifacts_scanned: 1,
        }])
    }

    #[test]
    fn newer_target_counts_cves_fixed_by_earlier_releases() {
        let plan = plan_for(vec![
            make_vuln("CVE-2024-001", VulnSeverity::High, vec!["1.1"]),
            make_vuln("CVE-2024-002", VulnSeverity::Critical, vec!["1.2"]),
        ]);
        assert_eq!(plan.upgrades[0].to_version, "1.2");
        assert_eq!(plan.upgrades[0].cves_fixed_count, 2);
        assert_eq!(plan.upgrades[0].severity_summary, "1 CRITICAL, 1 HIGH");
        assert!(plan.upgrades[0].cves_remaining.is_empty());
        assert_eq!(plan.total_cves_remaining, 0);
    }

    #[test]
    fn target_that_supersedes_most_fixes_wins_over_repeated_older_fix() {
        let plan = plan_for(vec![
            make_vuln("CVE-2024-001", VulnSeverity::High, vec!["1.1"]),
            make_vuln("CVE-2024-002", VulnSeverity::High, vec!["1.1"]),
            make_vuln("CVE-2024-003", VulnSeverity::High, vec!["1.10"]),
        ]);
        assert_eq!(plan.upgrades[0].to_version, "1.10");
        assert_eq!(plan.total_cves_fixed, 3);
        assert_eq!(plan.total_cves_remaining, 0);
    }

    #[test]
    fn other_branch_fixes_and_prereleases_are_not_assumed_to_fix() {
        // 1.9.5 cannot be assumed to contain the later 2.1.0 branch fix.
        let plan = plan_for(vec![
            make_vuln("CVE-2024-001", VulnSeverity::High, vec!["1.9.5", "2.1.0"]),
            make_vuln("CVE-2024-002", VulnSeverity::High, vec!["1.9.6"]),
        ]);
        assert_eq!(plan.upgrades[0].to_version, "2.1.0");
        assert_eq!(plan.total_cves_fixed, 2);
        // A final release carries its release candidate's fix, not the reverse.
        let plan = plan_for(vec![
            make_vuln("CVE-2024-001", VulnSeverity::High, vec!["2.0.0-rc1"]),
            make_vuln("CVE-2024-002", VulnSeverity::High, vec!["2.0.0"]),
        ]);
        assert_eq!(plan.upgrades[0].to_version, "2.0.0");
        assert_eq!(plan.total_cves_fixed, 2);
        assert!(!supersedes("2.0.0-rc1", "2.0.0"));
        assert!(supersedes("2.0.0", "2.0.0-rc1"));
        assert!(supersedes("1.0.10", "1.0"));
    }

    #[test]
    fn best_fixed_version_matches_fix_plan_target() {
        let vulns = vec![
            make_vuln("CVE-2024-001", VulnSeverity::High, vec!["1.1"]),
            make_vuln("CVE-2024-002", VulnSeverity::High, vec!["1.2"]),
        ];
        assert_eq!(best_fixed_version(&vulns, "1.0").as_deref(), Some("1.2"));
        assert_eq!(best_fixed_version(&[], "1.0"), None);
    }

    #[test]
    fn target_is_never_older_than_current_when_a_newer_fix_exists() {
        let vulns = vec![
            make_vuln("CVE-2024-001", VulnSeverity::High, vec!["5.3.33", "6.1.5"]),
            make_vuln("CVE-2024-002", VulnSeverity::High, vec!["5.3.33", "6.1.6"]),
        ];
        assert_eq!(
            best_fixed_version(&vulns, "6.1.0").as_deref(),
            Some("6.1.6")
        );
        // On the older branch the shared backport stays the smallest upgrade.
        assert_eq!(
            best_fixed_version(&vulns, "5.3.0").as_deref(),
            Some("5.3.33")
        );
        // Nothing newer is known: keep reporting OSV's fix rather than nothing.
        let vulns = vec![make_vuln("CVE-2024-001", VulnSeverity::High, vec!["1.1"])];
        assert_eq!(best_fixed_version(&vulns, "2.0").as_deref(), Some("1.1"));
    }

    #[test]
    fn prerelease_ordering_does_not_depend_on_qualifier_spelling() {
        assert!(!supersedes("4.1.0.RC1", "4.1.0.Final"));
        assert!(supersedes("4.1.0.Final", "4.1.0.RC1"));
        assert!(!supersedes("33.0.0-android", "33.0.0-jre"));
        assert!(!supersedes("33.0.0-jre", "33.0.0-android"));
        assert!(supersedes("4.1.1.RC1", "4.1.0.Final"));
        let vulns = vec![make_vuln(
            "CVE-2024-001",
            VulnSeverity::High,
            vec!["2.0.0", "2.0.0-rc1"],
        )];
        assert_eq!(best_fixed_version(&vulns, "1.0").as_deref(), Some("2.0.0"));
    }
}
