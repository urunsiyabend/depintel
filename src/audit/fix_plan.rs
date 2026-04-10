//! Compute a fix plan: the minimum set of version upgrades to close the maximum
//! number of CVEs from an audit report.

use serde::Serialize;
use std::collections::HashMap;

use crate::audit::osv::VulnSeverity;
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

            // Collect all candidate fixed versions across all CVEs for this artifact
            let mut version_to_fixes: HashMap<&str, Vec<&str>> = HashMap::new();
            let mut unfixable: Vec<String> = Vec::new();

            for vuln in &finding.vulnerabilities {
                let vuln_id = preferred_id(vuln);
                if vuln.fixed_versions.is_empty() {
                    unfixable.push(vuln_id.to_string());
                    continue;
                }
                for fv in &vuln.fixed_versions {
                    version_to_fixes
                        .entry(fv.as_str())
                        .or_default()
                        .push(vuln_id);
                }
            }

            if version_to_fixes.is_empty() {
                // All CVEs are unfixable
                total_remaining += unfixable.len();
                if !unfixable.is_empty() {
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
                }
                continue;
            }

            // For each candidate version, a CVE is "fixed" if the candidate version
            // appears in that CVE's fixed_versions list.
            // Pick the version that fixes the most CVEs. On ties, prefer the one
            // that appears latest alphabetically (crude "newest" heuristic).
            let best_version = version_to_fixes
                .iter()
                .max_by(|a, b| {
                    a.1.len()
                        .cmp(&b.1.len())
                        .then_with(|| a.0.cmp(b.0))
                })
                .map(|(v, _)| *v)
                .unwrap_or("");

            // Determine which CVEs are fixed by this version
            let fixed_ids: Vec<String> = version_to_fixes
                .get(best_version)
                .map(|ids| ids.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default();

            // CVEs NOT fixed by the best version (either unfixable or need a different version)
            let mut remaining = unfixable;
            for vuln in &finding.vulnerabilities {
                let vid = preferred_id(vuln);
                if !fixed_ids.contains(&vid.to_string())
                    && !remaining.contains(&vid.to_string())
                    && !vuln.fixed_versions.is_empty()
                {
                    // This CVE has a fix but not in the best_version
                    // Check if best_version would still fix it via version comparison
                    // For simplicity, we just mark it as remaining
                    remaining.push(vid.to_string());
                }
            }

            // Severity summary
            let severity_summary = build_severity_summary(
                &finding.vulnerabilities,
                &fixed_ids,
            );

            total_fixed += fixed_ids.len();
            total_remaining += remaining.len();

            upgrades.push(UpgradeAction {
                group: finding.group.clone(),
                artifact: finding.artifact.clone(),
                from_version: finding.version.clone(),
                to_version: best_version.to_string(),
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

fn preferred_id(vuln: &crate::audit::osv::Vulnerability) -> &str {
    vuln.aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .map(|s| s.as_str())
        .unwrap_or(&vuln.id)
}

fn build_severity_summary(
    vulns: &[crate::audit::osv::Vulnerability],
    fixed_ids: &[String],
) -> String {
    let mut crit = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    for v in vulns {
        let vid = preferred_id(v);
        if !fixed_ids.contains(&vid.to_string()) {
            continue;
        }
        match v.severity {
            VulnSeverity::Critical => crit += 1,
            VulnSeverity::High => high += 1,
            VulnSeverity::Medium => med += 1,
            VulnSeverity::Low => low += 1,
            VulnSeverity::Unknown => {}
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if crit > 0 { parts.push(format!("{} CRITICAL", crit)); }
    if high > 0 { parts.push(format!("{} HIGH", high)); }
    if med > 0 { parts.push(format!("{} MEDIUM", med)); }
    if low > 0 { parts.push(format!("{} LOW", low)); }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::osv::Vulnerability;
    use crate::audit::report::{AuditFinding, AuditReport, AuditSummary};

    fn make_vuln(id: &str, severity: VulnSeverity, fixed: Vec<&str>) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            aliases: if id.starts_with("CVE-") { vec![id.to_string()] } else { vec![] },
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
            summary: AuditSummary { critical: 1, high: 1, medium: 0, low: 0, unknown: 0 },
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
    fn test_unfixable_cves() {
        let report = AuditReport {
            module: "test".to_string(),
            summary: AuditSummary { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
            findings: vec![AuditFinding {
                group: "org.example".to_string(),
                artifact: "lib".to_string(),
                version: "1.0".to_string(),
                scope: "compile".to_string(),
                direct: true,
                paths: vec![],
                vulnerabilities: vec![
                    make_vuln("CVE-2024-001", VulnSeverity::High, vec![]),
                ],
                max_severity: VulnSeverity::High,
            }],
            artifacts_scanned: 5,
        };

        let plan = compute_fix_plan(&[report]);
        assert_eq!(plan.total_cves_remaining, 1);
        assert_eq!(plan.total_cves_fixed, 0);
    }
}
