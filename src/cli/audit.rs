use anyhow::Result;
use std::path::Path;

use crate::audit::applicability::{self, ApplicabilityLevel, ApplicabilityResult};
use crate::audit::cache::OsvCache;
use crate::audit::fix_plan;
use crate::audit::osv::{OsvClient, VulnSeverity};
use crate::audit::report::{build_report, AuditFinding, AuditReport, AuditSummary};
use crate::cli::list::collect_or_cache;
use crate::collector::{maven::CollectGoals, verbose_tree};
use crate::graph::builder;
use crate::output::color;

/// Result indicating whether the audit found blocking findings.
pub enum AuditOutcome {
    Clean,
    Blocking,
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    pom_dir: &Path,
    output_format: &str,
    module: Option<&str>,
    severity_filter: Option<&str>,
    include_test: bool,
    fresh_cves: bool,
    scan_usage: bool,
    fix_plan_flag: bool,
    fresh: bool,
    offline: bool,
) -> Result<AuditOutcome> {
    if offline {
        anyhow::bail!(
            "audit requires network access to query OSV.dev — --offline is not supported yet."
        );
    }

    let goals = CollectGoals {
        effective_pom: false,
        verbose_tree: true,
        dep_list: false,
    };
    let (_, verbose_tree_raw, _) = collect_or_cache(pom_dir, goals, fresh, false)?;
    let trees = verbose_tree::parse_verbose_tree(&verbose_tree_raw)?;

    if trees.is_empty() {
        anyhow::bail!("No dependency tree found in Maven output.");
    }

    let trees_filtered: Vec<_> = if let Some(mod_name) = module {
        trees
            .iter()
            .filter(|t| {
                t.root.artifact.key.artifact_id == mod_name
                    || format!(
                        "{}:{}",
                        t.root.artifact.key.group_id, t.root.artifact.key.artifact_id
                    ) == mod_name
            })
            .collect()
    } else {
        trees.iter().collect()
    };

    if trees_filtered.is_empty() {
        if let Some(mod_name) = module {
            anyhow::bail!("Module '{}' not found.", mod_name);
        }
    }

    let cache = OsvCache::default_location()?;
    if fresh_cves {
        cache.clear()?;
    }
    let client = OsvClient::new(cache);

    let mut reports: Vec<AuditReport> = Vec::new();
    for tree in &trees_filtered {
        let graph = builder::build_graph(tree);
        let mut report = build_report(&graph, &client, include_test)?;

        if let Some(sev_str) = severity_filter {
            let want = parse_severity(sev_str)?;
            apply_severity_filter(&mut report, want);
        }

        reports.push(report);
    }

    // Applicability scan
    let applicability_results: Option<Vec<Vec<ApplicabilityResult>>> = if scan_usage {
        Some(
            reports
                .iter()
                .map(|report| {
                    report
                        .findings
                        .iter()
                        .map(|f| applicability::scan_usage(pom_dir, &f.group, &f.artifact))
                        .collect()
                })
                .collect(),
        )
    } else {
        None
    };

    // Fix plan
    let plan = if fix_plan_flag {
        Some(fix_plan::compute_fix_plan(&reports))
    } else {
        None
    };

    match output_format {
        "json" => print_json(&reports, &applicability_results, &plan)?,
        _ => {
            print_text(&reports, &applicability_results);
            if let Some(ref p) = plan {
                print_fix_plan_text(p);
            }
        }
    }

    // CI gate: return Blocking if any HIGH or CRITICAL findings remain after filtering.
    let any_blocking = reports.iter().any(|r| r.summary.high > 0 || r.summary.critical > 0);
    if any_blocking {
        return Ok(AuditOutcome::Blocking);
    }

    Ok(AuditOutcome::Clean)
}

fn apply_severity_filter(report: &mut AuditReport, want: VulnSeverity) {
    report.findings.retain(|f| f.max_severity >= want);
    // Recompute summary so it reflects the filter, counting each vulnerability
    // like the unfiltered report does.
    let mut summary = AuditSummary::default();
    for vuln in report.findings.iter().flat_map(|f| &f.vulnerabilities) {
        summary.bump(vuln.severity);
    }
    report.summary = summary;
}

fn parse_severity(s: &str) -> Result<VulnSeverity> {
    match s.to_lowercase().as_str() {
        "low" => Ok(VulnSeverity::Low),
        "medium" | "med" | "moderate" => Ok(VulnSeverity::Medium),
        "high" => Ok(VulnSeverity::High),
        "critical" | "crit" => Ok(VulnSeverity::Critical),
        _ => anyhow::bail!("Unknown severity '{}'. Use: low, medium, high, critical", s),
    }
}

fn severity_color(sev: VulnSeverity, text: &str) -> String {
    match sev {
        VulnSeverity::Critical => color::red(text),
        VulnSeverity::High => color::red(text),
        VulnSeverity::Medium => color::yellow(text),
        VulnSeverity::Low => color::dim(text),
        VulnSeverity::Unknown => color::dim(text),
    }
}

fn print_text(
    reports: &[AuditReport],
    applicability: &Option<Vec<Vec<ApplicabilityResult>>>,
) {
    let total: usize = reports.iter().map(|r| r.findings.len()).sum();
    if total == 0 {
        let scanned: usize = reports.iter().map(|r| r.artifacts_scanned).sum();
        println!(
            "{} No vulnerabilities found ({} artifacts scanned across {} module(s)).",
            color::green("✔"),
            scanned,
            reports.len()
        );
        return;
    }

    for (ri, report) in reports.iter().enumerate() {
        if report.findings.is_empty() {
            continue;
        }
        println!(
            "{} {} vulnerability finding(s) in {} ({} artifacts scanned)",
            color::bold("SECURITY AUDIT:"),
            color::cyan(&report.findings.len().to_string()),
            color::cyan(&report.module),
            report.artifacts_scanned,
        );
        println!();

        for (fi, finding) in report.findings.iter().enumerate() {
            let app = applicability
                .as_ref()
                .and_then(|a| a.get(ri))
                .and_then(|r| r.get(fi));
            print_finding(finding, app);
        }

        println!(
            "Summary: {} CRITICAL, {} HIGH, {} MEDIUM, {} LOW{}",
            color::red(&report.summary.critical.to_string()),
            color::red(&report.summary.high.to_string()),
            color::yellow(&report.summary.medium.to_string()),
            color::dim(&report.summary.low.to_string()),
            if report.summary.unknown > 0 {
                format!(", {} UNKNOWN", color::dim(&report.summary.unknown.to_string()))
            } else {
                String::new()
            }
        );
        println!();
    }
}

fn print_finding(f: &AuditFinding, applicability: Option<&ApplicabilityResult>) {
    let coord = format!("{}:{}", f.group, f.artifact);
    let direct_tag = if f.direct {
        color::dim("[direct]")
    } else {
        color::dim("[transitive]")
    };

    let mut crit = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    for v in &f.vulnerabilities {
        match v.severity {
            VulnSeverity::Critical => crit += 1,
            VulnSeverity::High => high += 1,
            VulnSeverity::Medium => med += 1,
            VulnSeverity::Low => low += 1,
            VulnSeverity::Unknown => {}
        }
    }
    let mut severity_summary: Vec<String> = Vec::new();
    if crit > 0 { severity_summary.push(color::red(&format!("{} CRITICAL", crit))); }
    if high > 0 { severity_summary.push(color::red(&format!("{} HIGH", high))); }
    if med > 0 { severity_summary.push(color::yellow(&format!("{} MEDIUM", med))); }
    if low > 0 { severity_summary.push(color::dim(&format!("{} LOW", low))); }

    println!(
        "{} {} {}  {} {}  ({})",
        severity_color(f.max_severity, "▶"),
        color::bold(&coord),
        color::bold(&f.version),
        color::dim(&format!("({})", f.scope)),
        direct_tag,
        severity_summary.join(", ")
    );

    // Applicability
    if let Some(app) = applicability {
        let level_str = match app.level {
            ApplicabilityLevel::High => color::red("HIGH"),
            ApplicabilityLevel::Low => color::green("LOW"),
            ApplicabilityLevel::Unknown => color::dim("UNKNOWN"),
        };
        println!(
            "    Applicability: {} — {}",
            level_str,
            app.detail
        );
        for mf in app.matching_files.iter().take(3) {
            println!("      {}", color::dim(mf));
        }
        if app.matching_files.len() > 3 {
            println!("      {}", color::dim(&format!("({} more files)", app.matching_files.len() - 3)));
        }
    }

    let mut vulns = f.vulnerabilities.clone();
    vulns.sort_by(|a, b| b.severity.cmp(&a.severity));
    let max_vulns = 5;
    for v in vulns.iter().take(max_vulns) {
        let sev_label = severity_color(v.severity, v.severity.as_str());
        let alias_short = v
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .map(|s| s.as_str())
            .unwrap_or(&v.id);
        println!(
            "    {:9} {}  {}",
            sev_label,
            color::bold(alias_short),
            v.summary.lines().next().unwrap_or("").trim()
        );
        if !v.fixed_versions.is_empty() {
            println!(
                "              fixed in {}",
                color::green(&v.fixed_versions.join(", "))
            );
        }
    }
    if vulns.len() > max_vulns {
        println!(
            "    {} {} more vulnerabilities — run with --output json for full list",
            color::dim("…"),
            vulns.len() - max_vulns
        );
    }

    let recommended = recommend_upgrade(&vulns, &f.version);
    if let Some(target) = recommended {
        println!(
            "    {} upgrade {} → {}",
            color::green("→"),
            f.version,
            color::green(&target)
        );
    }

    if !f.paths.is_empty() && !f.direct {
        for (i, p) in f.paths.iter().take(3).enumerate() {
            let path_str = p[1..].join(" → ");
            println!("    {} {}", color::dim(&format!("path[{}]", i + 1)), color::dim(&path_str));
        }
        if f.paths.len() > 3 {
            println!(
                "    {}",
                color::dim(&format!(
                    "({} more path(s) — `depintel why {}` for all)",
                    f.paths.len() - 3,
                    coord
                ))
            );
        }
    }

    println!();
}

fn recommend_upgrade(vulns: &[crate::audit::osv::Vulnerability], current: &str) -> Option<String> {
    fix_plan::best_fixed_version(vulns, current)
}

fn print_fix_plan_text(plan: &fix_plan::FixPlan) {
    println!();
    let total = plan.total_cves_fixed + plan.total_cves_remaining;
    let upgrades_with_fixes: Vec<_> = plan.upgrades.iter().filter(|u| u.cves_fixed_count > 0).collect();

    println!(
        "{} {} upgrade(s) to fix {} of {} CVE(s)",
        color::bold("FIX PLAN:"),
        upgrades_with_fixes.len(),
        color::green(&plan.total_cves_fixed.to_string()),
        total,
    );
    println!();

    for (i, upgrade) in upgrades_with_fixes.iter().enumerate() {
        println!(
            "  {}. {}:{}",
            i + 1,
            color::bold(&upgrade.group),
            color::bold(&upgrade.artifact),
        );
        println!(
            "     {} → {}",
            color::dim(&upgrade.from_version),
            color::green(&upgrade.to_version),
        );
        println!(
            "     Fixes: {} ({} CVE(s))",
            upgrade.severity_summary,
            upgrade.cves_fixed_count,
        );
        if !upgrade.cves_remaining.is_empty() {
            println!(
                "     Remaining: {} CVE(s) with no fix in this version",
                upgrade.cves_remaining.len(),
            );
        }
        println!();
    }

    if plan.total_cves_remaining > 0 {
        println!(
            "  {} CVE(s) have no known fix version.",
            color::yellow(&plan.total_cves_remaining.to_string()),
        );
        println!();
    }
}

fn print_json(
    reports: &[AuditReport],
    applicability: &Option<Vec<Vec<ApplicabilityResult>>>,
    plan: &Option<fix_plan::FixPlan>,
) -> Result<()> {
    // Always output a consistent JSON structure
    let app_value = match applicability {
        Some(app) => {
            let flat: Vec<&ApplicabilityResult> = app.iter().flat_map(|r| r.iter()).collect();
            serde_json::to_value(flat)?
        }
        None => serde_json::Value::Null,
    };

    let plan_value = match plan {
        Some(p) => serde_json::to_value(p)?,
        None => serde_json::Value::Null,
    };

    let output = serde_json::json!({
        "reports": reports,
        "applicability": app_value,
        "fix_plan": plan_value,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::osv::Vulnerability;

    fn vuln(id: &str, severity: VulnSeverity, fixed: &[&str]) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            aliases: vec![],
            summary: String::new(),
            severity,
            cvss_score: None,
            fixed_versions: fixed.iter().map(|v| v.to_string()).collect(),
            sources: vec![],
            unfixed_from: vec![],
            last_affected: vec![],
        }
    }

    #[test]
    fn recommended_upgrade_covers_all_fixes_on_a_tie() {
        let vulns = vec![
            vuln("GHSA-a", VulnSeverity::High, &["1.1"]),
            vuln("GHSA-b", VulnSeverity::High, &["1.2"]),
        ];
        assert_eq!(recommend_upgrade(&vulns, "1.0").as_deref(), Some("1.2"));
    }

    #[test]
    fn severity_filter_keeps_per_vulnerability_summary_counts() {
        let vulnerabilities = vec![
            vuln("GHSA-a", VulnSeverity::Critical, &[]),
            vuln("GHSA-b", VulnSeverity::High, &[]),
            vuln("GHSA-c", VulnSeverity::High, &[]),
        ];
        let mut report = AuditReport {
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
        };
        apply_severity_filter(&mut report, VulnSeverity::High);
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.summary.high, 2);
    }

    #[test]
    fn recommendation_never_offers_a_fix_older_than_current() {
        let vulns = vec![vuln("GHSA-a", VulnSeverity::High, &["2.0"])];
        assert_eq!(recommend_upgrade(&vulns, "3.5"), None);
    }
}
