use anyhow::Result;
use std::path::Path;

use crate::audit::cache::OsvCache;
use crate::audit::osv::{OsvClient, VulnSeverity};
use crate::audit::report::{build_report, AuditFinding, AuditReport, AuditSummary};
use crate::cli::list::collect_or_cache;
use crate::collector::{maven::CollectGoals, verbose_tree};
use crate::graph::builder;
use crate::output::color;

pub fn run(
    pom_dir: &Path,
    output_format: &str,
    module: Option<&str>,
    severity_filter: Option<&str>,
    include_test: bool,
    fresh_cves: bool,
    fresh: bool,
    offline: bool,
) -> Result<()> {
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
            report.findings.retain(|f| f.max_severity >= want);
            // Recompute summary so it reflects the filter
            let mut summary = AuditSummary::default();
            for f in &report.findings {
                summary.bump(f.max_severity);
            }
            report.summary = summary;
        }

        reports.push(report);
    }

    match output_format {
        "json" => print_json(&reports)?,
        _ => print_text(&reports),
    }

    // CI gate: exit 2 if any HIGH or CRITICAL findings remain after filtering.
    let any_blocking = reports.iter().any(|r| r.summary.high > 0 || r.summary.critical > 0);
    if any_blocking {
        std::process::exit(2);
    }

    Ok(())
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

fn print_text(reports: &[AuditReport]) {
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

    for report in reports {
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

        for finding in &report.findings {
            print_finding(finding);
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

fn print_finding(f: &AuditFinding) {
    let coord = format!("{}:{}", f.group, f.artifact);
    let direct_tag = if f.direct {
        color::dim("[direct]")
    } else {
        color::dim("[transitive]")
    };

    // Per-artifact header: severity counts inside the dep + coord + version + context.
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
    if crit > 0 {
        severity_summary.push(color::red(&format!("{} CRITICAL", crit)));
    }
    if high > 0 {
        severity_summary.push(color::red(&format!("{} HIGH", high)));
    }
    if med > 0 {
        severity_summary.push(color::yellow(&format!("{} MEDIUM", med)));
    }
    if low > 0 {
        severity_summary.push(color::dim(&format!("{} LOW", low)));
    }

    println!(
        "{} {} {}  {} {}  ({})",
        severity_color(f.max_severity, "▶"),
        color::bold(&coord),
        color::bold(&f.version),
        color::dim(&format!("({})", f.scope)),
        direct_tag,
        severity_summary.join(", ")
    );

    // Show top vulns sorted by severity (descending). Cap to 5 by default;
    // remaining count printed at bottom.
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

    // Recommended fix: lowest fixed version that beats them all (best-effort).
    let recommended = recommend_upgrade(&vulns);
    if let Some(target) = recommended {
        println!(
            "    {} upgrade {} → {}",
            color::green("→"),
            f.version,
            color::green(&target)
        );
    }

    // Paths (top 3)
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

/// Pick the smallest fixed version that appears across the most CVEs — a heuristic
/// "if you upgrade to X, you patch the most things at once".
fn recommend_upgrade(vulns: &[crate::audit::osv::Vulnerability]) -> Option<String> {
    use std::collections::HashMap;
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for v in vulns {
        for fv in &v.fixed_versions {
            *counts.entry(fv.as_str()).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(v, _)| v.to_string())
}

fn print_json(reports: &[AuditReport]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(reports)?);
    Ok(())
}
