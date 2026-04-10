use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use crate::cli::list::collect_or_cache;
use crate::collector::{effective_pom, maven::CollectGoals, verbose_tree};
use crate::graph::builder;
use crate::graph::conflict::{self, ConflictReport, Severity};
use crate::output::color;

pub fn run(
    pom_dir: &Path,
    output_format: &str,
    module: Option<&str>,
    severity_filter: Option<&str>,
    group_filter: Option<&str>,
    fresh: bool,
    offline: bool,
) -> Result<()> {
    // conflicts needs verbose_tree (for the graph) and effective_pom (for managed deps)
    let goals = CollectGoals {
        effective_pom: true,
        verbose_tree: true,
        dep_list: false,
    };
    let (effective_pom_raw, verbose_tree_raw, _) = collect_or_cache(pom_dir, goals, fresh, offline)?;
    let trees = verbose_tree::parse_verbose_tree(&verbose_tree_raw)?;

    if trees.is_empty() {
        anyhow::bail!("No dependency tree found in Maven output.");
    }

    let pom_modules = effective_pom::parse_effective_pom(&effective_pom_raw)
        .ok()
        .unwrap_or_default();
    let managed_deps: Vec<_> = pom_modules
        .iter()
        .flat_map(|m| m.managed_dependencies.clone())
        .collect();

    // Module filter
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

    // Detect conflicts per module
    let mut module_results: Vec<(String, Vec<ConflictReport>)> = Vec::new();
    for tree in &trees_filtered {
        let graph = builder::build_graph(tree);
        let mut reports = conflict::detect_conflicts(&graph, &managed_deps);

        // Apply filters
        if let Some(sev_str) = severity_filter {
            let want = parse_severity(sev_str)?;
            reports.retain(|r| r.severity >= want);
        }
        if let Some(group) = group_filter {
            reports.retain(|r| r.key.group_id.starts_with(group));
        }

        let label = format!(
            "{}:{}",
            tree.root.artifact.key, tree.root.artifact.version
        );
        module_results.push((label, reports));
    }

    match output_format {
        "json" => print_json(&module_results)?,
        _ => print_text(&module_results),
    }

    // Exit with non-zero if there are HIGH conflicts (CI gate)
    let any_high = module_results
        .iter()
        .flat_map(|(_, r)| r.iter())
        .any(|r| r.severity == Severity::High);
    if any_high {
        std::process::exit(2);
    }

    Ok(())
}

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        _ => anyhow::bail!("Unknown severity '{}'. Use: low, medium, high", s),
    }
}

fn severity_color(s: Severity, text: &str) -> String {
    match s {
        Severity::High => color::red(text),
        Severity::Medium => color::yellow(text),
        Severity::Low => color::dim(text),
    }
}

fn print_text(modules: &[(String, Vec<ConflictReport>)]) {
    let total: usize = modules.iter().map(|(_, r)| r.len()).sum();
    if total == 0 {
        println!("{} No conflicts found.", color::green("✔"));
        return;
    }

    for (label, reports) in modules {
        println!(
            "{} {} found in {}",
            color::bold("CONFLICTS:"),
            color::cyan(&reports.len().to_string()),
            color::cyan(label)
        );
        println!();

        for r in reports {
            let sev_label = severity_color(r.severity, r.severity.as_str());
            println!("  {:8}{}", sev_label, color::bold(&r.key.to_string()));

            let jump_note = match r.version_jump {
                conflict::VersionJump::Major => " (MAJOR jump)".to_string(),
                conflict::VersionJump::Minor => " (minor jump)".to_string(),
                conflict::VersionJump::Patch => " (patch)".to_string(),
                conflict::VersionJump::None => String::new(),
            };
            let downgrade_tag = if r.is_downgrade {
                format!(" {}", color::red("[DOWNGRADE]"))
            } else {
                String::new()
            };
            println!(
                "          {} → {}{}{}",
                color::dim(&r.overridden_versions.join(", ")),
                color::green(&r.selected_version),
                jump_note,
                downgrade_tag
            );
            println!("          Selected: {} ({})", r.resolution, r.scope);
            if r.managed {
                println!("          {}", color::dim("Managed by dependencyManagement / BOM"));
            }
            if let Some(ref note) = r.risk_note {
                println!("          {} {}", color::yellow("Risk:"), note);
            }
            println!(
                "          Run: {}",
                color::dim(&format!("depintel why {}", r.key))
            );
            println!();
        }

        let high = reports.iter().filter(|r| r.severity == Severity::High).count();
        let medium = reports
            .iter()
            .filter(|r| r.severity == Severity::Medium)
            .count();
        let low = reports.iter().filter(|r| r.severity == Severity::Low).count();
        println!(
            "Summary: {} HIGH, {} MEDIUM, {} LOW",
            color::red(&high.to_string()),
            color::yellow(&medium.to_string()),
            color::dim(&low.to_string())
        );
    }
}

fn print_json(modules: &[(String, Vec<ConflictReport>)]) -> Result<()> {
    let json_modules: Vec<JsonModule> = modules
        .iter()
        .map(|(label, reports)| {
            let high = reports.iter().filter(|r| r.severity == Severity::High).count();
            let medium = reports
                .iter()
                .filter(|r| r.severity == Severity::Medium)
                .count();
            let low = reports.iter().filter(|r| r.severity == Severity::Low).count();
            JsonModule {
                module: label.clone(),
                summary: JsonSummary { high, medium, low },
                conflicts: reports.iter().map(report_to_json).collect(),
            }
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_modules)?);
    Ok(())
}

fn report_to_json(r: &ConflictReport) -> JsonConflict {
    JsonConflict {
        artifact: r.key.to_string(),
        severity: r.severity.as_str().to_string(),
        selected: r.selected_version.clone(),
        overridden: r.overridden_versions.clone(),
        version_jump: r.version_jump.as_str().to_string(),
        is_downgrade: r.is_downgrade,
        resolution: r.resolution.clone(),
        scope: r.scope.clone(),
        managed: r.managed,
        risk_factors: r.risk_factors.clone(),
        risk_note: r.risk_note.clone(),
    }
}

#[derive(Serialize)]
struct JsonModule {
    module: String,
    summary: JsonSummary,
    conflicts: Vec<JsonConflict>,
}

#[derive(Serialize)]
struct JsonSummary {
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Serialize)]
struct JsonConflict {
    artifact: String,
    severity: String,
    selected: String,
    overridden: Vec<String>,
    version_jump: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_downgrade: bool,
    resolution: String,
    scope: String,
    managed: bool,
    risk_factors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_note: Option<String>,
}
