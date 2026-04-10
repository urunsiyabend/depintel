use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

use petgraph::Direction;

use crate::audit::cache::OsvCache;
use crate::audit::osv::OsvClient;
use crate::audit::report;
use crate::bump::diff::{
    diff_conflicts, diff_cves, diff_graphs, ConflictDiff, CveDelta, GraphDiff,
};
use crate::bump::runner;
use crate::bump::scorer::{
    self, recommended_actions, Action, RiskAssessment, RiskLevel, ScoringInputs,
};
use crate::cli::list::collect_or_cache;
use crate::collector::{maven::CollectGoals, verbose_tree};
use crate::graph::builder::{self, DepGraph};
use crate::model::ArtifactKey;
use crate::output::color;

fn outgoing_count(graph: &DepGraph, key: &ArtifactKey, version: &str) -> usize {
    match graph.find_node_versioned(key, version) {
        Some(idx) => graph
            .graph
            .neighbors_directed(idx, Direction::Outgoing)
            .count(),
        None => 0,
    }
}

const DISCLAIMER_TEXT: &str = "\
  ─────
  depintel assesses dependency graph structure, version conflicts, and known
  CVEs. It does not perform static analysis, bytecode inspection, or API
  compatibility checking. Always verify with your test suite.";

/// Outcome of a bump preview. `HighRisk` is distinguished from `Ok` so the
/// CLI entry point can return a non-zero exit code *without* calling
/// `std::process::exit`, which would bypass destructors and flushers.
pub enum BumpOutcome {
    Ok,
    HighRisk,
}

pub fn run(
    pom_dir: &Path,
    output_format: &str,
    spec: &str,
    target_version_opt: Option<&str>,
    fresh: bool,
    offline: bool,
) -> Result<BumpOutcome> {
    let (group, artifact, explicit_target) = parse_spec(spec, target_version_opt)?;
    let target_version = explicit_target
        .as_deref()
        .context("Missing target version. Use --to <version> or group:artifact:version")?
        .to_string();

    // 1. Baseline — force a fresh run so we diff against the *current* pom.xml,
    // not whatever the cache has. Comparing a stale cache to a freshly mutated
    // POM produces phantom added/removed entries from unrelated edits.
    let baseline_goals = CollectGoals {
        effective_pom: false,
        verbose_tree: true,
        dep_list: false,
    };
    let (_, baseline_tree_raw, _) = collect_or_cache(pom_dir, baseline_goals, true, offline)?;
    let _ = fresh; // `fresh` is implicit for bump; kept in signature for symmetry.
    let baseline_trees = verbose_tree::parse_verbose_tree(&baseline_tree_raw)?;
    if baseline_trees.is_empty() {
        anyhow::bail!("Baseline Maven output is empty — cannot analyse this POM.");
    }
    // Multi-module projects emit one tree per module; fold them all into a
    // single project-wide graph so bumps work regardless of which module
    // actually declares the target artifact.
    let baseline_graph = builder::build_combined_graph(&baseline_trees);

    // Sanity: does the artifact actually appear in the baseline graph?
    let key = ArtifactKey::new(&group, &artifact);
    let baseline_selected = baseline_graph
        .get_requests(&key)
        .and_then(|reqs| reqs.iter().find(|r| r.selected).cloned());
    let baseline_version = match baseline_selected.as_ref() {
        Some(r) => r.version.clone(),
        None => anyhow::bail!(
            "Artifact '{}:{}' is not in the resolved dependency graph.\n\
             `depintel bump` can only preview artifacts that are actually selected in the current tree.",
            group,
            artifact
        ),
    };

    if baseline_version == target_version {
        if output_format == "json" {
            // Emit a well-formed "no-op" preview so JSON consumers never see
            // empty output for this case.
            let noop = serde_json::json!({
                "artifact": {
                    "group": group,
                    "artifact": artifact,
                    "from": baseline_version,
                    "to": target_version,
                },
                "noop": true,
                "message": format!("already at {}", target_version),
                "risk": {
                    "level": "low",
                    "basis": "graph_only",
                    "reasons": []
                },
                "cves": {"fixed": [], "introduced": [], "unchanged_count": 0},
                "transitive_changes": {"version_changes": [], "added": [], "removed": []},
                "conflicts": {"new": [], "resolved": []},
                "recommended_actions": []
            });
            println!("{}", serde_json::to_string_pretty(&noop)?);
        } else {
            println!(
                "{} is already at {}. Nothing to preview.",
                color::bold(&format!("{}:{}", group, artifact)),
                target_version
            );
        }
        return Ok(BumpOutcome::Ok);
    }

    // Determine baseline scope (affects risk modifiers).
    let baseline_scope = baseline_graph
        .find_node_versioned(&key, &baseline_version)
        .map(|idx| baseline_graph.graph[idx].scope.to_string())
        .unwrap_or_else(|| "compile".to_string());

    // 2. Override — mutate POM, run Maven, restore POM.
    if offline {
        anyhow::bail!(
            "bump requires running Maven against the modified POM — --offline is not supported. \
             Omit --offline so Maven can resolve the target version."
        );
    }
    let override_output_dir = pom_dir.join(".depintel").join("bump-preview");

    let override_raw = runner::collect_with_override(
        pom_dir,
        &override_output_dir,
        &group,
        &artifact,
        &target_version,
        CollectGoals {
            effective_pom: false,
            verbose_tree: true,
            dep_list: false,
        },
    )
    .with_context(|| {
        format!(
            "Could not build override graph for {}:{} → {}. \
             The target version may not exist in Maven Central or may have incompatible dependency requirements.",
            group, artifact, target_version
        )
    })?;

    let override_trees = verbose_tree::parse_verbose_tree(&override_raw.verbose_tree)?;
    if override_trees.is_empty() {
        anyhow::bail!("Override Maven output is empty — the mutated POM produced no tree.");
    }
    let override_graph = builder::build_combined_graph(&override_trees);

    // Sanity check #1: did Maven actually resolve the target version?
    let override_selected = override_graph
        .get_requests(&key)
        .and_then(|reqs| reqs.iter().find(|r| r.selected).cloned());
    match override_selected.as_ref() {
        Some(req) if req.version == target_version => {}
        Some(req) => anyhow::bail!(
            "Maven did not resolve {}:{} at the requested version {}. It ended up at {} instead.\n\
             This usually means {} is not a valid version. Verify on Maven Central:\n\
             https://central.sonatype.com/artifact/{}/{}",
            group, artifact, target_version, req.version, target_version, group, artifact
        ),
        None => anyhow::bail!(
            "After the bump the artifact {}:{} disappeared from the graph entirely.\n\
             This usually means the version {} does not exist in Maven Central or cannot be resolved.\n\
             Verify: https://central.sonatype.com/artifact/{}/{}",
            group, artifact, target_version, group, artifact
        ),
    }

    // Sanity check #2: did Maven actually DOWNLOAD the target's POM?
    // When the POM is missing from Central, dependency:tree often still prints
    // the artifact line (because it's in our mutated pom.xml) but has no clue
    // about its transitives — the subtree silently shrinks to zero.
    // Detect by comparing out-edge counts: if baseline had >0 children and
    // override now has 0, the target version's POM was not resolvable.
    let baseline_children = outgoing_count(&baseline_graph, &key, &baseline_version);
    let override_children = outgoing_count(&override_graph, &key, &target_version);
    // Heuristic warning, not a hard bail: some legitimate bumps DO shed all
    // transitive deps (e.g. a library that deleted its runtime requirements
    // between 1.x and 2.x). Previously this was an error that blocked valid
    // previews. Keep the diagnostic as a stderr warning so the user has the
    // signal but analysis still completes.
    if baseline_children >= 2 && override_children == 0 {
        eprintln!(
            "warning: {}:{} {} was placed in the tree but its transitive subtree is empty \
             (baseline had {} transitive dependencies). This can be a legitimate upstream \
             change or it can mean {}'s POM was not downloadable. Verify on Maven Central:\n  \
             https://central.sonatype.com/artifact/{}/{}",
            group, artifact, target_version, baseline_children, target_version, group, artifact
        );
    }

    // 3. Graph diff.
    let graph_diff = diff_graphs(&baseline_graph, &override_graph);

    // 4. Conflict diff.
    let conflict_diff = diff_conflicts(&baseline_graph, &override_graph);

    // 5. CVE delta — reuse audit pipeline on both graphs.
    let osv_cache = OsvCache::default_location()?;
    let osv_client = OsvClient::new(osv_cache);
    let baseline_audit = report::build_report(&baseline_graph, &osv_client, true)?;
    let override_audit = report::build_report(&override_graph, &osv_client, true)?;
    let cve_delta = diff_cves(&baseline_audit, &override_audit);

    // 6. Score risk.
    // Count how many new conflicts involve a major-version gap.
    let conflicts_new_major_count = conflict_diff
        .new
        .iter()
        .filter(|c| c.version_jump == "major")
        .count();
    // Is this artifact managed in baseline's effective POM? Heuristic: did any
    // baseline request for this key come with a managed_from? If so, treat the
    // override as intentional (managed_override) which drops risk one notch.
    let managed_override = baseline_graph
        .get_requests(&key)
        .map(|reqs| reqs.iter().any(|r| r.managed_from.is_some()))
        .unwrap_or(false);

    let assessment = scorer::score(&ScoringInputs {
        from_version: &baseline_version,
        to_version: &target_version,
        scope: &baseline_scope,
        graph_diff: &graph_diff,
        conflicts_new_count: conflict_diff.new.len(),
        conflicts_new_major_count,
        cve_delta: &cve_delta,
        managed_override,
    });

    let actions = recommended_actions(assessment.level, &baseline_version, &target_version, &cve_delta);

    let preview = BumpPreview {
        artifact: ArtifactSpec {
            group: group.clone(),
            artifact: artifact.clone(),
            from: baseline_version.clone(),
            to: target_version.clone(),
        },
        risk: &assessment,
        graph_diff: &graph_diff,
        conflicts: &conflict_diff,
        cves: &cve_delta,
        actions: &actions,
    };

    match output_format {
        "json" => print_json(&preview)?,
        _ => print_text(&preview, &baseline_scope),
    }

    // CI gate: HIGH or CRITICAL returns HighRisk so main() can set exit(2)
    // *after* destructors and buffered writers have flushed.
    if matches!(assessment.level, RiskLevel::High | RiskLevel::Critical) {
        Ok(BumpOutcome::HighRisk)
    } else {
        Ok(BumpOutcome::Ok)
    }
}

fn parse_spec(
    spec: &str,
    target_opt: Option<&str>,
) -> Result<(String, String, Option<String>)> {
    // Accept any of these Maven coordinate forms:
    //   group:artifact                          (+ --to version)
    //   group:artifact:version
    //   group:artifact:packaging:version        (Maven GAV-extended)
    //   group:artifact:packaging:classifier:version
    // Whitespace around each part is trimmed; empty parts are rejected.
    let parts: Vec<String> = spec.split(':').map(|p| p.trim().to_string()).collect();

    let (group, artifact, embedded_version) = match parts.len() {
        2 => (parts[0].clone(), parts[1].clone(), None),
        3 => (parts[0].clone(), parts[1].clone(), Some(parts[2].clone())),
        4 => {
            // group:artifact:packaging:version
            (parts[0].clone(), parts[1].clone(), Some(parts[3].clone()))
        }
        5 => {
            // group:artifact:packaging:classifier:version
            (parts[0].clone(), parts[1].clone(), Some(parts[4].clone()))
        }
        _ => anyhow::bail!(
            "Invalid bump target '{}'. Use 'group:artifact --to version', \
             'group:artifact:version', or a full Maven GAV like \
             'group:artifact:packaging:version'.",
            spec
        ),
    };

    if group.is_empty() {
        anyhow::bail!("Invalid bump target '{}': groupId is empty.", spec);
    }
    if artifact.is_empty() {
        anyhow::bail!("Invalid bump target '{}': artifactId is empty.", spec);
    }

    // Version must come from exactly one place.
    let target_trimmed = target_opt.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let target_version = match (embedded_version, target_trimmed) {
        (Some(v), None) => {
            if v.is_empty() {
                anyhow::bail!(
                    "Invalid bump target '{}': trailing ':' with empty version. Use --to <version> or drop the colon.",
                    spec
                );
            }
            Some(v)
        }
        (None, Some(v)) => Some(v),
        (Some(_), Some(_)) => anyhow::bail!(
            "Version specified twice: '{}' already contains a version, don't pass --to as well.",
            spec
        ),
        (None, None) => None,
    };

    Ok((group, artifact, target_version))
}

// ------------------------------------------------------------------
// Output types
// ------------------------------------------------------------------

#[derive(Serialize)]
struct ArtifactSpec {
    group: String,
    artifact: String,
    from: String,
    to: String,
}

#[derive(Serialize)]
struct BumpPreview<'a> {
    artifact: ArtifactSpec,
    risk: &'a RiskAssessment,
    #[serde(rename = "transitive_changes")]
    graph_diff: &'a GraphDiff,
    conflicts: &'a ConflictDiff,
    cves: &'a CveDelta,
    #[serde(rename = "recommended_actions")]
    actions: &'a [Action],
}

fn print_json(preview: &BumpPreview) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(preview)?);
    Ok(())
}

fn risk_color(level: RiskLevel, text: &str) -> String {
    match level {
        RiskLevel::Critical => color::red(text),
        RiskLevel::High => color::red(text),
        RiskLevel::Medium => color::yellow(text),
        RiskLevel::Low => color::green(text),
    }
}

fn severity_color(sev: &str, text: &str) -> String {
    match sev {
        "CRITICAL" | "HIGH" => color::red(text),
        "MEDIUM" => color::yellow(text),
        _ => color::dim(text),
    }
}

fn print_text(preview: &BumpPreview, scope: &str) {
    let a = &preview.artifact;
    println!();
    println!(
        "{} {}:{} {} → {}",
        color::bold("BUMP PREVIEW:"),
        a.group,
        color::bold(&a.artifact),
        color::dim(&a.from),
        color::green(&a.to),
    );
    println!();

    println!(
        "  Graph risk: {}",
        risk_color(preview.risk.level, preview.risk.level.as_str())
    );
    println!("  Basis: graph-level signals only (no bytecode/API analysis)");
    println!("  Scope: {}", scope);
    println!();

    if preview.risk.reasons.is_empty() {
        println!("  Reasons: no risk signals detected");
    } else {
        println!("  Reasons:");
        for r in &preview.risk.reasons {
            println!("    - {}", r);
        }
    }
    println!();

    // --- CVEs fixed ---
    if !preview.cves.fixed.is_empty() {
        println!(
            "  {} ({}):",
            color::bold("CVEs fixed"),
            preview.cves.fixed.len()
        );
        for e in preview.cves.fixed.iter().take(10) {
            println!(
                "    {:9} {}  {}",
                severity_color(&e.severity, &e.severity),
                color::bold(&e.id),
                e.summary
            );
        }
        if preview.cves.fixed.len() > 10 {
            println!(
                "    {}",
                color::dim(&format!("… {} more", preview.cves.fixed.len() - 10))
            );
        }
        println!();
    }

    // --- CVEs introduced ---
    if preview.cves.introduced.is_empty() {
        println!("  CVEs introduced: {}", color::green("none"));
    } else {
        println!(
            "  {} ({}):",
            color::bold("CVEs introduced"),
            preview.cves.introduced.len()
        );
        for e in preview.cves.introduced.iter().take(10) {
            println!(
                "    {:9} {}  {}",
                severity_color(&e.severity, &e.severity),
                color::bold(&e.id),
                e.summary
            );
        }
        if preview.cves.introduced.len() > 10 {
            println!(
                "    {}",
                color::dim(&format!("… {} more", preview.cves.introduced.len() - 10))
            );
        }
    }
    println!();

    // --- Transitive changes ---
    let has_changes = !preview.graph_diff.version_changes.is_empty()
        || !preview.graph_diff.added.is_empty()
        || !preview.graph_diff.removed.is_empty();
    if has_changes {
        println!("  {}", color::bold("Transitive changes:"));
        for c in &preview.graph_diff.version_changes {
            println!(
                "    ~ {}:{} {} → {}",
                c.group,
                c.artifact,
                color::dim(&c.from),
                color::green(&c.to)
            );
        }
        for added in &preview.graph_diff.added {
            println!(
                "    + {}:{} {} {}",
                added.group,
                added.artifact,
                added.version,
                color::dim("(new)")
            );
        }
        for removed in &preview.graph_diff.removed {
            println!(
                "    - {}:{} {} {}",
                removed.group,
                removed.artifact,
                removed.version,
                color::dim("(removed)")
            );
        }
    } else {
        println!("  Transitive changes: {}", color::dim("none"));
    }
    println!();

    // --- Conflicts ---
    if !preview.conflicts.new.is_empty() {
        println!("  {}:", color::bold("New conflicts"));
        for c in &preview.conflicts.new {
            println!(
                "    {} {}  ({} → {}, {})",
                severity_color(&c.severity, &c.severity),
                c.artifact,
                color::dim(&c.overridden.join(", ")),
                color::green(&c.selected),
                c.version_jump
            );
        }
    } else {
        println!("  New conflicts: {}", color::green("none"));
    }

    if !preview.conflicts.resolved.is_empty() {
        println!("  {}:", color::bold("Conflicts resolved"));
        for c in &preview.conflicts.resolved {
            println!("    {} {}", color::green("✓"), c.artifact);
        }
    }
    println!();

    // --- Recommended actions ---
    println!("  {}:", color::bold("Recommended actions"));
    for (i, action) in preview.actions.iter().enumerate() {
        let (label, detail) = match action {
            Action::RunTests { detail } => ("Run tests", detail.as_str()),
            Action::ReviewChangelog { detail } => ("Review changelog", detail.as_str()),
            Action::CheckApiCompat { detail } => ("Check API compatibility", detail.as_str()),
            Action::BumpParentFirst { detail, .. } => ("Bump parent first", detail.as_str()),
            Action::ManualReview { detail } => ("Manual review required", detail.as_str()),
        };
        println!("    {}. {}: {}", i + 1, color::bold(label), detail);
    }
    println!();
    println!("{}", DISCLAIMER_TEXT);
    println!();
}
