use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use crate::cli::list::collect_or_cache;
use crate::collector::{effective_pom, verbose_tree};
use crate::graph::builder::{self, VersionRequest};
use crate::graph::path::{self, request_status_label, WhyOptions, WhyResult, WhyWarning};
use crate::model::ArtifactKey;
use crate::output::color;

pub fn run(
    pom_dir: &Path,
    artifact: &str,
    output_format: &str,
    module: Option<&str>,
    depth: Option<usize>,
    all_versions: bool,
    fresh: bool,
    offline: bool,
) -> Result<()> {
    let key = ArtifactKey::parse(artifact).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid artifact format: '{}'. Expected groupId:artifactId",
            artifact
        )
    })?;

    // why needs verbose_tree + effective_pom, not dep_list
    let goals = crate::collector::maven::CollectGoals {
        effective_pom: true,
        verbose_tree: true,
        dep_list: false,
    };
    let (effective_pom_raw, verbose_tree_raw, _) = collect_or_cache(pom_dir, goals, fresh, offline)?;
    let trees = verbose_tree::parse_verbose_tree(&verbose_tree_raw)?;

    if trees.is_empty() {
        anyhow::bail!("No dependency tree found in Maven output.");
    }

    // Parse effective POM for dependencyManagement cross-reference
    let pom_modules = effective_pom::parse_effective_pom(&effective_pom_raw)
        .ok()
        .unwrap_or_default();

    let managed_deps: Vec<_> = pom_modules
        .iter()
        .flat_map(|m| m.managed_dependencies.clone())
        .collect();

    let bom_imports: Vec<_> = pom_modules
        .iter()
        .flat_map(|m| m.bom_imports.clone())
        .collect();

    let options = WhyOptions {
        max_depth: depth,
        all_versions,
        managed_deps,
        bom_imports,
    };

    // Filter by module if specified
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
            let available: Vec<_> = trees
                .iter()
                .map(|t| t.root.artifact.key.artifact_id.as_str())
                .collect();
            anyhow::bail!(
                "Module '{}' not found. Available: {}",
                mod_name,
                available.join(", ")
            );
        }
    }

    // Build graphs and query
    let mut results: Vec<WhyResult> = Vec::new();
    for tree in &trees_filtered {
        let graph = builder::build_graph(tree);
        if let Some(result) = path::why_artifact(&graph, &key, &options) {
            results.push(result);
        }
    }

    if results.is_empty() {
        match output_format {
            "json" => {
                let err = serde_json::json!({
                    "query": artifact,
                    "error": "not_found",
                    "message": "Artifact not present in dependency graph"
                });
                println!("{}", serde_json::to_string_pretty(&err)?);
            }
            _ => {
                eprintln!("Artifact '{}' not found in dependency graph.", artifact);
            }
        }
        std::process::exit(1);
    }

    match output_format {
        "json" => print_json(&key, &results)?,
        _ => print_text(&key, &results, module.is_some()),
    }

    Ok(())
}

fn print_text(key: &ArtifactKey, results: &[WhyResult], single_module: bool) {
    println!("{} {}", color::bold("WHY:"), color::cyan(&key.to_string()));
    println!();

    if results.len() == 1 || single_module {
        for result in results {
            print_single_module_text(result);
        }
    } else {
        println!("Found in {} modules:", results.len());
        println!();

        for result in results {
            println!("  Module: {}", result.module_label);
            if let Some(ref ver) = result.selected_version {
                println!(
                    "    Selected: {} ({})",
                    ver, result.resolution.reason
                );
            }
            println!("    Paths: {}", result.requests.len());
            for w in &result.warnings {
                println!("    ⚠ {}", w.description);
            }
            println!();
        }

        println!("Run with --module <name> for full path details.");
    }
}

fn print_single_module_text(result: &WhyResult) {
    if let Some(ref ver) = result.selected_version {
        println!("Selected version: {}", color::green(ver));
    }
    if let Some(ref scope) = result.selected_scope {
        println!("Scope: {}", scope);
    }
    println!();

    println!("Resolution reason:");
    println!("  {}", result.resolution.detail);
    if let Some(ref src) = result.resolution.source {
        match src.source_type.as_str() {
            "path_depth" => {
                if let (Some(sd), Some(od)) = (src.selected_depth, src.overridden_depth) {
                    println!("  (depth {} vs depth {})", sd, od);
                }
            }
            "bom" | "dependency_management" => {
                if let Some(ref aid) = src.artifact_id {
                    println!("  source: {}", aid);
                }
            }
            _ => {}
        }
    }

    // Count real overrides (different version) vs duplicates (same version)
    let overridden_count = result
        .requests
        .iter()
        .filter(|r| {
            request_status_label(r, result.selected_version.as_deref()) == "overridden"
        })
        .count();
    if overridden_count > 0 {
        println!(
            "  overrides {} other requested version(s)",
            overridden_count
        );
    }
    println!();

    // Requested versions — only show if there are different versions or overrides
    let has_overrides = overridden_count > 0;
    let distinct_versions: std::collections::HashSet<_> =
        result.requests.iter().map(|r| &r.version).collect();
    let show_requested = has_overrides || distinct_versions.len() > 1 || result.requests.len() > 1;

    if show_requested {
        println!("Requested versions:");
        for req in &result.requests {
            let status = request_status_label(req, result.selected_version.as_deref());
            let (marker, ver_display) = match status {
                "selected" => (color::green("✔"), color::green(&req.version)),
                "duplicate" => (color::dim("="), color::dim(&req.version)),
                "overridden" => (color::red("✘"), color::red(&req.version)),
                _ => ("?".to_string(), req.version.clone()),
            };
            let path_str = req.path[1..].join(" → ");
            let managed = req
                .managed_from
                .as_deref()
                .map(|v| format!(" (managed from {})", v))
                .unwrap_or_default();
            println!(
                "  {} {}  ← {} [{}]{}",
                marker, ver_display, path_str, status, managed
            );
        }
        println!();
    }

    // Dependency paths
    println!("Dependency paths ({} found):", result.requests.len());
    println!();

    for (i, req) in result.requests.iter().enumerate() {
        let status = request_status_label(req, result.selected_version.as_deref());
        let (marker, status_display) = match status {
            "selected" => (color::green("✔"), color::green("selected")),
            "duplicate" => (color::dim("="), color::dim("duplicate")),
            "overridden" => (color::red("✘"), color::red("overridden")),
            _ => ("?".to_string(), status.to_string()),
        };

        let virtual_tag = if req.virtual_path {
            color::dim(" [reconstructed via duplicate]")
        } else {
            String::new()
        };
        println!("  [{}] {}{}", i + 1, req.path[0], virtual_tag);
        for (depth, segment) in req.path[1..].iter().enumerate() {
            let is_last = depth == req.path.len() - 2;
            let prefix = "       ".repeat(depth + 1);
            if is_last {
                println!(
                    "  {}└── {}  {} ({})",
                    prefix, segment, marker, status_display
                );
            } else {
                println!("  {}└── {}", prefix, segment);
            }
        }
        println!();
    }

    // Warnings
    if !result.warnings.is_empty() {
        println!("{}:", color::bold("Warnings"));
        for w in &result.warnings {
            let icon = color::yellow("⚠");
            match w.warning_type.as_str() {
                "scope_mismatch" | "multiple_paths_same_version" => {
                    println!("  {} {}", icon, w.description);
                }
                "major_version_mismatch" => {
                    println!(
                        "  {} {} compiled against {} — {}",
                        icon, w.consumer, w.compiled_against, color::red(&w.description)
                    );
                }
                _ => {
                    println!(
                        "  {} {} compiled against {} — {}",
                        icon, w.consumer, w.compiled_against, color::yellow(&w.description)
                    );
                }
            }
        }
        println!();
    }
}

fn print_json(key: &ArtifactKey, results: &[WhyResult]) -> Result<()> {
    if results.len() == 1 {
        let r = &results[0];
        let json = WhyJsonSingle {
            query: key.to_string(),
            selected: r.selected_version.as_ref().map(|v| WhyJsonSelected {
                group: key.group_id.clone(),
                artifact: key.artifact_id.clone(),
                version: v.clone(),
                scope: r.selected_scope.clone().unwrap_or_default(),
            }),
            resolution: resolution_to_json(&r.resolution),
            requested_versions: requests_to_json(&r.requests, r.selected_version.as_deref()),
            warnings: warnings_to_json(&r.warnings),
        };
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        let modules: Vec<WhyJsonModule> = results
            .iter()
            .map(|r| WhyJsonModule {
                module: r.module_label.clone(),
                selected: r.selected_version.as_ref().map(|v| WhyJsonSelected {
                    group: key.group_id.clone(),
                    artifact: key.artifact_id.clone(),
                    version: v.clone(),
                    scope: r.selected_scope.clone().unwrap_or_default(),
                }),
                resolution: resolution_to_json(&r.resolution),
                requested_versions: requests_to_json(&r.requests, r.selected_version.as_deref()),
                warnings: warnings_to_json(&r.warnings),
            })
            .collect();

        let json = WhyJsonMulti {
            query: key.to_string(),
            modules,
        };
        println!("{}", serde_json::to_string_pretty(&json)?);
    }
    Ok(())
}

fn resolution_to_json(res: &path::ResolutionInfo) -> WhyJsonResolution {
    WhyJsonResolution {
        reason: res.reason.clone(),
        detail: res.detail.clone(),
        source: res.source.as_ref().map(|s| WhyJsonSource {
            source_type: s.source_type.clone(),
            group: s.group_id.clone(),
            artifact: s.artifact_id.clone(),
            version: s.version.clone(),
            selected_depth: s.selected_depth,
            overridden_depth: s.overridden_depth,
        }),
    }
}

fn requests_to_json(requests: &[VersionRequest], selected_version: Option<&str>) -> Vec<WhyJsonRequested> {
    requests
        .iter()
        .map(|req| WhyJsonRequested {
            version: req.version.clone(),
            status: request_status_label(req, selected_version).to_string(),
            path: req.path.clone(),
            managed_from: req.managed_from.clone(),
            virtual_path: req.virtual_path,
        })
        .collect()
}

fn warnings_to_json(warnings: &[WhyWarning]) -> Vec<WhyJsonWarning> {
    warnings
        .iter()
        .map(|w| WhyJsonWarning {
            warning_type: w.warning_type.clone(),
            artifact: w.consumer.clone(),
            compiled_against: w.compiled_against.clone(),
            resolved_to: w.resolved_to.clone(),
            description: w.description.clone(),
        })
        .collect()
}

// --- JSON types ---

#[derive(Serialize)]
struct WhyJsonSingle {
    query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected: Option<WhyJsonSelected>,
    resolution: WhyJsonResolution,
    requested_versions: Vec<WhyJsonRequested>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<WhyJsonWarning>,
}

#[derive(Serialize)]
struct WhyJsonMulti {
    query: String,
    modules: Vec<WhyJsonModule>,
}

#[derive(Serialize)]
struct WhyJsonModule {
    module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected: Option<WhyJsonSelected>,
    resolution: WhyJsonResolution,
    requested_versions: Vec<WhyJsonRequested>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<WhyJsonWarning>,
}

#[derive(Serialize)]
struct WhyJsonSelected {
    group: String,
    artifact: String,
    version: String,
    scope: String,
}

#[derive(Serialize)]
struct WhyJsonResolution {
    reason: String,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<WhyJsonSource>,
}

#[derive(Serialize)]
struct WhyJsonSource {
    #[serde(rename = "type")]
    source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overridden_depth: Option<usize>,
}

#[derive(Serialize)]
struct WhyJsonRequested {
    version: String,
    status: String,
    path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_from: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    virtual_path: bool,
}

#[derive(Serialize)]
struct WhyJsonWarning {
    #[serde(rename = "type")]
    warning_type: String,
    artifact: String,
    compiled_against: String,
    resolved_to: String,
    description: String,
}
