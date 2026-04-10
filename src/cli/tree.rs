use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use crate::cli::list::collect_or_cache;
use crate::collector::maven::CollectGoals;
use crate::collector::verbose_tree::{self, ModuleTree, NodeStatus, TreeNode};
use crate::graph::builder;

pub fn run(
    pom_dir: &Path,
    output_format: &str,
    module: Option<&str>,
    verbose: bool,
    fresh: bool,
    offline: bool,
) -> Result<()> {
    // tree only needs verbose_tree
    let goals = CollectGoals {
        effective_pom: false,
        verbose_tree: true,
        dep_list: false,
    };
    let (_, verbose_tree_raw, _) = collect_or_cache(pom_dir, goals, fresh, offline)?;

    let trees = verbose_tree::parse_verbose_tree(&verbose_tree_raw)?;

    if trees.is_empty() {
        eprintln!("No dependency tree found in Maven output.");
        return Ok(());
    }

    // Filter by module if specified
    let trees_to_show: Vec<&ModuleTree> = if let Some(mod_name) = module {
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

    if trees_to_show.is_empty() {
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

    match output_format {
        "json" => {
            let json_trees: Vec<JsonTreeModule> = trees_to_show
                .iter()
                .map(|tree| {
                    let graph = builder::build_graph(tree);
                    let conflicts = graph.conflicted_artifacts().len();
                    JsonTreeModule {
                        module: format!(
                            "{}:{}",
                            tree.root.artifact.key.group_id,
                            tree.root.artifact.key.artifact_id
                        ),
                        version: tree.root.artifact.version.clone(),
                        node_count: graph.graph.node_count(),
                        edge_count: graph.graph.edge_count(),
                        conflict_count: conflicts,
                        tree: tree_node_to_json(&tree.root),
                    }
                })
                .collect();

            println!("{}", serde_json::to_string_pretty(&json_trees)?);
        }
        _ => {
            for tree in &trees_to_show {
                let graph = builder::build_graph(tree);
                print_tree_node(&tree.root, "", true, true, verbose);
                let conflicts = graph.conflicted_artifacts().len();
                println!(
                    "\n{} dependencies, {} conflicts",
                    graph.graph.node_count() - 1,
                    conflicts,
                );
                if !verbose {
                    println!("(use --verbose to show omitted duplicates)");
                }
                println!();
            }
        }
    }

    Ok(())
}

fn print_tree_node(node: &TreeNode, prefix: &str, is_last: bool, is_root: bool, verbose: bool) {
    // Without --verbose, skip duplicate nodes entirely
    if !verbose && matches!(node.status, NodeStatus::OmittedForDuplicate) {
        return;
    }

    let connector = if is_root {
        ""
    } else if is_last {
        "\\- "
    } else {
        "+- "
    };

    let managed = node
        .managed_from
        .as_deref()
        .map(|v| format!(" (managed from {})", v))
        .unwrap_or_default();

    let conflict_info = match &node.status {
        NodeStatus::OmittedForConflict { winning_version } => {
            format!(" (conflict: {} wins)", winning_version)
        }
        NodeStatus::OmittedForDuplicate => " (omitted duplicate)".to_string(),
        NodeStatus::Selected => String::new(),
    };

    println!(
        "{}{}{}:{}:{}{}{}",
        prefix,
        connector,
        node.artifact.key,
        node.artifact.version,
        node.artifact.scope,
        conflict_info,
        managed,
    );

    let child_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{}   ", prefix)
    } else {
        format!("{}|  ", prefix)
    };

    // Filter children for display when not verbose
    let visible_children: Vec<&TreeNode> = if verbose {
        node.children.iter().collect()
    } else {
        node.children
            .iter()
            .filter(|c| !matches!(c.status, NodeStatus::OmittedForDuplicate))
            .collect()
    };

    for (i, child) in visible_children.iter().enumerate() {
        let is_last_child = i == visible_children.len() - 1;
        print_tree_node(child, &child_prefix, is_last_child, false, verbose);
    }
}

// --- JSON output types ---

#[derive(Serialize)]
struct JsonTreeModule {
    module: String,
    version: String,
    node_count: usize,
    edge_count: usize,
    conflict_count: usize,
    tree: JsonTreeNode,
}

#[derive(Serialize)]
struct JsonTreeNode {
    group_id: String,
    artifact_id: String,
    version: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_from: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<JsonTreeNode>,
}

fn tree_node_to_json(node: &TreeNode) -> JsonTreeNode {
    let status = match &node.status {
        NodeStatus::Selected => None,
        NodeStatus::OmittedForConflict { winning_version } => {
            Some(format!("omitted_conflict:{}", winning_version))
        }
        NodeStatus::OmittedForDuplicate => Some("omitted_duplicate".to_string()),
    };

    JsonTreeNode {
        group_id: node.artifact.key.group_id.clone(),
        artifact_id: node.artifact.key.artifact_id.clone(),
        version: node.artifact.version.clone(),
        scope: node.artifact.scope.to_string(),
        status,
        managed_from: node.managed_from.clone(),
        children: node.children.iter().map(tree_node_to_json).collect(),
    }
}
