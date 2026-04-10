use std::collections::HashSet;

use crate::collector::effective_pom::ManagedDependency;
use crate::graph::builder::{DepGraph, VersionRequest};
use crate::model::ArtifactKey;

/// Result of a "why" query for a single module.
#[derive(Debug)]
pub struct WhyResult {
    pub module_label: String,
    pub selected_version: Option<String>,
    pub selected_scope: Option<String>,
    pub resolution: ResolutionInfo,
    pub requests: Vec<VersionRequest>,
    pub warnings: Vec<WhyWarning>,
}

/// How the selected version was determined.
#[derive(Debug)]
pub struct ResolutionInfo {
    pub reason: String,
    pub detail: String,
    /// The source BOM or POM that caused this resolution (if applicable).
    pub source: Option<ResolutionSource>,
}

#[derive(Debug, Clone)]
pub struct ResolutionSource {
    pub source_type: String, // "bom", "parent", "dependency_management", "path_depth"
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    /// For nearest_wins
    pub selected_depth: Option<usize>,
    pub overridden_depth: Option<usize>,
}

/// A warning about a version gap or mismatch.
#[derive(Debug)]
pub struct WhyWarning {
    pub warning_type: String,
    pub consumer: String,
    pub compiled_against: String,
    pub resolved_to: String,
    pub description: String,
}

/// Configuration for why query.
pub struct WhyOptions {
    pub max_depth: Option<usize>,
    pub all_versions: bool,
    pub managed_deps: Vec<ManagedDependency>,
    /// BOMs imported in dependencyManagement (scope=import, type=pom).
    pub bom_imports: Vec<ManagedDependency>,
}

impl Default for WhyOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            all_versions: false,
            managed_deps: Vec::new(),
            bom_imports: Vec::new(),
        }
    }
}

/// Classify a version request as selected, overridden (different version lost), or duplicate (same version, already included).
fn classify_status(req: &VersionRequest, selected_version: Option<&str>) -> &'static str {
    if req.selected {
        "selected"
    } else if let Some(sel_ver) = selected_version {
        if req.version == sel_ver {
            "duplicate"
        } else {
            "overridden"
        }
    } else {
        "overridden"
    }
}

/// Run a "why" query against a single module's graph.
pub fn why_artifact(graph: &DepGraph, key: &ArtifactKey, options: &WhyOptions) -> Option<WhyResult> {
    let requests = graph.get_requests(key)?;
    if requests.is_empty() {
        return None;
    }

    // Apply depth filter
    let filtered_requests: Vec<VersionRequest> = if let Some(max_depth) = options.max_depth {
        requests
            .iter()
            .filter(|r| r.path.len() <= max_depth + 1) // +1 for root
            .cloned()
            .collect()
    } else {
        requests.clone()
    };

    if filtered_requests.is_empty() {
        return None;
    }

    // Find the selected version
    let selected = filtered_requests.iter().find(|r| r.selected);
    let selected_version = selected.map(|r| r.version.clone());
    let selected_scope = selected.map(|r| {
        if let Some(idx) = graph.find_node_versioned(key, &r.version) {
            graph.graph[idx].scope.to_string()
        } else {
            "compile".to_string()
        }
    });

    // Determine resolution reason (using effective-pom managed deps for BOM detection)
    let resolution = determine_resolution(
        &filtered_requests,
        selected_version.as_deref(),
        key,
        &options.managed_deps,
        &options.bom_imports,
    );

    // Generate warnings
    let warnings = generate_warnings(&filtered_requests, selected_version.as_deref(), graph, key);

    // Show every path we know about (real + virtual). Each path represents a distinct
    // transitive route Maven either emitted directly or hid under "omitted for duplicate".
    // --all-versions was historically about hiding same-version requests, but those are
    // exactly what a user running `why` wants to see. It remains as a no-op for now.
    let _ = options.all_versions;
    let display_requests = filtered_requests;

    Some(WhyResult {
        module_label: graph.root_label(),
        selected_version,
        selected_scope,
        resolution,
        requests: display_requests,
        warnings,
    })
}

fn determine_resolution(
    requests: &[VersionRequest],
    selected_version: Option<&str>,
    key: &ArtifactKey,
    managed_deps: &[ManagedDependency],
    bom_imports: &[ManagedDependency],
) -> ResolutionInfo {
    // Check if any request has managed_from — that means dependencyManagement was involved
    let managed_request = requests.iter().find(|r| r.managed_from.is_some());

    if let Some(managed_req) = managed_request {
        // Prefer a managed_from entry that shows a real version change (from != to)
        let best_managed = requests
            .iter()
            .filter(|r| r.managed_from.is_some())
            .find(|r| r.managed_from.as_deref() != Some(&r.version))
            .or(Some(managed_req));
        let from_version = best_managed
            .and_then(|r| r.managed_from.as_deref())
            .unwrap_or("unknown");

        // Cross-reference with effective-pom to find the BOM/parent source
        let source = find_management_source(key, managed_deps, bom_imports);

        let selected_ver = selected_version.unwrap_or(&managed_req.version);
        let version_change = if from_version != selected_ver {
            format!("overrides {} → {}", from_version, selected_ver)
        } else {
            format!("pins version {}", selected_ver)
        };

        let (reason, detail) = if let Some(ref src) = source {
            match src.source_type.as_str() {
                "bom" => (
                    "bom_pin".to_string(),
                    format!(
                        "BOM {} ({}) {}",
                        src.artifact_id.as_deref().unwrap_or("unknown"),
                        src.version.as_deref().unwrap_or("?"),
                        version_change,
                    ),
                ),
                _ => (
                    "dependency_management_pin".to_string(),
                    format!("dependencyManagement {}", version_change),
                ),
            }
        } else {
            (
                "dependency_management_pin".to_string(),
                format!("dependencyManagement {}", version_change),
            )
        };

        return ResolutionInfo {
            reason,
            detail,
            source,
        };
    }

    let distinct_versions: HashSet<_> = requests.iter().map(|r| r.version.as_str()).collect();

    if distinct_versions.len() <= 1 {
        // Only one version requested
        let selected_req = requests.iter().find(|r| r.selected);
        if let Some(req) = selected_req {
            if req.path.len() <= 2 {
                return ResolutionInfo {
                    reason: "direct_declaration".to_string(),
                    detail: "Declared directly in <dependencies>".to_string(),
                    source: None,
                };
            }
        }
        return ResolutionInfo {
            reason: "only_version".to_string(),
            detail: "Only one version requested — no conflict to resolve".to_string(),
            source: None,
        };
    }

    // Multiple distinct versions — figure out why selected version won
    if let Some(sel_ver) = selected_version {
        let selected_req = requests.iter().find(|r| r.selected && r.version == sel_ver);
        let overridden: Vec<_> = requests
            .iter()
            .filter(|r| !r.selected && r.version != sel_ver)
            .collect();

        if let Some(sel) = selected_req {
            let sel_depth = sel.path.len();
            let max_override_depth = overridden.iter().map(|r| r.path.len()).max().unwrap_or(0);
            let min_override_depth = overridden.iter().map(|r| r.path.len()).min().unwrap_or(0);

            if max_override_depth > sel_depth {
                return ResolutionInfo {
                    reason: "nearest_wins".to_string(),
                    detail: format!(
                        "Selected at depth {} wins over alternatives at depth {}",
                        sel_depth - 1,
                        max_override_depth - 1
                    ),
                    source: Some(ResolutionSource {
                        source_type: "path_depth".to_string(),
                        group_id: None,
                        artifact_id: None,
                        version: None,
                        selected_depth: Some(sel_depth - 1),
                        overridden_depth: Some(max_override_depth - 1),
                    }),
                };
            }

            if min_override_depth == sel_depth {
                return ResolutionInfo {
                    reason: "first_declaration_wins".to_string(),
                    detail: "Same depth — first declaration in POM order wins".to_string(),
                    source: None,
                };
            }
        }
    }

    ResolutionInfo {
        reason: "unknown".to_string(),
        detail: "Could not determine resolution reason".to_string(),
        source: None,
    }
}

/// Try to find the BOM or parent POM that manages this artifact's version.
fn find_management_source(
    key: &ArtifactKey,
    managed_deps: &[ManagedDependency],
    bom_imports: &[ManagedDependency],
) -> Option<ResolutionSource> {
    // Look for this artifact in the managed dependencies
    let managed = managed_deps.iter().find(|md| md.key == *key)?;

    // Check if any BOMs are imported — if so, this version likely comes from a BOM.
    // The effective-pom flattens BOM contents into dependencyManagement, so we can't
    // always tell which BOM contributed which dep. But if BOMs exist and the artifact
    // matches a groupId pattern of a known BOM, we can infer it.
    //
    // Heuristic: if the artifact's groupId starts with the same prefix as a BOM's groupId,
    // it likely came from that BOM.
    if let Some(bom) = bom_imports.iter().find(|b| {
        // Check if the artifact group starts with the BOM's group prefix
        // e.g., org.springframework.boot BOM manages org.springframework.* deps
        let bom_prefix = b.key.group_id.split('.').take(2).collect::<Vec<_>>().join(".");
        key.group_id.starts_with(&bom_prefix)
    }) {
        return Some(ResolutionSource {
            source_type: "bom".to_string(),
            group_id: Some(bom.key.group_id.clone()),
            artifact_id: Some(bom.key.artifact_id.clone()),
            version: Some(bom.version.clone()),
            selected_depth: None,
            overridden_depth: None,
        });
    }

    Some(ResolutionSource {
        source_type: "dependency_management".to_string(),
        group_id: Some(key.group_id.clone()),
        artifact_id: Some(key.artifact_id.clone()),
        version: Some(managed.version.clone()),
        selected_depth: None,
        overridden_depth: None,
    })
}

fn generate_warnings(
    requests: &[VersionRequest],
    selected_version: Option<&str>,
    graph: &DepGraph,
    key: &ArtifactKey,
) -> Vec<WhyWarning> {
    let mut warnings = Vec::new();
    let selected_version = match selected_version {
        Some(v) => v,
        None => return warnings,
    };

    let sel_parsed = parse_semver(selected_version);

    // Track scopes for scope_mismatch detection
    let mut scopes: HashSet<String> = HashSet::new();

    // Count paths with the same version as selected
    let same_version_paths = requests
        .iter()
        .filter(|r| r.version == selected_version)
        .count();

    for req in requests {
        // Collect scopes
        if let Some(idx) = graph.find_node_versioned(key, &req.version) {
            scopes.insert(graph.graph[idx].scope.to_string());
        }

        // Skip selected and duplicates (same version) for version warnings
        if req.selected || req.version == selected_version {
            continue;
        }

        let req_parsed = parse_semver(&req.version);

        let consumer = if req.path.len() >= 2 {
            req.path[req.path.len() - 2].clone()
        } else {
            continue;
        };

        if sel_parsed.0 != req_parsed.0 {
            warnings.push(WhyWarning {
                warning_type: "major_version_mismatch".to_string(),
                consumer,
                compiled_against: format!("{}.x", req_parsed.0),
                resolved_to: format!("{}.x", sel_parsed.0),
                description: format!(
                    "MAJOR version mismatch: expects {}.x, resolved to {}.x",
                    req_parsed.0, sel_parsed.0
                ),
            });
        } else {
            let gap = (sel_parsed.1 as i32 - req_parsed.1 as i32).unsigned_abs();
            if gap >= 1 {
                warnings.push(WhyWarning {
                    warning_type: "version_gap".to_string(),
                    consumer,
                    compiled_against: format!("{}.{}.x", req_parsed.0, req_parsed.1),
                    resolved_to: selected_version.to_string(),
                    description: format!("{} minor version gap", gap),
                });
            }
        }
    }

    // Scope mismatch warning
    if scopes.len() >= 2 {
        let scope_list: Vec<_> = scopes.into_iter().collect();
        warnings.push(WhyWarning {
            warning_type: "scope_mismatch".to_string(),
            consumer: key.to_string(),
            compiled_against: String::new(),
            resolved_to: String::new(),
            description: format!("Artifact appears in multiple scopes: {}", scope_list.join(", ")),
        });
    }

    // Multiple paths same version (info-level, 3+ paths)
    if same_version_paths >= 3 {
        warnings.push(WhyWarning {
            warning_type: "multiple_paths_same_version".to_string(),
            consumer: key.to_string(),
            compiled_against: String::new(),
            resolved_to: selected_version.to_string(),
            description: format!(
                "Same version pulled from {} independent paths",
                same_version_paths
            ),
        });
    }

    warnings
}

/// Parse a version string into (major, minor, patch). Best effort.
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

/// Classify a request for display purposes.
pub fn request_status_label(req: &VersionRequest, selected_version: Option<&str>) -> &'static str {
    classify_status(req, selected_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::verbose_tree::parse_verbose_tree;
    use crate::graph::builder::build_graph;

    fn default_opts() -> WhyOptions {
        WhyOptions::default()
    }

    #[test]
    fn test_why_direct_dependency() {
        let input = r#"com.example:app:jar:1.0.0
+- org.apache.commons:commons-lang3:jar:3.14.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.apache.commons", "commons-lang3");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();
        assert_eq!(result.selected_version.as_deref(), Some("3.14.0"));
        assert_eq!(result.resolution.reason, "direct_declaration");
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_why_transitive_no_conflict() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:bar:jar:1.0:compile
|  +- org.baz:qux:jar:2.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.baz", "qux");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();
        assert_eq!(result.selected_version.as_deref(), Some("2.0"));
        assert_eq!(result.resolution.reason, "only_version");
    }

    #[test]
    fn test_why_conflict_nearest_wins() {
        let input = r#"com.example:app:jar:1.0.0
+- org.springframework:spring-web:jar:6.1.3:compile
|  +- com.fasterxml.jackson.core:jackson-databind:jar:2.15.3:compile
+- org.apache.kafka:kafka-clients:jar:3.5.1:compile
|  +- org.foo:bar:jar:1.0:compile
|  |  +- (com.fasterxml.jackson.core:jackson-databind:jar:2.14.2:compile - omitted for conflict with 2.15.3)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("com.fasterxml.jackson.core", "jackson-databind");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();
        assert_eq!(result.selected_version.as_deref(), Some("2.15.3"));
        assert_eq!(result.resolution.reason, "nearest_wins");
        assert!(result.resolution.source.is_some());
        let src = result.resolution.source.as_ref().unwrap();
        assert_eq!(src.source_type, "path_depth");
        assert_eq!(result.requests.len(), 2);
        assert!(result.warnings.iter().any(|w| w.warning_type == "version_gap"));
    }

    #[test]
    fn test_why_managed_from() {
        let input = r#"com.example:app:jar:1.0.0
+- org.springframework:spring-core:jar:6.1.3:compile (managed from 6.0.12)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.springframework", "spring-core");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();
        assert_eq!(result.resolution.reason, "dependency_management_pin");
    }

    #[test]
    fn test_why_managed_with_effective_pom_cross_ref() {
        let input = r#"com.example:app:jar:1.0.0
+- org.springframework:spring-core:jar:6.1.3:compile (managed from 6.0.12)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.springframework", "spring-core");

        let opts = WhyOptions {
            managed_deps: vec![ManagedDependency {
                key: ArtifactKey::new("org.springframework", "spring-core"),
                version: "6.1.3".to_string(),
                scope: None,
                packaging: None,
            }],
            ..Default::default()
        };

        let result = why_artifact(&graph, &key, &opts).unwrap();
        assert_eq!(result.resolution.reason, "dependency_management_pin");
        assert!(result.resolution.source.is_some());
    }

    #[test]
    fn test_why_not_found() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:bar:jar:1.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("com.nonexistent", "nope");

        assert!(why_artifact(&graph, &key, &default_opts()).is_none());
    }

    #[test]
    fn test_why_major_version_mismatch_warning() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:bar:jar:1.0:compile
|  +- org.slf4j:slf4j-api:jar:2.0.9:compile
+- org.vendor:legacy:jar:4.0:compile
|  +- (org.slf4j:slf4j-api:jar:1.7.36:compile - omitted for conflict with 2.0.9)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.slf4j", "slf4j-api");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.warning_type == "major_version_mismatch"));
    }

    #[test]
    fn test_why_duplicate_not_shown_as_override() {
        let input = r#"com.example:app:jar:1.0.0
+- org.ow2.asm:asm:jar:9.6:compile
+- org.ow2.asm:asm-util:jar:9.6:compile
|  +- (org.ow2.asm:asm:jar:9.6:compile - omitted for duplicate)
|  +- org.ow2.asm:asm-tree:jar:9.6:compile
|  |  +- (org.ow2.asm:asm:jar:9.6:compile - omitted for duplicate)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.ow2.asm", "asm");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();

        // All are version 9.6 — no overridden, only selected + duplicates
        for req in &result.requests {
            let status = request_status_label(req, result.selected_version.as_deref());
            assert_ne!(status, "overridden", "Same version should not be 'overridden'");
        }
        // Resolution should be direct_declaration, not "overrides N"
        assert_eq!(result.resolution.reason, "direct_declaration");

        // No version gap warnings for same-version duplicates
        assert!(result.warnings.iter().all(|w| w.warning_type != "version_gap"));
    }

    #[test]
    fn test_why_depth_filter() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:bar:jar:1.0:compile
|  +- org.baz:qux:jar:2.0:compile
|  |  +- org.deep:lib:jar:3.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.deep", "lib");

        // Without depth limit: found
        let result = why_artifact(&graph, &key, &default_opts());
        assert!(result.is_some());

        // With depth 2: not found (lib is at depth 3)
        let opts = WhyOptions {
            max_depth: Some(2),
            ..Default::default()
        };
        let result = why_artifact(&graph, &key, &opts);
        assert!(result.is_none());

        // With depth 3: found
        let opts = WhyOptions {
            max_depth: Some(3),
            ..Default::default()
        };
        let result = why_artifact(&graph, &key, &opts);
        assert!(result.is_some());
    }

    #[test]
    fn test_why_multiple_paths_same_version_warning() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:a:jar:1.0:compile
|  +- org.common:lib:jar:1.0:compile
+- org.foo:b:jar:1.0:compile
|  +- (org.common:lib:jar:1.0:compile - omitted for duplicate)
+- org.foo:c:jar:1.0:compile
|  +- (org.common:lib:jar:1.0:compile - omitted for duplicate)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);
        let key = ArtifactKey::new("org.common", "lib");

        let result = why_artifact(&graph, &key, &default_opts()).unwrap();
        assert!(result
            .warnings
            .iter()
            .any(|w| w.warning_type == "multiple_paths_same_version"));
    }

    #[test]
    fn test_parse_semver() {
        assert_eq!(parse_semver("2.15.3"), (2, 15, 3));
        assert_eq!(parse_semver("1.7.36"), (1, 7, 36));
        assert_eq!(parse_semver("3.2.2-beta"), (3, 2, 2));
        assert_eq!(parse_semver("6.1"), (6, 1, 0));
        assert_eq!(parse_semver("2"), (2, 0, 0));
    }
}
