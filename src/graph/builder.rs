use std::collections::{HashMap, HashSet};

use petgraph::graph::{DiGraph, NodeIndex};

use crate::collector::verbose_tree::{ModuleTree, NodeStatus, TreeNode};
use crate::model::{ArtifactKey, Scope};

/// A node in the dependency graph.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub key: ArtifactKey,
    pub version: String,
    pub scope: Scope,
}

/// The full dependency graph for one module.
#[derive(Debug)]
pub struct DepGraph {
    pub graph: DiGraph<GraphNode, ()>,
    pub root: NodeIndex,
    /// Map from (groupId:artifactId, version) -> node index.
    /// Multiple versions of the same artifact can exist (requested vs selected).
    node_index: HashMap<(ArtifactKey, String), NodeIndex>,
    /// All version requests observed: artifactKey -> [(version, status, path)]
    pub version_requests: HashMap<ArtifactKey, Vec<VersionRequest>>,
}

/// A record of a version being requested somewhere in the tree.
#[derive(Debug, Clone)]
pub struct VersionRequest {
    pub version: String,
    pub selected: bool,
    /// The dependency path from root to this request.
    pub path: Vec<String>,
    pub managed_from: Option<String>,
    /// True if this request was reconstructed from a canonical subtree
    /// because the actual parent was "omitted for duplicate" in Maven's output.
    pub virtual_path: bool,
}

impl DepGraph {
    /// Find node index for a specific artifact key + version.
    pub fn find_node_versioned(&self, key: &ArtifactKey, version: &str) -> Option<NodeIndex> {
        self.node_index.get(&(key.clone(), version.to_string())).copied()
    }

    /// Get all version requests for an artifact.
    pub fn get_requests(&self, key: &ArtifactKey) -> Option<&Vec<VersionRequest>> {
        self.version_requests.get(key)
    }

    /// Get all artifact keys that have conflicting version requests (2+ distinct versions).
    pub fn conflicted_artifacts(&self) -> Vec<&ArtifactKey> {
        self.version_requests
            .iter()
            .filter(|(_, requests)| {
                let distinct_versions: std::collections::HashSet<_> =
                    requests.iter().map(|r| &r.version).collect();
                distinct_versions.len() >= 2
            })
            .map(|(key, _)| key)
            .collect()
    }

    /// Get the root module's group:artifact:version label.
    pub fn root_label(&self) -> String {
        let root = &self.graph[self.root];
        format!("{}:{}", root.key, root.version)
    }

    /// Fold another module's graph into this one. Used to build a "project-wide"
    /// view of a multi-module Maven project: nodes from `other` that aren't
    /// already present are added (keeping their outgoing edges so features like
    /// empty-subtree detection still work), and `version_requests` are unioned
    /// per artifact key. Duplicate edges are tolerated.
    pub fn extend_with(&mut self, other: DepGraph) {
        // 1. Union version_requests.
        for (key, reqs) in other.version_requests {
            self.version_requests
                .entry(key)
                .or_insert_with(Vec::new)
                .extend(reqs);
        }

        // 2. Map other's NodeIndex -> our NodeIndex, adding missing nodes.
        let mut remap: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        for nidx in other.graph.node_indices() {
            let n = &other.graph[nidx];
            let kv = (n.key.clone(), n.version.clone());
            let target = match self.node_index.get(&kv) {
                Some(existing) => *existing,
                None => {
                    let new_idx = self.graph.add_node(n.clone());
                    self.node_index.insert(kv, new_idx);
                    new_idx
                }
            };
            remap.insert(nidx, target);
        }

        // 3. Copy edges (duplicates are allowed; petgraph handles them fine).
        for edge in other.graph.edge_indices() {
            if let Some((a, b)) = other.graph.edge_endpoints(edge) {
                let (na, nb) = (remap[&a], remap[&b]);
                self.graph.add_edge(na, nb, ());
            }
        }
    }
}

/// Build a single "project-wide" graph from all module trees in a
/// multi-module Maven project. The first tree becomes the primary graph; the
/// rest are folded in via [`DepGraph::extend_with`]. For single-module
/// projects this is equivalent to calling [`build_graph`] on the lone tree.
pub fn build_combined_graph(trees: &[ModuleTree]) -> DepGraph {
    assert!(!trees.is_empty(), "build_combined_graph requires at least one tree");
    let mut combined = build_graph(&trees[0]);
    for tree in &trees[1..] {
        combined.extend_with(build_graph(tree));
    }
    combined
}

/// Build a DepGraph from a parsed ModuleTree.
pub fn build_graph(module_tree: &ModuleTree) -> DepGraph {
    let mut graph = DiGraph::new();
    let mut node_index: HashMap<(ArtifactKey, String), NodeIndex> = HashMap::new();
    let mut version_requests: HashMap<ArtifactKey, Vec<VersionRequest>> = HashMap::new();

    // Pass 1: collect canonical subtrees.
    // Maven's verbose tree elides children of duplicate nodes, so we need to remember
    // what each artifact's children look like when first fully expanded, keyed by (key, version).
    let mut canonical: HashMap<(ArtifactKey, String), Vec<TreeNode>> = HashMap::new();
    collect_canonical(&module_tree.root, &mut canonical);

    // Add root node
    let root_node = &module_tree.root;
    let root_gn = GraphNode {
        key: root_node.artifact.key.clone(),
        version: root_node.artifact.version.clone(),
        scope: root_node.artifact.scope.clone(),
    };
    let root_idx = graph.add_node(root_gn);
    node_index.insert(
        (root_node.artifact.key.clone(), root_node.artifact.version.clone()),
        root_idx,
    );

    // Pass 2: recursively add children, synthesizing virtual requests for duplicates.
    let root_label = format!("{}:{}", root_node.artifact.key, root_node.artifact.version);
    add_children(
        &mut graph,
        &mut node_index,
        &mut version_requests,
        &canonical,
        root_idx,
        &root_node.children,
        vec![root_label],
    );

    DepGraph {
        graph,
        root: root_idx,
        node_index,
        version_requests,
    }
}

/// Walk the parsed tree once and record children for each (key, version) the first time
/// it appears as a fully-expanded Selected node.
fn collect_canonical(
    node: &TreeNode,
    map: &mut HashMap<(ArtifactKey, String), Vec<TreeNode>>,
) {
    let k = (node.artifact.key.clone(), node.artifact.version.clone());
    if matches!(node.status, NodeStatus::Selected)
        && !node.children.is_empty()
        && !map.contains_key(&k)
    {
        map.insert(k, node.children.clone());
    }
    for child in &node.children {
        collect_canonical(child, map);
    }
}

/// For a node marked "omitted for duplicate", walk its canonical subtree and emit
/// virtual VersionRequests so analysis sees every real path.
fn emit_virtual_requests(
    virtual_children: &[TreeNode],
    parent_path: Vec<String>,
    canonical: &HashMap<(ArtifactKey, String), Vec<TreeNode>>,
    version_requests: &mut HashMap<ArtifactKey, Vec<VersionRequest>>,
    visited: &mut HashSet<(ArtifactKey, String)>,
) {
    for vchild in virtual_children {
        // Skip conflict/duplicate leaves at this level — they'd just repeat.
        if !matches!(vchild.status, NodeStatus::Selected) {
            continue;
        }
        let key = vchild.artifact.key.clone();
        let version = vchild.artifact.version.clone();
        let visit_key = (key.clone(), version.clone());
        if visited.contains(&visit_key) {
            continue;
        }

        let label = format!("{}:{}", key, version);
        let mut path = parent_path.clone();
        path.push(label);

        version_requests
            .entry(key.clone())
            .or_default()
            .push(VersionRequest {
                version: version.clone(),
                selected: false,
                path: path.clone(),
                managed_from: vchild.managed_from.clone(),
                virtual_path: true,
            });

        visited.insert(visit_key.clone());
        let next_children: &[TreeNode] = if !vchild.children.is_empty() {
            &vchild.children
        } else if let Some(canon) = canonical.get(&visit_key) {
            canon.as_slice()
        } else {
            &[]
        };
        emit_virtual_requests(next_children, path, canonical, version_requests, visited);
        visited.remove(&visit_key);
    }
}

fn add_children(
    graph: &mut DiGraph<GraphNode, ()>,
    node_index: &mut HashMap<(ArtifactKey, String), NodeIndex>,
    version_requests: &mut HashMap<ArtifactKey, Vec<VersionRequest>>,
    canonical: &HashMap<(ArtifactKey, String), Vec<TreeNode>>,
    parent_idx: NodeIndex,
    children: &[TreeNode],
    parent_path: Vec<String>,
) {
    for child in children {
        let key = child.artifact.key.clone();
        let version = child.artifact.version.clone();
        let label = format!("{}:{}", key, version);

        let selected = matches!(child.status, NodeStatus::Selected);
        let is_duplicate = matches!(child.status, NodeStatus::OmittedForDuplicate);

        // Record version request
        let mut path = parent_path.clone();
        path.push(label.clone());

        version_requests
            .entry(key.clone())
            .or_default()
            .push(VersionRequest {
                version: version.clone(),
                selected,
                path: path.clone(),
                managed_from: child.managed_from.clone(),
                virtual_path: false,
            });

        // If this is a duplicate, expand its canonical subtree as virtual requests
        // so analysis can see every real transitive path Maven elided.
        if is_duplicate {
            let visit_key = (key.clone(), version.clone());
            if let Some(canon_children) = canonical.get(&visit_key) {
                let mut visited: HashSet<(ArtifactKey, String)> = HashSet::new();
                visited.insert(visit_key);
                let canon_children = canon_children.clone();
                emit_virtual_requests(
                    &canon_children,
                    path.clone(),
                    canonical,
                    version_requests,
                    &mut visited,
                );
            }
        }

        // Get or create graph node
        let child_idx = *node_index
            .entry((key.clone(), version.clone()))
            .or_insert_with(|| {
                graph.add_node(GraphNode {
                    key: key.clone(),
                    version: version.clone(),
                    scope: child.artifact.scope.clone(),
                })
            });

        // Edge — the rich semantics live on VersionRequest, the edge itself is just structural.
        graph.add_edge(parent_idx, child_idx, ());

        // Recurse into children (only for selected nodes — omitted nodes have no children in tree)
        if selected && !child.children.is_empty() {
            add_children(
                graph,
                node_index,
                version_requests,
                canonical,
                child_idx,
                &child.children,
                path,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::verbose_tree::parse_verbose_tree;

    #[test]
    fn test_build_simple_graph() {
        let input = r#"com.example:app:jar:1.0.0
+- org.springframework:spring-web:jar:6.1.3:compile
|  +- org.springframework:spring-core:jar:6.1.3:compile
+- org.apache.commons:commons-lang3:jar:3.14.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);

        // Root + 3 dependencies = 4 nodes
        assert_eq!(graph.graph.node_count(), 4);
        // Root->spring-web, Root->commons-lang3, spring-web->spring-core = 3 edges
        assert_eq!(graph.graph.edge_count(), 3);
        assert_eq!(graph.root_label(), "com.example:app:1.0.0");
    }

    #[test]
    fn test_build_graph_with_conflict() {
        let input = r#"com.example:app:jar:1.0.0
+- org.springframework:spring-web:jar:6.1.3:compile
|  +- com.fasterxml.jackson.core:jackson-databind:jar:2.15.3:compile
+- org.apache.kafka:kafka-clients:jar:3.5.1:compile
|  +- (com.fasterxml.jackson.core:jackson-databind:jar:2.14.2:compile - omitted for conflict with 2.15.3)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);

        // jackson-databind has 2 version requests
        let jackson_key = ArtifactKey::new("com.fasterxml.jackson.core", "jackson-databind");
        let requests = graph.get_requests(&jackson_key).unwrap();
        assert_eq!(requests.len(), 2);

        // One selected, one not
        assert!(requests.iter().any(|r| r.version == "2.15.3" && r.selected));
        assert!(requests.iter().any(|r| r.version == "2.14.2" && !r.selected));

        // It's a conflicted artifact
        let conflicts = graph.conflicted_artifacts();
        assert!(conflicts.contains(&&jackson_key));
    }

    #[test]
    fn test_build_graph_with_duplicates() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:bar:jar:1.0:compile
|  +- org.baz:qux:jar:2.0:compile
+- org.other:lib:jar:1.0:compile
|  +- (org.baz:qux:jar:2.0:compile - omitted for duplicate)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);

        // qux appears twice but same version — not a conflict
        let qux_key = ArtifactKey::new("org.baz", "qux");
        let requests = graph.get_requests(&qux_key).unwrap();
        assert_eq!(requests.len(), 2);

        // Not in conflicted list (same version)
        let conflicts = graph.conflicted_artifacts();
        assert!(!conflicts.contains(&&qux_key));
    }

    #[test]
    fn test_build_graph_managed_from() {
        let input = r#"com.example:app:jar:1.0.0
+- org.springframework:spring-core:jar:6.1.3:compile (managed from 6.0.12)"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);

        let spring_key = ArtifactKey::new("org.springframework", "spring-core");
        let requests = graph.get_requests(&spring_key).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].managed_from.as_deref(), Some("6.0.12"));
    }

    #[test]
    fn test_version_request_paths() {
        let input = r#"com.example:app:jar:1.0.0
+- org.foo:bar:jar:1.0:compile
|  +- org.baz:qux:jar:2.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        let graph = build_graph(&trees[0]);

        let qux_key = ArtifactKey::new("org.baz", "qux");
        let requests = graph.get_requests(&qux_key).unwrap();
        assert_eq!(requests[0].path, vec![
            "com.example:app:1.0.0",
            "org.foo:bar:1.0",
            "org.baz:qux:2.0",
        ]);
    }
}
