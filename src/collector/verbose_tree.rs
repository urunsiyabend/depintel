use crate::model::{Artifact, ArtifactKey, Scope};
use anyhow::Result;

/// A node in the parsed verbose dependency tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub artifact: Artifact,
    pub status: NodeStatus,
    pub managed_from: Option<String>,
    pub children: Vec<TreeNode>,
}

/// Whether this node represents a selected or omitted dependency.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeStatus {
    /// Dependency is included in the build.
    Selected,
    /// Omitted due to conflict with the given version.
    OmittedForConflict { winning_version: String },
    /// Omitted because same version already included.
    OmittedForDuplicate,
}

/// A parsed module tree from verbose dependency:tree output.
#[derive(Debug, Clone)]
pub struct ModuleTree {
    pub root: TreeNode,
}

/// Parse the output of `mvn dependency:tree -Dverbose`.
///
/// The output may contain multiple module trees in a multi-module project.
pub fn parse_verbose_tree(input: &str) -> Result<Vec<ModuleTree>> {
    let mut trees = Vec::new();
    let mut current_lines: Vec<&str> = Vec::new();

    for line in input.lines() {
        let content = strip_info_prefix(line);

        if content.is_empty() {
            continue;
        }

        // A root node has no tree characters (no +-, |, \-)
        // and is a valid artifact coordinate
        let is_root = !content.starts_with('|')
            && !content.starts_with('+')
            && !content.starts_with('\\')
            && !content.starts_with(' ')
            && content.contains(':')
            && !content.starts_with('(');

        if is_root && !current_lines.is_empty() {
            if let Some(tree) = parse_single_tree(&current_lines) {
                trees.push(tree);
            }
            current_lines.clear();
        }

        if content.contains(':') {
            current_lines.push(content);
        }
    }

    // Don't forget the last tree
    if !current_lines.is_empty() {
        if let Some(tree) = parse_single_tree(&current_lines) {
            trees.push(tree);
        }
    }

    Ok(trees)
}

fn strip_info_prefix(line: &str) -> &str {
    let trimmed = line.trim_end();
    if let Some(rest) = trimmed.strip_prefix("[INFO] ") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("[INFO]") {
        rest.trim_start()
    } else {
        trimmed
    }
}

fn parse_single_tree(lines: &[&str]) -> Option<ModuleTree> {
    if lines.is_empty() {
        return None;
    }

    let root_node = parse_artifact_line(lines[0], 0)?;
    let mut root = root_node;

    // Parse child nodes using depth tracking via tree characters
    root.children = build_children_from_lines(&lines[1..], 1);

    Some(ModuleTree { root })
}

fn build_children_from_lines(lines: &[&str], target_depth: usize) -> Vec<TreeNode> {
    let mut children = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let depth = compute_depth(lines[i]);

        if depth < target_depth {
            break;
        }

        if depth == target_depth {
            if let Some(mut node) = parse_artifact_line(lines[i], depth) {
                // Collect child lines
                let child_lines_start = i + 1;
                let mut child_lines_end = child_lines_start;
                while child_lines_end < lines.len() {
                    let child_depth = compute_depth(lines[child_lines_end]);
                    if child_depth <= target_depth {
                        break;
                    }
                    child_lines_end += 1;
                }

                if child_lines_start < child_lines_end {
                    node.children =
                        build_children_from_lines(&lines[child_lines_start..child_lines_end], target_depth + 1);
                }

                children.push(node);
                i = child_lines_end;
                continue;
            }
        }

        i += 1;
    }

    children
}

/// Compute the depth of a tree line based on tree-drawing characters.
/// Each level of depth is represented by 3 characters: "+- ", "|  ", "\- "
fn compute_depth(line: &str) -> usize {
    let mut depth = 0;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '|' | '+' | '\\' => {
                depth += 1;
                // Skip the tree drawing characters for this level
                i += 3; // typically "+- " or "|  " or "\- "
            }
            ' ' => {
                i += 1;
            }
            _ => break,
        }
    }

    depth
}

/// Parse a single artifact line from the verbose tree.
fn parse_artifact_line(line: &str, _depth: usize) -> Option<TreeNode> {
    // Strip tree-drawing characters
    let artifact_str = strip_tree_chars(line);

    if artifact_str.is_empty() {
        return None;
    }

    // Check for parenthesized (omitted) entries
    let (artifact_part, status, managed_from) = parse_status_and_managed(artifact_str);

    // Parse the artifact coordinates: group:artifact:type:version:scope
    parse_coordinates(artifact_part).map(|artifact| TreeNode {
        artifact,
        status,
        managed_from,
        children: Vec::new(),
    })
}

fn strip_tree_chars(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'|' | b'+' | b'\\' | b'-' | b' ' => i += 1,
            _ => break,
        }
    }

    &line[i..]
}

fn parse_status_and_managed(s: &str) -> (&str, NodeStatus, Option<String>) {
    let mut artifact_part = s;
    let mut status = NodeStatus::Selected;
    let mut managed_from = None;

    // Maven verbose tree formats:
    //   artifact:coords:scope (version managed from X.Y.Z)
    //   artifact:coords:scope (version managed from X.Y.Z; scope not updated to compile)
    //   artifact:coords:scope (managed from X.Y.Z)
    //   (artifact:coords:scope - version managed from X.Y.Z; omitted for duplicate)
    //   (artifact:coords:scope - omitted for conflict with X.Y.Z)
    //   (artifact:coords:scope - omitted for duplicate)

    // Extract "managed from" version from any parenthesized suffix
    // Look for both "managed from " and "version managed from "
    for pattern in &["(version managed from ", "(managed from "] {
        if let Some(idx) = s.rfind(pattern) {
            let after_pattern = &s[idx + pattern.len()..];
            // Version ends at ';' or ')'
            let version_end = after_pattern
                .find(|c| c == ';' || c == ')')
                .unwrap_or(after_pattern.len());
            managed_from = Some(after_pattern[..version_end].trim().to_string());
            artifact_part = s[..idx].trim();
            break;
        }
    }

    // Check for parenthesized omitted entry: starts with '('
    if artifact_part.starts_with('(') {
        let inner = if artifact_part.ends_with(')') {
            &artifact_part[1..artifact_part.len() - 1]
        } else {
            &artifact_part[1..]
        };

        // Look for " - omitted for conflict with X.Y.Z"
        if let Some(idx) = inner.find(" - omitted for conflict with ") {
            let winning = &inner[idx + " - omitted for conflict with ".len()..];
            let winning = winning.trim_end_matches(')');
            status = NodeStatus::OmittedForConflict {
                winning_version: winning.to_string(),
            };
            artifact_part = &inner[..idx];
        }
        // Look for " - version managed from X; omitted for duplicate"
        else if let Some(idx) = inner.find("; omitted for duplicate") {
            status = NodeStatus::OmittedForDuplicate;
            // artifact part might have " - version managed from X" before the semicolon
            let before_semi = &inner[..idx];
            if let Some(dash_idx) = before_semi.find(" - version managed from ") {
                let ver = &before_semi[dash_idx + " - version managed from ".len()..];
                managed_from = Some(ver.trim().to_string());
                artifact_part = &before_semi[..dash_idx];
            } else if let Some(dash_idx) = before_semi.find(" - ") {
                artifact_part = &before_semi[..dash_idx];
            } else {
                artifact_part = before_semi;
            }
        }
        // Look for " - omitted for duplicate"
        else if let Some(idx) = inner.find(" - omitted for duplicate") {
            status = NodeStatus::OmittedForDuplicate;
            artifact_part = &inner[..idx];
        }
        // Parenthesized but unknown reason
        else {
            artifact_part = inner;
        }
    }

    (artifact_part, status, managed_from)
}

fn parse_coordinates(s: &str) -> Option<Artifact> {
    let s = s.trim();
    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // group:artifact:type:version:scope
        5 => Some(Artifact {
            key: ArtifactKey::new(parts[0], parts[1]),
            packaging: parts[2].to_string(),
            version: parts[3].to_string(),
            scope: Scope::parse(parts[4]),
            optional: false,
            classifier: None,
        }),
        // group:artifact:type:classifier:version:scope
        6 => Some(Artifact {
            key: ArtifactKey::new(parts[0], parts[1]),
            packaging: parts[2].to_string(),
            classifier: Some(parts[3].to_string()),
            version: parts[4].to_string(),
            scope: Scope::parse(parts[5]),
            optional: false,
        }),
        // root: group:artifact:type:version (no scope)
        4 => Some(Artifact {
            key: ArtifactKey::new(parts[0], parts[1]),
            packaging: parts[2].to_string(),
            version: parts[3].to_string(),
            scope: Scope::Compile,
            optional: false,
            classifier: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_tree() {
        let input = r#"[INFO] com.example:app:jar:1.0.0
[INFO] +- org.springframework.boot:spring-boot-starter-web:jar:3.2.2:compile
[INFO] |  +- org.springframework:spring-web:jar:6.1.3:compile
[INFO] +- org.apache.commons:commons-lang3:jar:3.14.0:compile"#;

        let trees = parse_verbose_tree(input).unwrap();
        assert_eq!(trees.len(), 1);

        let root = &trees[0].root;
        assert_eq!(root.artifact.key.artifact_id, "app");
        assert_eq!(root.children.len(), 2);
        assert_eq!(
            root.children[0].artifact.key.artifact_id,
            "spring-boot-starter-web"
        );
        assert_eq!(root.children[0].children.len(), 1);
        assert_eq!(
            root.children[0].children[0].artifact.key.artifact_id,
            "spring-web"
        );
    }

    #[test]
    fn test_parse_conflict_line() {
        let input =
            "(com.fasterxml.jackson.core:jackson-databind:jar:2.14.2:compile - omitted for conflict with 2.15.3)";
        let (artifact_part, status, _) = parse_status_and_managed(input);

        assert!(matches!(
            status,
            NodeStatus::OmittedForConflict {
                winning_version
            } if winning_version == "2.15.3"
        ));
        assert_eq!(
            artifact_part,
            "com.fasterxml.jackson.core:jackson-databind:jar:2.14.2:compile"
        );
    }

    #[test]
    fn test_parse_managed_from() {
        let input =
            "org.springframework:spring-core:jar:6.1.3:compile (managed from 6.0.12)";
        let (artifact_part, status, managed) = parse_status_and_managed(input);

        assert_eq!(status, NodeStatus::Selected);
        assert_eq!(managed, Some("6.0.12".to_string()));
        assert_eq!(
            artifact_part,
            "org.springframework:spring-core:jar:6.1.3:compile"
        );
    }

    #[test]
    fn test_parse_version_managed_from() {
        // Real Maven format: "version managed from"
        let input =
            "org.springframework.boot:spring-boot-starter:jar:3.3.2:compile (version managed from 3.3.2)";
        let (artifact_part, status, managed) = parse_status_and_managed(input);

        assert_eq!(status, NodeStatus::Selected);
        assert_eq!(managed, Some("3.3.2".to_string()));
        assert_eq!(
            artifact_part,
            "org.springframework.boot:spring-boot-starter:jar:3.3.2:compile"
        );
    }

    #[test]
    fn test_parse_version_managed_with_scope_suffix() {
        // "version managed from X; scope not updated to compile"
        let input =
            "org.springframework.boot:spring-boot:jar:3.3.2:compile (version managed from 3.3.2; scope not updated to compile)";
        let (artifact_part, status, managed) = parse_status_and_managed(input);

        assert_eq!(status, NodeStatus::Selected);
        assert_eq!(managed, Some("3.3.2".to_string()));
        assert_eq!(
            artifact_part,
            "org.springframework.boot:spring-boot:jar:3.3.2:compile"
        );
    }

    #[test]
    fn test_parse_version_managed_and_omitted_duplicate() {
        // "(artifact - version managed from X; omitted for duplicate)"
        let input =
            "(org.springframework:spring-core:jar:6.1.11:compile - version managed from 6.1.11; omitted for duplicate)";
        let (artifact_part, status, managed) = parse_status_and_managed(input);

        assert_eq!(status, NodeStatus::OmittedForDuplicate);
        assert_eq!(managed, Some("6.1.11".to_string()));
        assert_eq!(
            artifact_part,
            "org.springframework:spring-core:jar:6.1.11:compile"
        );
    }

    #[test]
    fn test_compute_depth() {
        assert_eq!(compute_depth("com.example:app:jar:1.0"), 0);
        assert_eq!(compute_depth("+- org.foo:bar:jar:1.0:compile"), 1);
        assert_eq!(compute_depth("|  +- org.foo:baz:jar:1.0:compile"), 2);
        assert_eq!(compute_depth("|  |  +- org.foo:qux:jar:1.0:compile"), 3);
    }

    #[test]
    fn test_parse_tree_with_conflicts() {
        let input = r#"[INFO] com.example:app:jar:1.0.0
[INFO] +- org.springframework.boot:spring-boot-starter-web:jar:3.2.2:compile
[INFO] |  +- com.fasterxml.jackson.core:jackson-databind:jar:2.15.3:compile
[INFO] +- org.apache.kafka:kafka-clients:jar:3.5.1:compile
[INFO] |  +- (com.fasterxml.jackson.core:jackson-databind:jar:2.14.2:compile - omitted for conflict with 2.15.3)"#;

        let trees = parse_verbose_tree(input).unwrap();
        assert_eq!(trees.len(), 1);

        let root = &trees[0].root;
        assert_eq!(root.children.len(), 2);

        // kafka-clients should have a conflicted child
        let kafka = &root.children[1];
        assert_eq!(kafka.children.len(), 1);
        assert!(matches!(
            kafka.children[0].status,
            NodeStatus::OmittedForConflict { .. }
        ));
    }
}
