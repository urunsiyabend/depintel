//! Analyze how a dependency version should be changed and produce a human-readable
//! fix strategy (property change, direct edit, add managed entry, etc.).

use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use crate::bump::mutator::discover_module_poms;

/// How the user should apply the version change.
#[derive(Debug, Clone, Serialize)]
pub struct FixStrategy {
    /// One of: "property", "direct", "managed", "add_managed", "add_direct"
    pub method: String,
    /// Human-readable instruction.
    pub instruction: String,
    /// Which pom.xml to edit (relative path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Property name if method = "property".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

/// Analyze the POM structure to determine the best fix strategy for bumping
/// `group:artifact` from `from_version` to `to_version`.
pub fn analyze_fix_strategy(
    pom_dir: &Path,
    group: &str,
    artifact: &str,
    _from_version: &str,
    to_version: &str,
    is_direct: bool,
) -> Result<FixStrategy> {
    let module_poms = discover_module_poms(pom_dir)?;

    for pom_path in &module_poms {
        let content = std::fs::read_to_string(pom_path)?;
        let rel = pom_path
            .strip_prefix(pom_dir)
            .unwrap_or(pom_path)
            .to_string_lossy()
            .to_string();

        // Check for property-based version (e.g., <version>${jackson.version}</version>)
        if let Some(prop) = find_property_version(&content, group, artifact) {
            return Ok(FixStrategy {
                method: "property".to_string(),
                instruction: format!(
                    "Set <{}>{}</{}>",
                    prop, to_version, prop
                ),
                file: Some(rel),
                property: Some(prop),
            });
        }

        // Check for direct <dependency> declaration with literal version
        if has_direct_dependency(&content, group, artifact) {
            return Ok(FixStrategy {
                method: "direct".to_string(),
                instruction: format!(
                    "Update <version>{}</version> in the <dependency> declaration for {}:{}",
                    to_version, group, artifact
                ),
                file: Some(rel),
                property: None,
            });
        }

        // Check for <dependencyManagement> entry
        if has_managed_dependency(&content, group, artifact) {
            return Ok(FixStrategy {
                method: "managed".to_string(),
                instruction: format!(
                    "Update <version>{}</version> in the <dependencyManagement> entry for {}:{}",
                    to_version, group, artifact
                ),
                file: Some(rel),
                property: None,
            });
        }
    }

    // Not found anywhere — it's transitive-only
    if is_direct {
        // Declared somewhere we couldn't parse, fall back to generic
        Ok(FixStrategy {
            method: "direct".to_string(),
            instruction: format!(
                "Update the version of {}:{} to {} in your pom.xml",
                group, artifact, to_version
            ),
            file: None,
            property: None,
        })
    } else {
        // Transitive dependency — recommend adding a managed entry
        Ok(FixStrategy {
            method: "add_managed".to_string(),
            instruction: format!(
                "Add a <dependencyManagement> entry to pin {}:{} to {}",
                group, artifact, to_version
            ),
            file: Some("pom.xml".to_string()),
            property: None,
        })
    }
}

/// Search for a `<dependency>` block matching group:artifact where the version
/// uses a property reference like `${some.property}`. Returns the property name.
fn find_property_version(content: &str, group: &str, artifact: &str) -> Option<String> {
    // Simple text-based search: find the dependency block, then check its version
    let lower = content.to_lowercase();
    let group_tag = format!("<groupid>{}</groupid>", group.to_lowercase());
    let artifact_tag = format!("<artifactid>{}</artifactid>", artifact.to_lowercase());

    let mut search_from = 0;
    while let Some(gpos) = lower[search_from..].find(&group_tag) {
        let abs_gpos = search_from + gpos;
        // Look for the enclosing <dependency> block (within ~500 chars)
        let block_start = if abs_gpos >= 500 { abs_gpos - 500 } else { 0 };
        let block_end = (abs_gpos + 500).min(content.len());
        let block = &lower[block_start..block_end];

        if block.contains(&artifact_tag) {
            // Find <version>${...}</version> in this region
            let region = &content[block_start..block_end];
            if let Some(prop) = extract_property_ref(region) {
                return Some(prop);
            }
        }
        search_from = abs_gpos + group_tag.len();
    }
    None
}

/// Extract a property name from `<version>${prop.name}</version>`.
fn extract_property_ref(region: &str) -> Option<String> {
    let lower = region.to_lowercase();
    let mut pos = 0;
    while let Some(vstart) = lower[pos..].find("<version>") {
        let abs = pos + vstart + "<version>".len();
        if let Some(vend) = lower[abs..].find("</version>") {
            let val = region[abs..abs + vend].trim();
            if val.starts_with("${") && val.ends_with('}') {
                return Some(val[2..val.len() - 1].to_string());
            }
        }
        pos = abs;
    }
    None
}

/// Check if a POM has a direct `<dependency>` (not in `<dependencyManagement>`)
/// for the given group:artifact.
fn has_direct_dependency(content: &str, group: &str, artifact: &str) -> bool {
    // Rough heuristic: find group+artifact outside of <dependencyManagement> blocks
    let lower = content.to_lowercase();
    let group_tag = format!("<groupid>{}</groupid>", group.to_lowercase());
    let artifact_tag = format!("<artifactid>{}</artifactid>", artifact.to_lowercase());

    // Find the dependencyManagement region to exclude
    let mgmt_start = lower.find("<dependencymanagement>");
    let mgmt_end = lower.find("</dependencymanagement>");

    let mut search_from = 0;
    while let Some(gpos) = lower[search_from..].find(&group_tag) {
        let abs_gpos = search_from + gpos;
        // Check if this position is inside dependencyManagement
        let in_mgmt = match (mgmt_start, mgmt_end) {
            (Some(s), Some(e)) => abs_gpos > s && abs_gpos < e,
            _ => false,
        };

        if !in_mgmt {
            // Check if artifact tag is nearby (within 200 chars)
            let block_start = if abs_gpos >= 200 { abs_gpos - 200 } else { 0 };
            let block_end = (abs_gpos + 200).min(lower.len());
            if lower[block_start..block_end].contains(&artifact_tag) {
                return true;
            }
        }
        search_from = abs_gpos + group_tag.len();
    }
    false
}

/// Check if a POM has this artifact in `<dependencyManagement>`.
fn has_managed_dependency(content: &str, group: &str, artifact: &str) -> bool {
    let lower = content.to_lowercase();
    let group_tag = format!("<groupid>{}</groupid>", group.to_lowercase());
    let artifact_tag = format!("<artifactid>{}</artifactid>", artifact.to_lowercase());

    let mgmt_start = match lower.find("<dependencymanagement>") {
        Some(s) => s,
        None => return false,
    };
    let mgmt_end = match lower.find("</dependencymanagement>") {
        Some(e) => e,
        None => return false,
    };

    let mgmt_region = &lower[mgmt_start..mgmt_end];
    mgmt_region.contains(&group_tag) && mgmt_region.contains(&artifact_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_property_version() {
        let pom = r#"
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson.version}</version>
        </dependency>
        "#;
        let prop = find_property_version(pom, "com.fasterxml.jackson.core", "jackson-databind");
        assert_eq!(prop, Some("jackson.version".to_string()));
    }

    #[test]
    fn test_find_property_version_none() {
        let pom = r#"
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>32.1.3-jre</version>
        </dependency>
        "#;
        let prop = find_property_version(pom, "com.google.guava", "guava");
        assert_eq!(prop, None);
    }

    #[test]
    fn test_has_direct_dependency() {
        let pom = r#"
        <project>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>org.other</groupId>
                <artifactId>other</artifactId>
                <version>1.0</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>com.google.guava</groupId>
              <artifactId>guava</artifactId>
              <version>32.0</version>
            </dependency>
          </dependencies>
        </project>
        "#;
        assert!(has_direct_dependency(pom, "com.google.guava", "guava"));
    }

    #[test]
    fn test_has_managed_dependency() {
        let pom = r#"
        <project>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>com.google.guava</groupId>
                <artifactId>guava</artifactId>
                <version>32.0</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>
        "#;
        assert!(has_managed_dependency(pom, "com.google.guava", "guava"));
        assert!(!has_managed_dependency(pom, "org.other", "other"));
    }
}
