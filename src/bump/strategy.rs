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
    // ASCII lowercasing keeps byte offsets valid for slicing `content`.
    let lower = content.to_ascii_lowercase();
    dependency_blocks(&lower)
        .into_iter()
        // Both groupId AND artifactId must be in this specific <dependency> block
        .filter(|&(start, end)| block_declares(&lower[start..end], group, artifact))
        .find_map(|(start, end)| extract_property_ref(&content[start..end]))
}

/// Byte ranges of every `<dependency>...</dependency>` block in lowercased content.
fn dependency_blocks(lower: &str) -> Vec<(usize, usize)> {
    let dep_open = "<dependency>";
    let dep_close = "</dependency>";
    let mut blocks = Vec::new();
    let mut search_from = 0;
    while let Some(dstart) = lower[search_from..].find(dep_open) {
        let abs_dstart = search_from + dstart;
        let block_body_start = abs_dstart + dep_open.len();
        let abs_dend = match lower[block_body_start..].find(dep_close) {
            Some(e) => block_body_start + e,
            None => break,
        };
        blocks.push((abs_dstart, abs_dend));
        search_from = abs_dend + dep_close.len();
    }
    blocks
}

/// Whether a lowercased `<dependency>` block declares group:artifact itself.
/// Coordinates inside `<exclusions>` name other artifacts and are ignored.
fn block_declares(block_lower: &str, group: &str, artifact: &str) -> bool {
    let mut own = block_lower.to_string();
    while let Some(start) = own.find("<exclusions>") {
        match own[start..].find("</exclusions>") {
            Some(end) => own.replace_range(start..start + end + "</exclusions>".len(), ""),
            None => {
                own.truncate(start);
                break;
            }
        }
    }
    let group_tag = format!("<groupid>{}</groupid>", group.to_ascii_lowercase());
    let artifact_tag = format!("<artifactid>{}</artifactid>", artifact.to_ascii_lowercase());
    own.contains(&group_tag) && own.contains(&artifact_tag)
}

/// Extract a property name from `<version>${prop.name}</version>`.
fn extract_property_ref(region: &str) -> Option<String> {
    let lower = region.to_ascii_lowercase();
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
    let lower = content.to_ascii_lowercase();

    // Find the dependencyManagement region to exclude
    let mgmt_start = lower.find("<dependencymanagement>");
    let mgmt_end = lower.find("</dependencymanagement>");

    dependency_blocks(&lower).into_iter().any(|(start, end)| {
        // Skip if inside dependencyManagement
        let in_mgmt = match (mgmt_start, mgmt_end) {
            (Some(s), Some(e)) => start > s && start < e,
            _ => false,
        };
        !in_mgmt && block_declares(&lower[start..end], group, artifact)
    })
}

/// Check if a POM has this artifact in `<dependencyManagement>`.
fn has_managed_dependency(content: &str, group: &str, artifact: &str) -> bool {
    let lower = content.to_ascii_lowercase();

    let mgmt_start = match lower.find("<dependencymanagement>") {
        Some(s) => s,
        None => return false,
    };
    let mgmt_end = match lower.find("</dependencymanagement>") {
        Some(e) => e,
        None => return false,
    };

    // Both coordinates must belong to the same managed entry.
    dependency_blocks(&lower).into_iter().any(|(start, end)| {
        start > mgmt_start
            && start < mgmt_end
            && block_declares(&lower[start..end], group, artifact)
    })
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
    fn test_find_property_version_picks_correct_artifact() {
        // Regression: when multiple deps have property versions, the function
        // must return the property belonging to the REQUESTED artifact, not
        // whichever property appears first in the file.
        let pom = r#"
        <dependencies>
            <dependency>
                <groupId>io.netty</groupId>
                <artifactId>netty-handler</artifactId>
                <version>${netty.version}</version>
            </dependency>
            <dependency>
                <groupId>com.squareup.okhttp3</groupId>
                <artifactId>okhttp</artifactId>
                <version>${okhttp.version}</version>
            </dependency>
        </dependencies>
        "#;
        let prop = find_property_version(pom, "com.squareup.okhttp3", "okhttp");
        assert_eq!(prop, Some("okhttp.version".to_string()));

        let prop = find_property_version(pom, "io.netty", "netty-handler");
        assert_eq!(prop, Some("netty.version".to_string()));
    }

    #[test]
    fn exclusions_do_not_match_the_excluding_dependency() {
        let pom = r#"
        <project>
          <dependencies>
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
              <version>${spring.version}</version>
              <exclusions>
                <exclusion>
                  <groupId>commons-logging</groupId>
                  <artifactId>commons-logging</artifactId>
                </exclusion>
              </exclusions>
            </dependency>
          </dependencies>
        </project>
        "#;
        assert_eq!(
            find_property_version(pom, "commons-logging", "commons-logging"),
            None
        );
        assert!(!has_direct_dependency(
            pom,
            "commons-logging",
            "commons-logging"
        ));
        assert_eq!(
            find_property_version(pom, "org.springframework", "spring-core"),
            Some("spring.version".to_string())
        );
    }

    #[test]
    fn non_ascii_text_does_not_shift_property_offsets() {
        // 'İ' lowercases to two chars with a different UTF-8 length.
        let pom = format!(
            r#"
        <project>
          <name>{}</name>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-databind</artifactId>
              <version>${{jackson.version}}</version>
            </dependency>
          </dependencies>
        </project>
        "#,
            "İ".repeat(200)
        );
        let pom = pom.as_str();
        assert_eq!(
            find_property_version(pom, "com.fasterxml.jackson.core", "jackson-databind"),
            Some("jackson.version".to_string())
        );
    }

    #[test]
    fn managed_coordinates_must_come_from_one_entry() {
        let pom = r#"
        <project>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>com.google.guava</groupId>
                <artifactId>failureaccess</artifactId>
                <version>1.0.2</version>
              </dependency>
              <dependency>
                <groupId>org.other</groupId>
                <artifactId>guava</artifactId>
                <version>1.0</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>
        "#;
        assert!(!has_managed_dependency(pom, "com.google.guava", "guava"));
        assert!(has_managed_dependency(pom, "org.other", "guava"));
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
