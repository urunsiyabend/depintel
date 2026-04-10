use crate::model::{Artifact, ArtifactKey, Scope};
use anyhow::Result;

/// A parsed entry from `mvn dependency:list` output.
#[derive(Debug, Clone)]
pub struct DepListEntry {
    pub artifact: Artifact,
}

/// Parse the output of `mvn dependency:list`.
///
/// Format (from -DoutputFile):
/// ```text
/// The following files have been resolved:
///    group:artifact:type:version:scope
///    group:artifact:type:classifier:version:scope
/// ```
///
/// Format (from stdout with [INFO] prefixes):
/// ```text
/// [INFO]    group:artifact:type:version:scope
/// ```
pub fn parse_dep_list(input: &str) -> Result<Vec<DepListEntry>> {
    let mut entries = Vec::new();

    for line in input.lines() {
        let trimmed = line.trim();

        // Strip [INFO] prefix if present
        let trimmed = if let Some(rest) = trimmed.strip_prefix("[INFO]") {
            rest.trim()
        } else {
            trimmed
        };

        // Skip non-dependency lines
        if trimmed.is_empty()
            || trimmed.starts_with("The following")
            || trimmed.starts_with("---")
            || trimmed.starts_with("none")
            || trimmed.starts_with("BUILD")
            || !trimmed.contains(':')
        {
            continue;
        }

        if let Some(entry) = parse_dep_entry(trimmed) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

fn parse_dep_entry(line: &str) -> Option<DepListEntry> {
    // Strip trailing metadata like " -- module org.foo.bar"
    let line = line.split(" -- ").next().unwrap_or(line).trim();

    // Possible formats:
    //   group:artifact:type:version:scope
    //   group:artifact:type:classifier:version:scope
    let parts: Vec<&str> = line.split(':').collect();

    match parts.len() {
        5 => {
            // group:artifact:type:version:scope
            Some(DepListEntry {
                artifact: Artifact {
                    key: ArtifactKey::new(parts[0], parts[1]),
                    version: parts[3].to_string(),
                    scope: Scope::parse(parts[4]),
                    optional: false,
                    classifier: None,
                    packaging: parts[2].to_string(),
                },
            })
        }
        6 => {
            // group:artifact:type:classifier:version:scope
            Some(DepListEntry {
                artifact: Artifact {
                    key: ArtifactKey::new(parts[0], parts[1]),
                    version: parts[4].to_string(),
                    scope: Scope::parse(parts[5]),
                    optional: false,
                    classifier: Some(parts[3].to_string()),
                    packaging: parts[2].to_string(),
                },
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dep_list_file_format() {
        let input = r#"
The following files have been resolved:
   org.springframework.boot:spring-boot-starter-web:jar:3.2.2:compile
   com.fasterxml.jackson.core:jackson-databind:jar:2.15.3:compile
   org.junit.jupiter:junit-jupiter-api:jar:5.10.1:test
"#;
        let entries = parse_dep_list(input).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].artifact.key.group_id, "org.springframework.boot");
        assert_eq!(entries[0].artifact.key.artifact_id, "spring-boot-starter-web");
        assert_eq!(entries[0].artifact.version, "3.2.2");
        assert_eq!(entries[0].artifact.scope, Scope::Compile);

        assert_eq!(entries[2].artifact.scope, Scope::Test);
    }

    #[test]
    fn test_parse_dep_list_with_classifier() {
        let input = "   org.lwjgl:lwjgl:jar:natives-linux:3.3.1:runtime\n";
        let entries = parse_dep_list(input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].artifact.classifier.as_deref(), Some("natives-linux"));
        assert_eq!(entries[0].artifact.version, "3.3.1");
        assert_eq!(entries[0].artifact.scope, Scope::Runtime);
    }

    #[test]
    fn test_parse_dep_list_module_suffix() {
        let input = r#"
The following files have been resolved:
   org.ow2.asm:asm:jar:9.6:compile -- module org.objectweb.asm
   org.junit.jupiter:junit-jupiter:jar:5.9.2:test -- module org.junit.jupiter
"#;
        let entries = parse_dep_list(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].artifact.scope, Scope::Compile);
        assert_eq!(entries[0].artifact.version, "9.6");
        assert_eq!(entries[1].artifact.scope, Scope::Test);
        assert_eq!(entries[1].artifact.version, "5.9.2");
    }

    #[test]
    fn test_parse_dep_list_info_prefix() {
        let input = r#"[INFO]    org.apache.commons:commons-lang3:jar:3.14.0:compile
[INFO]    org.slf4j:slf4j-api:jar:2.0.9:compile
"#;
        let entries = parse_dep_list(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].artifact.key.artifact_id, "commons-lang3");
    }
}
