//! Scan project source files for usage of vulnerable packages to assess CVE applicability.

use serde::Serialize;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApplicabilityLevel {
    High,
    Low,
    Unknown,
}

impl ApplicabilityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApplicabilityLevel::High => "HIGH",
            ApplicabilityLevel::Low => "LOW",
            ApplicabilityLevel::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplicabilityResult {
    pub level: ApplicabilityLevel,
    pub detail: String,
    pub matching_files: Vec<String>,
}

/// Scan the project source tree for usage of a given Maven artifact's packages.
pub fn scan_usage(
    project_dir: &Path,
    group_id: &str,
    artifact_id: &str,
) -> ApplicabilityResult {
    let patterns = resolve_patterns(group_id, artifact_id);

    // Find the source directory — prefer Maven-standard layout, fall back to bare src/
    let src_dirs: Vec<&str> = vec!["src/main/java", "src/main/kotlin", "src/main/scala", "src"];
    let mut found_src = false;

    let mut matching_files: Vec<String> = Vec::new();
    let mut total_matches: usize = 0;

    // Use the first matching source directory to avoid double-counting
    let active_src_dir = src_dirs.iter().find(|d| project_dir.join(d).exists());
    for src_dir in active_src_dir.iter() {
        let src_path = project_dir.join(src_dir);
        if !src_path.exists() {
            continue;
        }
        found_src = true;

        for entry in WalkDir::new(&src_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                name.ends_with(".java")
                    || name.ends_with(".kt")
                    || name.ends_with(".scala")
                    || name.ends_with(".groovy")
            })
        {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let mut found_in_file = false;
                for pattern in &patterns {
                    if content.contains(pattern.as_str()) {
                        found_in_file = true;
                        total_matches += 1;
                    }
                }
                if found_in_file {
                    let rel = entry
                        .path()
                        .strip_prefix(project_dir)
                        .unwrap_or(entry.path())
                        .to_string_lossy()
                        .to_string();
                    matching_files.push(rel);
                }
            }
        }
    }

    if !found_src {
        return ApplicabilityResult {
            level: ApplicabilityLevel::Unknown,
            detail: "No source directory found".to_string(),
            matching_files: Vec::new(),
        };
    }

    if matching_files.is_empty() {
        ApplicabilityResult {
            level: ApplicabilityLevel::Low,
            detail: format!(
                "No imports of {} found in source",
                patterns.join(", ")
            ),
            matching_files: Vec::new(),
        }
    } else {
        ApplicabilityResult {
            level: ApplicabilityLevel::High,
            detail: format!(
                "Found {} import(s) in {} file(s)",
                total_matches,
                matching_files.len()
            ),
            matching_files,
        }
    }
}

/// Resolve Java package patterns to search for, given a Maven coordinate.
fn resolve_patterns(group_id: &str, artifact_id: &str) -> Vec<String> {
    // Check known artifact → package mappings first
    if let Some(known) = known_patterns(group_id, artifact_id) {
        return known;
    }

    // Generic fallback: groupId usually maps to Java package prefix
    // e.g., "com.fasterxml.jackson.core" → "com.fasterxml.jackson.core"
    vec![group_id.to_string()]
}

/// Well-known mappings from Maven coordinates to Java package prefixes.
fn known_patterns(group: &str, artifact: &str) -> Option<Vec<String>> {
    let patterns: Option<Vec<&str>> = match (group, artifact) {
        // Netty
        ("io.netty", "netty-codec-smtp") => Some(vec!["io.netty.handler.codec.smtp"]),
        ("io.netty", "netty-codec-http") => Some(vec!["io.netty.handler.codec.http"]),
        ("io.netty", "netty-codec-http2") => Some(vec!["io.netty.handler.codec.http2"]),
        ("io.netty", "netty-handler") => Some(vec!["io.netty.handler.ssl", "io.netty.handler.proxy", "io.netty.handler.stream"]),
        ("io.netty", "netty-transport") => Some(vec!["io.netty.channel", "io.netty.bootstrap"]),
        ("io.netty", "netty-buffer") => Some(vec!["io.netty.buffer"]),
        ("io.netty", "netty-common") => Some(vec!["io.netty.util"]),
        // Jackson
        ("com.fasterxml.jackson.core", "jackson-databind") => Some(vec!["com.fasterxml.jackson.databind"]),
        ("com.fasterxml.jackson.core", "jackson-core") => Some(vec!["com.fasterxml.jackson.core"]),
        ("com.fasterxml.jackson.core", "jackson-annotations") => Some(vec!["com.fasterxml.jackson.annotation"]),
        // Log4j
        ("org.apache.logging.log4j", "log4j-core") => Some(vec!["org.apache.logging.log4j"]),
        ("org.apache.logging.log4j", "log4j-api") => Some(vec!["org.apache.logging.log4j"]),
        // SLF4J
        ("org.slf4j", "slf4j-api") => Some(vec!["org.slf4j"]),
        // OkHttp
        ("com.squareup.okhttp3", "okhttp") => Some(vec!["okhttp3"]),
        // Gson
        ("com.google.code.gson", "gson") => Some(vec!["com.google.gson"]),
        // Guava
        ("com.google.guava", "guava") => Some(vec!["com.google.common"]),
        // Spring
        ("org.springframework", a) if a.starts_with("spring-") => {
            let module = a.strip_prefix("spring-").unwrap_or(a);
            Some(vec![Box::leak(format!("org.springframework.{}", module.replace('-', ".")).into_boxed_str())])
        }
        // Commons
        ("org.apache.commons", "commons-lang3") => Some(vec!["org.apache.commons.lang3"]),
        ("org.apache.commons", "commons-collections4") => Some(vec!["org.apache.commons.collections4"]),
        ("commons-io", "commons-io") => Some(vec!["org.apache.commons.io"]),
        // SnakeYAML
        ("org.yaml", "snakeyaml") => Some(vec!["org.yaml.snakeyaml"]),
        // Nimbus
        ("com.nimbusds", "nimbus-jose-jwt") => Some(vec!["com.nimbusds.jose", "com.nimbusds.jwt"]),
        // Bouncy Castle
        ("org.bouncycastle", _) => Some(vec!["org.bouncycastle"]),
        _ => None,
    };
    patterns.map(|v| v.into_iter().map(String::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_known_patterns() {
        let p = known_patterns("com.fasterxml.jackson.core", "jackson-databind").unwrap();
        assert_eq!(p, vec!["com.fasterxml.jackson.databind"]);

        let p = known_patterns("io.netty", "netty-codec-smtp").unwrap();
        assert_eq!(p, vec!["io.netty.handler.codec.smtp"]);

        assert!(known_patterns("com.unknown", "unknown").is_none());
    }

    #[test]
    fn test_scan_usage_finds_imports() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src/main/java/com/example");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("App.java"),
            "import com.fasterxml.jackson.databind.ObjectMapper;\nclass App {}",
        )
        .unwrap();

        let result = scan_usage(dir.path(), "com.fasterxml.jackson.core", "jackson-databind");
        assert_eq!(result.level, ApplicabilityLevel::High);
        assert_eq!(result.matching_files.len(), 1);
    }

    #[test]
    fn test_scan_usage_no_match() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src/main/java/com/example");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("App.java"), "class App {}").unwrap();

        let result = scan_usage(dir.path(), "io.netty", "netty-codec-smtp");
        assert_eq!(result.level, ApplicabilityLevel::Low);
    }

    #[test]
    fn test_scan_usage_no_src() {
        let dir = TempDir::new().unwrap();
        let result = scan_usage(dir.path(), "io.netty", "netty-codec-smtp");
        assert_eq!(result.level, ApplicabilityLevel::Unknown);
    }
}
