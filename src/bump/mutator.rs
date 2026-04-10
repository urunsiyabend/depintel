//! POM mutation: inject or replace a `<dependencyManagement>` entry.
//!
//! We do NOT round-trip the XML through a structured writer (quick-xml's reader
//! + writer loses comments, whitespace, and attribute order in ways Maven users
//! hate). Instead we use the reader to *find* byte positions and then splice
//! the original string. The result is a minimally modified POM that a human
//! could diff against the original and immediately see what changed.

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A discovered `<version>` range plus, if the text was a `${property}` reference,
/// the property name so the mutator can update the property definition instead
/// of splatting a literal into the placeholder.
#[derive(Debug, Clone)]
struct VersionSite {
    range: (usize, usize),
    property_ref: Option<String>,
}

/// Result of analyzing an existing pom.xml for entries we may need to touch.
#[derive(Debug)]
struct PomIndex {
    /// Byte position right after `<project ...>` open tag.
    project_open_end: Option<usize>,
    /// Byte position just before `</project>`.
    project_close_start: Option<usize>,
    /// Byte position just before `</dependencies>` inside `<dependencyManagement>`.
    dep_mgmt_deps_close_start: Option<usize>,
    /// Version sites for managed entries.
    existing_mgmt: Vec<VersionSite>,
    /// Version sites for direct entries (at project-level OR inside a `<profile>`).
    existing_direct: Vec<VersionSite>,
    /// property-name -> (text range) for entries defined under `<project><properties>`.
    properties: HashMap<String, (usize, usize)>,
}

#[derive(Clone)]
struct ElementStack {
    elements: Vec<String>,
}

impl ElementStack {
    fn new() -> Self {
        Self { elements: Vec::new() }
    }
    fn push(&mut self, name: String) {
        self.elements.push(name);
    }
    fn pop(&mut self) {
        self.elements.pop();
    }
    fn matches_suffix(&self, path: &[&str]) -> bool {
        if self.elements.len() < path.len() {
            return false;
        }
        let offset = self.elements.len() - path.len();
        path.iter()
            .enumerate()
            .all(|(i, &want)| self.elements[offset + i] == want)
    }
}

/// Try to patch an existing `<dependency>` or `<dependencyManagement>` entry
/// for `group:artifact` without inserting new XML nodes. Returns `Ok(None)`
/// when the artifact is not already declared in this pom.xml — the caller
/// then decides where (if anywhere) to inject a fallback override.
///
/// Used by multi-module bumping: each child pom.xml is probed, and only the
/// ones that actually declare the target artifact get mutated. Adding a
/// fresh `<dependencyManagement>` block to every child is both noisy and
/// semantically wrong (it would shadow parent BOMs unpredictably).
pub fn try_patch_in_place(
    content: &str,
    group: &str,
    artifact: &str,
    target_version: &str,
) -> Result<Option<String>> {
    let index = analyze_pom(content, group, artifact)?;
    if !index.existing_direct.is_empty() {
        return Ok(Some(splice_sites(
            content,
            &index.existing_direct,
            &index.properties,
            target_version,
        )));
    }
    if !index.existing_mgmt.is_empty() {
        return Ok(Some(splice_sites(
            content,
            &index.existing_mgmt,
            &index.properties,
            target_version,
        )));
    }
    Ok(None)
}

/// Walk a Maven project root and return every `pom.xml` reachable through
/// `<modules>/<module>` declarations. The root pom is always included first.
/// Cycles (via symlinks or relative paths that point at an ancestor) are
/// broken by canonicalising and deduplicating.
pub fn discover_module_poms(root_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack: Vec<PathBuf> = vec![root_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let pom = dir.join("pom.xml");
        if !pom.exists() {
            continue;
        }
        let canonical = std::fs::canonicalize(&pom).unwrap_or_else(|_| pom.clone());
        if !visited.insert(canonical) {
            continue;
        }
        let content = match std::fs::read_to_string(&pom) {
            Ok(c) => c,
            Err(_) => {
                // Unreadable pom — include the path anyway so the caller sees
                // it in backups, but don't descend into missing modules.
                out.push(pom);
                continue;
            }
        };
        out.push(pom.clone());
        for module_rel in parse_module_declarations(&content) {
            // Maven treats `<module>foo</module>` as a sibling directory that
            // contains its own pom.xml. Strip any trailing `/pom.xml` some
            // projects write by mistake.
            let rel = module_rel.trim_end_matches("/pom.xml").trim_end_matches("\\pom.xml");
            stack.push(dir.join(rel));
        }
    }
    Ok(out)
}

/// Extract the text of every `<module>` element directly inside `<modules>`.
fn parse_module_declarations(content: &str) -> Vec<String> {
    let mut reader = Reader::from_str(content);
    reader.trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut modules: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                stack.push(name);
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(t)) => {
                let n = stack.len();
                if n >= 2 && stack[n - 1] == "module" && stack[n - 2] == "modules" {
                    if let Ok(s) = t.unescape() {
                        let trimmed = s.trim().to_string();
                        if !trimmed.is_empty() {
                            modules.push(trimmed);
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    modules
}

/// Inject or replace a `<dependencyManagement>` override for `group:artifact`
/// pinning it to `target_version`. Returns the mutated pom.xml content.
pub fn mutate_pom_xml(
    content: &str,
    group: &str,
    artifact: &str,
    target_version: &str,
) -> Result<String> {
    let index = analyze_pom(content, group, artifact)?;

    // Case 0: one or more direct <dependency> entries pin a version.
    // Patch ALL of them (classifier-qualified duplicates or profile siblings
    // must move together or Maven will silently pick the unpatched sibling).
    // For sites whose <version> is a `${property}` reference, update the
    // referenced property definition instead of the placeholder text so the
    // POM's property indirection stays intact.
    if !index.existing_direct.is_empty() {
        return Ok(splice_sites(
            content,
            &index.existing_direct,
            &index.properties,
            target_version,
        ));
    }

    // Case 1: one or more dependencyManagement entries exist → replace all.
    if !index.existing_mgmt.is_empty() {
        return Ok(splice_sites(
            content,
            &index.existing_mgmt,
            &index.properties,
            target_version,
        ));
    }

    // Case 2: dependencyManagement.dependencies exists → append new <dependency> entry.
    if let Some(splice_at) = index.dep_mgmt_deps_close_start {
        let insertion = format!(
            "    <dependency>\n      <groupId>{}</groupId>\n      <artifactId>{}</artifactId>\n      <version>{}</version>\n    </dependency>\n  ",
            group, artifact, target_version
        );
        let mut out = String::with_capacity(content.len() + insertion.len());
        out.push_str(&content[..splice_at]);
        out.push_str(&insertion);
        out.push_str(&content[splice_at..]);
        return Ok(out);
    }

    // Case 3: No dependencyManagement at all → add a fresh section before </project>.
    if let Some(splice_at) = index.project_close_start {
        let insertion = format!(
            "  <dependencyManagement>\n    <dependencies>\n      <dependency>\n        <groupId>{}</groupId>\n        <artifactId>{}</artifactId>\n        <version>{}</version>\n      </dependency>\n    </dependencies>\n  </dependencyManagement>\n",
            group, artifact, target_version
        );
        let mut out = String::with_capacity(content.len() + insertion.len());
        out.push_str(&content[..splice_at]);
        out.push_str(&insertion);
        out.push_str(&content[splice_at..]);
        return Ok(out);
    }

    // Case 4: something is wrong with the POM — no <project> close tag found.
    // Fall back to project_open_end (immediately after <project>).
    if let Some(splice_at) = index.project_open_end {
        let insertion = format!(
            "\n  <dependencyManagement>\n    <dependencies>\n      <dependency>\n        <groupId>{}</groupId>\n        <artifactId>{}</artifactId>\n        <version>{}</version>\n      </dependency>\n    </dependencies>\n  </dependencyManagement>\n",
            group, artifact, target_version
        );
        let mut out = String::with_capacity(content.len() + insertion.len());
        out.push_str(&content[..splice_at]);
        out.push_str(&insertion);
        out.push_str(&content[splice_at..]);
        return Ok(out);
    }

    anyhow::bail!(
        "Could not find a valid <project> element in pom.xml to inject dependencyManagement override"
    )
}

#[derive(Clone, Copy, PartialEq)]
enum DepKind {
    DirectDependency,
    ManagedDependency,
}

/// Decide how a `<dependency>` currently on the stack should be classified,
/// or `None` if it's in a context we don't touch (e.g. `<plugin>/dependencies`).
///
/// Accepts direct deps under `<project>` or `<profile>` (profile deps used to
/// be silently missed). Managed deps are recognised whether they sit directly
/// under project or inside a profile.
fn classify_dep(stack: &[String]) -> Option<DepKind> {
    let n = stack.len();
    if n < 3 || stack[n - 1] != "dependency" || stack[n - 2] != "dependencies" {
        return None;
    }
    // parent of <dependencies> tells us direct vs managed
    let parent = stack[n - 3].as_str();
    match parent {
        "project" | "profile" => {
            // Reject `<build>/<plugins>/<plugin>/<dependencies>` — the parent
            // would have been "plugin", not "project"/"profile".
            Some(DepKind::DirectDependency)
        }
        "dependencyManagement" => Some(DepKind::ManagedDependency),
        _ => None,
    }
}

fn analyze_pom(content: &str, group: &str, artifact: &str) -> Result<PomIndex> {
    let mut reader = Reader::from_str(content);
    reader.trim_text(false);

    let mut stack = ElementStack::new();

    let mut index = PomIndex {
        project_open_end: None,
        project_close_start: None,
        dep_mgmt_deps_close_start: None,
        existing_mgmt: Vec::new(),
        existing_direct: Vec::new(),
        properties: HashMap::new(),
    };

    struct CurrentDep {
        kind: DepKind,
        group_id: Option<String>,
        artifact_id: Option<String>,
        scope: Option<String>,
        dtype: Option<String>,
        version_site: Option<VersionSite>,
    }
    let mut current_dep: Option<CurrentDep> = None;

    let mut prev_pos: usize = 0;

    loop {
        let pos_before = prev_pos;
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let name = String::from_utf8_lossy(&name_bytes).into_owned();

                if name == "project" && index.project_open_end.is_none() {
                    index.project_open_end = Some(reader.buffer_position() as usize);
                }

                stack.push(name.clone());

                if let Some(kind) = classify_dep(&stack.elements) {
                    current_dep = Some(CurrentDep {
                        kind,
                        group_id: None,
                        artifact_id: None,
                        scope: None,
                        dtype: None,
                        version_site: None,
                    });
                }
            }
            Ok(Event::End(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let name = String::from_utf8_lossy(&name_bytes).into_owned();
                let pos_of_close_open = pos_before;

                // Remember the LAST `<dependencyManagement><dependencies>` close
                // so new entries can be appended there.
                if stack.matches_suffix(&["dependencyManagement", "dependencies"])
                    && name == "dependencies"
                {
                    index.dep_mgmt_deps_close_start = Some(pos_of_close_open);
                }

                if name == "dependency" && classify_dep(&stack.elements).is_some() {
                    if let Some(dep) = current_dep.take() {
                        let _is_bom_import = dep.scope.as_deref() == Some("import")
                            && dep.dtype.as_deref() == Some("pom");
                        if dep.group_id.as_deref() == Some(group)
                            && dep.artifact_id.as_deref() == Some(artifact)
                        {
                            if let Some(site) = dep.version_site {
                                match dep.kind {
                                    DepKind::DirectDependency => {
                                        index.existing_direct.push(site);
                                    }
                                    DepKind::ManagedDependency => {
                                        index.existing_mgmt.push(site);
                                    }
                                }
                            }
                        }
                    }
                }

                if stack.elements.last().map(String::as_str) == Some("project") && name == "project"
                {
                    index.project_close_start = Some(pos_of_close_open);
                }

                stack.pop();
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .unescape()
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| String::new());
                let trimmed = text.trim().to_string();

                // --- 1. dependency fields ---
                if let Some(ref mut dep) = current_dep {
                    if !trimmed.is_empty() {
                        if let Some(leaf) = stack.elements.last() {
                            match leaf.as_str() {
                                "groupId" => dep.group_id = Some(trimmed.clone()),
                                "artifactId" => dep.artifact_id = Some(trimmed.clone()),
                                "scope" => dep.scope = Some(trimmed.clone()),
                                "type" => dep.dtype = Some(trimmed.clone()),
                                "version" => {
                                    let end = reader.buffer_position() as usize;
                                    let start = prev_pos;
                                    let raw = &content[start..end];
                                    let (off_start, off_end) = trim_offsets(raw);
                                    let range = (start + off_start, start + off_end);
                                    let prop = parse_property_ref(&trimmed);
                                    dep.version_site = Some(VersionSite {
                                        range,
                                        property_ref: prop,
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // --- 2. <project><properties><NAME> text capture ---
                // stack tail = [..., "project", "properties", NAME]
                if stack.elements.len() >= 3 && !trimmed.is_empty() {
                    let n = stack.elements.len();
                    if stack.elements[n - 2] == "properties"
                        && stack.elements.get(n - 3).map(String::as_str) == Some("project")
                    {
                        let name = stack.elements[n - 1].clone();
                        let end = reader.buffer_position() as usize;
                        let start = prev_pos;
                        let raw = &content[start..end];
                        let (off_start, off_end) = trim_offsets(raw);
                        index
                            .properties
                            .entry(name)
                            .or_insert((start + off_start, start + off_end));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(anyhow::anyhow!(e))
                    .context("Failed to parse pom.xml while locating the target dependency");
            }
            _ => {}
        }
        prev_pos = reader.buffer_position() as usize;
    }

    Ok(index)
}

/// If `s` is exactly `${name}`, return `name`.
fn parse_property_ref(s: &str) -> Option<String> {
    let s = s.trim();
    if s.starts_with("${") && s.ends_with('}') && s.len() > 3 {
        Some(s[2..s.len() - 1].to_string())
    } else {
        None
    }
}

/// Replace every `(start, end)` range in `content` with `replacement`.
/// Ranges must be non-overlapping. We apply them in reverse source order so
/// earlier offsets stay valid as we splice later ones.
fn splice_ranges(content: &str, ranges: &[(usize, usize)], replacement: &str) -> String {
    let mut sorted: Vec<(usize, usize)> = ranges.to_vec();
    sorted.sort_by(|a, b| b.0.cmp(&a.0)); // descending
    let mut dedup: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for r in sorted {
        if !dedup.iter().any(|existing| *existing == r) {
            dedup.push(r);
        }
    }
    let mut out = content.to_string();
    for (start, end) in dedup {
        out.replace_range(start..end, replacement);
    }
    out
}

/// Splice a set of version sites, honouring `${property}` references by
/// updating the referenced property text instead of the placeholder.
/// Each unique byte range is only patched once even if several sites point at it.
fn splice_sites(
    content: &str,
    sites: &[VersionSite],
    properties: &HashMap<String, (usize, usize)>,
    replacement: &str,
) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for s in sites {
        match &s.property_ref {
            Some(name) => {
                if let Some(r) = properties.get(name) {
                    ranges.push(*r);
                } else {
                    // Placeholder with no matching property definition — fall
                    // back to patching the placeholder literal so Maven at
                    // least resolves to the target version.
                    ranges.push(s.range);
                }
            }
            None => ranges.push(s.range),
        }
    }
    splice_ranges(content, &ranges, replacement)
}

/// Return the (start, end) byte offsets of `s` with surrounding whitespace trimmed,
/// where the offsets are relative to `s` itself.
fn trim_offsets(s: &str) -> (usize, usize) {
    let mut start = 0;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        if !c.is_whitespace() {
            start = i;
            break;
        }
        start = i + c.len_utf8();
    }
    for (i, c) in s.char_indices().rev() {
        if !c.is_whitespace() {
            end = i + c.len_utf8();
            break;
        }
        end = i;
    }
    if start > end {
        (0, 0)
    } else {
        (start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POM_NO_DEPMGMT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
"#;

    const POM_WITH_DEPMGMT_NO_ENTRY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.other</groupId>
                <artifactId>other-lib</artifactId>
                <version>1.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
"#;

    const POM_WITH_DEPMGMT_ENTRY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>2.14.1</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"#;

    #[test]
    fn direct_dependency_version_is_patched_in_place() {
        // log4j-core is a DIRECT dep with an explicit <version> — dependencyManagement
        // would be ignored by Maven, so the mutator must patch the version directly.
        let out = mutate_pom_xml(
            POM_NO_DEPMGMT,
            "org.apache.logging.log4j",
            "log4j-core",
            "2.17.2",
        )
        .unwrap();
        assert!(out.contains("<version>2.17.2</version>"));
        assert!(
            !out.contains("<version>2.14.1</version>"),
            "old direct version should have been replaced, got:\n{}",
            out
        );
        // We should NOT introduce a dependencyManagement section for a direct patch.
        assert!(
            !out.contains("<dependencyManagement>"),
            "direct patch should not add a dependencyManagement section"
        );
    }

    #[test]
    fn creates_depmgmt_for_transitive_target() {
        // A transitive dep not mentioned in the POM at all → create a managed entry.
        let out = mutate_pom_xml(
            POM_NO_DEPMGMT,
            "com.fasterxml.jackson.core",
            "jackson-databind",
            "2.17.0",
        )
        .unwrap();
        assert!(out.contains("<dependencyManagement>"));
        assert!(out.contains("jackson-databind"));
        assert!(out.contains("<version>2.17.0</version>"));
    }

    #[test]
    fn appends_to_existing_depmgmt() {
        let out = mutate_pom_xml(
            POM_WITH_DEPMGMT_NO_ENTRY,
            "org.apache.logging.log4j",
            "log4j-core",
            "2.17.2",
        )
        .unwrap();
        // The other-lib entry is preserved
        assert!(out.contains("other-lib"));
        // log4j now has a managed entry pinning 2.17.2
        let count_mgmt = out
            .match_indices("<dependencyManagement>")
            .count();
        assert_eq!(count_mgmt, 1, "should not duplicate dependencyManagement");
        assert!(out.contains("<version>2.17.2</version>"));
    }

    #[test]
    fn replaces_existing_entry_version() {
        let out = mutate_pom_xml(
            POM_WITH_DEPMGMT_ENTRY,
            "org.apache.logging.log4j",
            "log4j-core",
            "2.17.2",
        )
        .unwrap();
        assert!(
            !out.contains("2.14.1"),
            "old version should be replaced, got:\n{}",
            out
        );
        assert!(out.contains("2.17.2"));
        // Still exactly one <dependency> entry in depmgmt for log4j
        let dep_count = out.matches("<artifactId>log4j-core</artifactId>").count();
        assert_eq!(dep_count, 1);
    }

    // ---- Edge case probes ----

    #[test]
    fn property_placeholder_updates_property_definition() {
        // Fix verification: mutator should update the <properties> entry,
        // leave the `${...}` placeholder intact, and NOT inject depMgmt.
        let pom = r#"<?xml version="1.0"?>
<project>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
  </dependencies>
</project>"#;
        let out = mutate_pom_xml(pom, "org.apache.logging.log4j", "log4j-core", "2.17.2").unwrap();
        assert!(out.contains("<log4j.version>2.17.2</log4j.version>"), "property not updated:\n{}", out);
        assert!(out.contains("${log4j.version}"), "placeholder should be preserved:\n{}", out);
        assert!(!out.contains("2.14.1"), "old version should be gone:\n{}", out);
        assert!(!out.contains("<dependencyManagement>"), "should not inject depMgmt:\n{}", out);
    }

    #[test]
    fn profile_dependency_is_patched_in_place() {
        // Fix verification: a dep declared ONLY inside <profiles><profile> is
        // patched in place instead of being silently missed.
        let pom = r#"<?xml version="1.0"?>
<project>
  <profiles>
    <profile>
      <id>dev</id>
      <dependencies>
        <dependency>
          <groupId>org.apache.logging.log4j</groupId>
          <artifactId>log4j-core</artifactId>
          <version>2.14.1</version>
        </dependency>
      </dependencies>
    </profile>
  </profiles>
</project>"#;
        let out = mutate_pom_xml(pom, "org.apache.logging.log4j", "log4j-core", "2.17.2").unwrap();
        assert!(!out.contains("2.14.1"), "profile dep not updated:\n{}", out);
        assert!(out.contains("<version>2.17.2</version>"));
        assert!(!out.contains("<dependencyManagement>"), "should not inject depMgmt for profile dep:\n{}", out);
    }

    #[test]
    fn probe_empty_version_tag() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version></version>
    </dependency>
  </dependencies>
</project>"#;
        let out = mutate_pom_xml(pom, "g", "a", "9.9.9").unwrap();
        println!("EMPTY_VERSION_OUT:\n{}", out);
    }

    #[test]
    fn probe_whitespace_only_version() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>
      </version>
    </dependency>
  </dependencies>
</project>"#;
        let out = mutate_pom_xml(pom, "g", "a", "9.9.9").unwrap();
        println!("WHITESPACE_VERSION_OUT:\n{}", out);
    }

    #[test]
    fn probe_version_with_comment_inside() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>1.0.0<!-- pinned --></version>
    </dependency>
  </dependencies>
</project>"#;
        let out = mutate_pom_xml(pom, "g", "a", "2.0.0").unwrap();
        println!("COMMENT_IN_VERSION_OUT:\n{}", out);
    }

    #[test]
    fn probe_multiple_direct_dup_same_ga_no_classifier() {
        // Two direct entries for same GA (illegal Maven, but users do it).
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>1.5.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let out = mutate_pom_xml(pom, "g", "a", "9.9.9").unwrap();
        println!("DUP_DIRECT_OUT:\n{}", out);
        assert!(!out.contains("1.0.0"));
        assert!(!out.contains("1.5.0"));
    }

    #[test]
    fn probe_nested_project_tag_in_text() {
        // Mutator uses `project_close_start` which tracks the *last* </project>.
        // A stray "<project>" mention inside CDATA or text shouldn't confuse it.
        let pom = r#"<?xml version="1.0"?>
<project>
  <description>our &lt;project&gt; lib</description>
</project>"#;
        let out = mutate_pom_xml(pom, "g", "a", "1.0.0").unwrap();
        println!("NESTED_PROJECT_OUT:\n{}", out);
        assert!(out.contains("<dependencyManagement>"));
    }

    #[test]
    fn probe_bom_import_depmgmt() {
        // BOM-imported depMgmt entry (scope=import, type=pom). Mutator treats
        // it as a normal managed entry and overwrites the BOM version.
        let pom = r#"<?xml version="1.0"?>
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>2.14.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>"#;
        let out = mutate_pom_xml(pom, "com.fasterxml.jackson", "jackson-bom", "2.17.0").unwrap();
        println!("BOM_IMPORT_OUT:\n{}", out);
    }

    // ---- scorer probes ----
    #[test]
    fn zerover_minor_bump_is_major() {
        // Fix verification: under SemVer 0.x rules, a minor bump is breaking.
        let j = crate::bump::scorer::classify_version_jump("0.1.0", "0.2.0");
        assert!(j.major_jump);
        assert!(!j.is_downgrade);
    }

    #[test]
    fn release_to_prerelease_is_downgrade() {
        // Fix verification: 2.0.0 -> 2.0.0-RC1 must be detected as a downgrade.
        let j = crate::bump::scorer::classify_version_jump("2.0.0", "2.0.0-RC1");
        assert!(j.is_downgrade, "release→pre-release should be a downgrade");

        // And the reverse is a forward move, not a downgrade.
        let j2 = crate::bump::scorer::classify_version_jump("2.0.0-RC1", "2.0.0");
        assert!(!j2.is_downgrade);
    }

    #[test]
    fn v_prefix_is_parsed() {
        // Fix verification: `v2.0.0 -> v3.0.0` must be detected as a major jump
        // (previously non-numeric prefix silenced the signal).
        let j = crate::bump::scorer::classify_version_jump("v2.0.0", "v3.0.0");
        assert!(j.major_jump);
    }

    #[test]
    fn downgrade_does_not_double_signal_as_skip() {
        // Fix verification: downgrade should NOT also be flagged as
        // `minor_versions_skipped_N`.
        let j = crate::bump::scorer::classify_version_jump("1.10.0", "1.6.0");
        assert_eq!(j.minor_skipped, 0, "downgrade shouldn't populate minor_skipped");
        assert!(j.is_downgrade);
    }

    #[test]
    fn try_patch_returns_none_when_artifact_not_present() {
        let pom = r#"<?xml version="1.0"?>
<project><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency></dependencies></project>"#;
        let r = try_patch_in_place(pom, "not", "there", "9.9.9").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn try_patch_updates_existing_direct() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>g</groupId>
      <artifactId>a</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let r = try_patch_in_place(pom, "g", "a", "2.5.0").unwrap().unwrap();
        assert!(r.contains("<version>2.5.0</version>"), "got:\n{}", r);
        assert!(!r.contains("1.0.0"), "got:\n{}", r);
    }

    #[test]
    fn discover_module_poms_finds_multi_module_reactor() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("pom.xml"),
            r#"<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.test</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>api</module>
    <module>impl</module>
  </modules>
</project>"#,
        )
        .unwrap();
        fs::create_dir(root.join("api")).unwrap();
        fs::create_dir(root.join("impl")).unwrap();
        fs::write(
            root.join("api").join("pom.xml"),
            r#"<?xml version="1.0"?><project><artifactId>api</artifactId></project>"#,
        )
        .unwrap();
        fs::write(
            root.join("impl").join("pom.xml"),
            r#"<?xml version="1.0"?><project><artifactId>impl</artifactId></project>"#,
        )
        .unwrap();

        let poms = discover_module_poms(root).unwrap();
        assert_eq!(poms.len(), 3, "expected root + 2 modules, got {:?}", poms);
        // Root is enumerated first.
        assert!(poms[0].ends_with("pom.xml"));
        assert!(poms.iter().any(|p| p.to_string_lossy().contains("api")));
        assert!(poms.iter().any(|p| p.to_string_lossy().contains("impl")));
    }

    #[test]
    fn discover_module_poms_handles_missing_child() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("pom.xml"),
            r#"<?xml version="1.0"?>
<project><modules><module>missing</module></modules></project>"#,
        )
        .unwrap();
        // `missing/` directory intentionally not created.
        let poms = discover_module_poms(root).unwrap();
        assert_eq!(poms.len(), 1, "missing child should be skipped, not errored");
    }

    #[test]
    fn output_is_parseable_xml() {
        // Round-trip: mutating should produce XML that quick-xml can re-read without error.
        let out = mutate_pom_xml(
            POM_NO_DEPMGMT,
            "org.apache.logging.log4j",
            "log4j-core",
            "2.17.2",
        )
        .unwrap();
        let mut r = Reader::from_str(&out);
        loop {
            match r.read_event() {
                Ok(Event::Eof) => break,
                Err(e) => panic!("mutated POM failed to parse: {}", e),
                _ => {}
            }
        }
    }
}
