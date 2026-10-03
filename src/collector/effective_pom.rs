use crate::model::{ArtifactKey, Scope};
use anyhow::Result;
use quick_xml::events::Event;
use quick_xml::Reader;

/// A dependency management entry from the effective POM.
#[derive(Debug, Clone)]
pub struct ManagedDependency {
    pub key: ArtifactKey,
    pub version: String,
    pub scope: Option<Scope>,
    pub packaging: Option<String>,
}

impl ManagedDependency {
    /// Returns true if this is a BOM import (scope=import, type=pom).
    pub fn is_bom(&self) -> bool {
        self.scope.as_ref() == Some(&Scope::Import) && self.packaging.as_deref() == Some("pom")
    }
}

/// Module info extracted from effective POM.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub modules: Vec<String>,
    pub managed_dependencies: Vec<ManagedDependency>,
    pub properties: Vec<(String, String)>,
    /// BOMs imported via dependencyManagement (scope=import, type=pom).
    pub bom_imports: Vec<ManagedDependency>,
}

/// Parse the effective POM XML to extract dependencyManagement and module info.
pub fn parse_effective_pom(xml: &str) -> Result<Vec<ModuleInfo>> {
    let mut modules = Vec::new();
    let mut reader = Reader::from_str(xml);

    let mut current_module: Option<ModuleInfo> = None;
    let mut in_dep_mgmt = false;
    let mut in_dependencies_under_mgmt = false;
    let mut in_dependency = false;
    let mut in_modules = false;
    let mut in_properties = false;

    // Current dependency fields
    let mut dep_group_id = String::new();
    let mut dep_artifact_id = String::new();
    let mut dep_version = String::new();
    let mut dep_scope = None;
    let mut dep_type = None;

    // Track element path for context
    let mut current_element = String::new();
    let mut depth = 0u32;
    let mut project_depth = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                depth += 1;

                if name == "project" && project_depth.is_none() {
                    project_depth = Some(depth);
                }

                let project_child = project_depth.is_some_and(|d| depth == d + 1);
                if name == "dependencyManagement" && project_child {
                    in_dep_mgmt = true;
                } else if name == "dependencies" && in_dep_mgmt {
                    in_dependencies_under_mgmt = true;
                } else if name == "dependency" && in_dependencies_under_mgmt {
                    in_dependency = true;
                    dep_group_id.clear();
                    dep_artifact_id.clear();
                    dep_version.clear();
                    dep_scope = None;
                    dep_type = None;
                } else if name == "modules" && project_child {
                    in_modules = true;
                } else if name == "properties" && project_child {
                    in_properties = true;
                }

                current_element = name;
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                depth -= 1;

                if name == "dependencyManagement" {
                    in_dep_mgmt = false;
                } else if name == "dependencies" && in_dep_mgmt {
                    in_dependencies_under_mgmt = false;
                } else if name == "dependency" && in_dependency {
                    in_dependency = false;
                    if !dep_group_id.is_empty() && !dep_artifact_id.is_empty() {
                        let managed = ManagedDependency {
                            key: ArtifactKey::new(&dep_group_id, &dep_artifact_id),
                            version: dep_version.clone(),
                            scope: dep_scope.clone(),
                            packaging: dep_type.clone(),
                        };
                        if let Some(ref mut module) = current_module {
                            if managed.is_bom() {
                                module.bom_imports.push(managed.clone());
                            }
                            module.managed_dependencies.push(managed);
                        }
                    }
                } else if name == "modules" {
                    in_modules = false;
                } else if name == "properties" {
                    in_properties = false;
                } else if name == "project" {
                    project_depth = None;
                    if let Some(module) = current_module.take() {
                        modules.push(module);
                    }
                }

                current_element.clear();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if text.is_empty() {
                    continue;
                }

                if in_dependency {
                    match current_element.as_str() {
                        "groupId" => dep_group_id = text,
                        "artifactId" => dep_artifact_id = text,
                        "version" => dep_version = text,
                        "scope" => dep_scope = Some(Scope::parse(&text)),
                        "type" => dep_type = Some(text),
                        _ => {}
                    }
                } else if in_modules && current_element == "module" {
                    if let Some(ref mut module) = current_module {
                        module.modules.push(text);
                    }
                } else if in_properties {
                    if let Some(ref mut module) = current_module {
                        module.properties.push((current_element.clone(), text));
                    }
                } else if project_depth.is_some_and(|d| depth == d + 1) {
                    match current_element.as_str() {
                        "groupId" => {
                            if current_module.is_none() {
                                current_module = Some(ModuleInfo {
                                    group_id: text,
                                    artifact_id: String::new(),
                                    version: String::new(),
                                    modules: Vec::new(),
                                    managed_dependencies: Vec::new(),
                                    properties: Vec::new(),
                                    bom_imports: Vec::new(),
                                });
                            } else if let Some(ref mut m) = current_module {
                                if m.group_id.is_empty() {
                                    m.group_id = text;
                                }
                            }
                        }
                        "artifactId" => {
                            if let Some(ref mut m) = current_module {
                                if m.artifact_id.is_empty() {
                                    m.artifact_id = text;
                                }
                            }
                        }
                        "version" => {
                            if let Some(ref mut m) = current_module {
                                if m.version.is_empty() {
                                    m.version = text;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(anyhow::anyhow!("Error parsing effective POM XML: {}", e));
            }
            _ => {}
        }
    }

    // Handle case where we have a module that wasn't closed
    if let Some(module) = current_module.take() {
        modules.push(module);
    }

    Ok(modules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_coordinates_do_not_come_from_parent() {
        let xml = r#"<project>
  <parent>
    <groupId>org.parent</groupId>
    <artifactId>parent</artifactId>
    <version>9</version>
  </parent>
  <groupId>org.child</groupId>
  <artifactId>child</artifactId>
  <version>1</version>
</project>"#;
        let modules = parse_effective_pom(xml).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].group_id, "org.child");
        assert_eq!(modules[0].artifact_id, "child");
        assert_eq!(modules[0].version, "1");
    }

    #[test]
    fn nested_profile_sections_do_not_override_effective_project_sections() {
        let xml = r#"<project>
  <groupId>org.example</groupId><artifactId>app</artifactId><version>1</version>
  <dependencyManagement><dependencies><dependency>
    <groupId>org.lib</groupId><artifactId>lib</artifactId><version>2</version>
  </dependency></dependencies></dependencyManagement>
  <properties><lib.version>2</lib.version></properties>
  <modules><module>active</module></modules>
  <profiles><profile><id>inactive</id>
    <dependencyManagement><dependencies><dependency>
      <groupId>org.lib</groupId><artifactId>lib</artifactId><version>9</version>
    </dependency></dependencies></dependencyManagement>
    <properties><lib.version>9</lib.version></properties>
    <modules><module>inactive</module></modules>
  </profile></profiles>
</project>"#;
        let modules = parse_effective_pom(xml).unwrap();
        let module = &modules[0];
        assert_eq!(module.managed_dependencies.len(), 1);
        assert_eq!(module.managed_dependencies[0].version, "2");
        assert_eq!(module.properties, vec![("lib.version".into(), "2".into())]);
        assert_eq!(module.modules, vec!["active"]);
    }

    #[test]
    fn reactor_projects_keep_separate_coordinates_and_bom_imports() {
        let xml = r#"<projects>
  <project>
    <parent><groupId>org.parent</groupId><artifactId>parent</artifactId><version>9</version></parent>
    <groupId>org.example</groupId><artifactId>first</artifactId><version>1</version>
    <dependencyManagement><dependencies><dependency>
      <groupId>org.bom</groupId><artifactId>bom</artifactId><version>2</version>
      <type>pom</type><scope>import</scope>
    </dependency></dependencies></dependencyManagement>
  </project>
  <project>
    <groupId>org.other</groupId><artifactId>second</artifactId><version>3</version>
  </project>
</projects>"#;
        let modules = parse_effective_pom(xml).unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].artifact_id, "first");
        assert_eq!(modules[0].bom_imports.len(), 1);
        assert!(modules[0].bom_imports[0].is_bom());
        assert_eq!(modules[1].group_id, "org.other");
        assert_eq!(modules[1].artifact_id, "second");
        assert_eq!(modules[1].version, "3");
        assert!(modules[1].managed_dependencies.is_empty());
    }

    #[test]
    fn test_parse_simple_effective_pom() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.3</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>"#;

        let modules = parse_effective_pom(xml).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].group_id, "com.example");
        assert_eq!(modules[0].artifact_id, "app");
        assert_eq!(modules[0].managed_dependencies.len(), 1);
        assert_eq!(modules[0].managed_dependencies[0].version, "2.15.3");
    }
}
