use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identity of a Maven artifact (without version).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactKey {
    pub group_id: String,
    pub artifact_id: String,
}

impl ArtifactKey {
    pub fn new(group_id: impl Into<String>, artifact_id: impl Into<String>) -> Self {
        Self {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
        }
    }

    /// Parse from "groupId:artifactId" format.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some(Self::new(parts[0], parts[1]))
        } else {
            None
        }
    }
}

impl fmt::Display for ArtifactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.group_id, self.artifact_id)
    }
}

/// A specific version of an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub key: ArtifactKey,
    pub version: String,
    pub scope: Scope,
    pub optional: bool,
    pub classifier: Option<String>,
    pub packaging: String,
}

impl fmt::Display for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.key.group_id, self.key.artifact_id, self.packaging, self.version
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Compile,
    Runtime,
    Provided,
    Test,
    System,
    Import,
}

impl Scope {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "compile" => Scope::Compile,
            "runtime" => Scope::Runtime,
            "provided" => Scope::Provided,
            "test" => Scope::Test,
            "system" => Scope::System,
            "import" => Scope::Import,
            _ => Scope::Compile,
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Compile => write!(f, "compile"),
            Scope::Runtime => write!(f, "runtime"),
            Scope::Provided => write!(f, "provided"),
            Scope::Test => write!(f, "test"),
            Scope::System => write!(f, "system"),
            Scope::Import => write!(f, "import"),
        }
    }
}
