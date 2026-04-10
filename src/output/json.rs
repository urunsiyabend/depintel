use crate::collector::dep_list::DepListEntry;
use serde::Serialize;

#[derive(Serialize)]
struct DepListJson {
    count: usize,
    dependencies: Vec<DepJson>,
}

#[derive(Serialize)]
struct DepJson {
    group_id: String,
    artifact_id: String,
    version: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    classifier: Option<String>,
}

/// Format dependency list as JSON.
pub fn format_dep_list_json(entries: &[DepListEntry]) -> anyhow::Result<String> {
    let json = DepListJson {
        count: entries.len(),
        dependencies: entries
            .iter()
            .map(|e| DepJson {
                group_id: e.artifact.key.group_id.clone(),
                artifact_id: e.artifact.key.artifact_id.clone(),
                version: e.artifact.version.clone(),
                scope: e.artifact.scope.to_string(),
                classifier: e.artifact.classifier.clone(),
            })
            .collect(),
    };

    Ok(serde_json::to_string_pretty(&json)?)
}
