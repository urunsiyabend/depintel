use crate::collector::dep_list::DepListEntry;

/// Format dependency list as human-readable text.
pub fn format_dep_list(entries: &[DepListEntry]) -> String {
    let mut output = String::new();

    if entries.is_empty() {
        output.push_str("No dependencies declared.\n");
        return output;
    }

    output.push_str(&format!("Dependencies ({} found):\n\n", entries.len()));

    // Group by scope
    let mut compile = Vec::new();
    let mut runtime = Vec::new();
    let mut provided = Vec::new();
    let mut test = Vec::new();
    let mut other = Vec::new();

    for entry in entries {
        match entry.artifact.scope {
            crate::model::Scope::Compile => compile.push(entry),
            crate::model::Scope::Runtime => runtime.push(entry),
            crate::model::Scope::Provided => provided.push(entry),
            crate::model::Scope::Test => test.push(entry),
            _ => other.push(entry),
        }
    }

    fn format_group(output: &mut String, name: &str, entries: &[&DepListEntry]) {
        if entries.is_empty() {
            return;
        }
        output.push_str(&format!("  [{}] ({}):\n", name, entries.len()));
        for entry in entries {
            let classifier = entry
                .artifact
                .classifier
                .as_deref()
                .map(|c| format!(":{}", c))
                .unwrap_or_default();
            output.push_str(&format!(
                "    {}:{}{}:{}\n",
                entry.artifact.key.group_id,
                entry.artifact.key.artifact_id,
                classifier,
                entry.artifact.version,
            ));
        }
        output.push('\n');
    }

    format_group(&mut output, "compile", &compile);
    format_group(&mut output, "runtime", &runtime);
    format_group(&mut output, "provided", &provided);
    format_group(&mut output, "test", &test);
    format_group(&mut output, "other", &other);

    output
}
