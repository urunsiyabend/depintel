# Changelog

## 0.1.7

Backward-compatible bug fixes; no new commands or breaking interface changes.

### Fixed

- Scan all main Java, Kotlin, Scala and Groovy source roots instead of stopping at the first one.
- Report unknown applicability when source traversal or reads fail without positive usage evidence.
- Respect package boundaries when matching usage (for example, Netty HTTP versus HTTP/2).
- Preserve Maven dependency-tree nesting after last-child branches.
- Reconstruct omitted conflict requests and nested duplicate paths.
- Update direct and managed versions together when bumping the same artifact.
- Insert transitive overrides into project-level management rather than optional profiles.
- Reuse root management sections that lack dependencies and expand self-closing management/dependencies containers.
- Deduplicate shared CVE identities in fix-plan counts and severity summaries.
- Handle zero-impact CVSS v3 vectors without inventing a medium-severity score.

### Maintenance

- Remove deprecated TempDir::into_path usage and automatically clean up cache test directories.
- Add regression coverage for the fixes above.
