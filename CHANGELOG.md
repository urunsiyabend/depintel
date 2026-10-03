# Changelog

## 0.1.10

Backward-compatible bug fixes; public commands and report schemas are unchanged.

### Fixed

- Invalidate unversioned or incompatible OSV cache entries so legacy advisory results are refetched with current filtering.
- Refuse backup symlink collisions and atomically reserve private backup files without overwriting existing recovery data; clean up partial backup creation.
- Discover explicitly named module POM files as well as module directories, retaining cycle protection.
- Ignore query strings and fragments when parsing GitHub POM URLs.
- Reject empty explicit GitHub refs before cache lookup, avoiding default-branch cache collisions.

### Tests

- Complete suite: 133 passing tests, including offline fixtures for cache migration, backup recovery and creation-time permissions.

## 0.1.9

Backward-compatible bug fixes; public commands and schemas are unchanged.

### Fixed

- Exclude parent coordinates and nested profile sections from effective project data.
- Publish Maven cache validity only after output writes succeed.
- Update all referenced scoped properties during shared-group fallback mutation.
- Attempt restoration of every POM even if one restoration fails, retaining failed backups.
- Enrich shared OSV advisory details separately for each package query.
- Exclude withdrawn OSV advisories from newly fetched findings and cache entries.

### Tests

- Complete suite: 122 passing tests. Legacy OSV cache entries expire normally or can be refreshed with `--fresh-cves`.

## 0.1.8

Backward-compatible bug fixes; commands and serialized schemas are unchanged.

### Fixed

- Compare numeric version components when breaking fix-plan candidate ties, so 2.10 ranks above 2.9.
- Escape XML text when inserting or replacing Maven coordinates and versions.
- Update profile-local version properties instead of unrelated root definitions; preserve root inheritance when no local override exists.
- Preserve selected version, scope and resolution metadata when `why --depth` filters displayed paths.
- Prevent reconstructed duplicate subtrees from revisiting real ancestors and inventing cyclic paths.

### Tests

- Add five RED/GREEN regression tests; the complete suite now contains 114 passing tests.

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
