# Changelog

## 0.1.13

Backward-compatible bug fixes; public commands and report schemas are unchanged. Severities, conflict downgrades and exit codes can change where earlier results were wrong, and existing OSV cache entries are refetched once.

### Fixed

- Score CVSS v4 vectors from their own impact metrics; advisories previously capped at MEDIUM now reach HIGH or CRITICAL, so `audit` can newly exit 2.
- Follow OSV `next_page_token` pagination instead of caching truncated advisory lists, and fail rather than cache a partial result if paging does not end.
- Ignore GIT range events, which hold commit hashes, when reporting fixed versions.
- Audit a dependency selected in compile scope when an omitted test-scope duplicate appears first in the tree; it was skipped entirely without `--include-test`.
- Take combined multi-module scopes from selected occurrences regardless of module order.
- Audit every version selected across modules during `bump`, and report version changes in all modules instead of only the first selected version.
- Do not treat a bump target selected by only one module as a no-op or as proof that the override worked; report an error when no module's selection changed.
- Count CVEs fixed by earlier releases as closed by a newer fix-plan target, unless OSV shows the advisory reintroduced at or below that target, the target falls inside an unpatched `last_affected` range, or all its fixes predate the current version. Such CVEs stay in `cves_remaining`. Never offer an older version or prefer a pre-release as a fix: when no upgrade closes a CVE the plan reports `(no fix available)`. Text recommendations use the same choice.
- Keep per-vulnerability summary counts under `audit --severity`.
- Use the highest severity among advisory records sharing a CVE in `bump` CVE deltas, so an unrated first record cannot hide a critical introduction.
- Parse qualified version segments in `conflicts` and `why` (`31.1-jre` was read as minor 0) and compare fourth numeric segments; such conflicts now report the correct jump and downgrades.
- Detect fourth-segment downgrades in `bump`, and stop treating qualifiers such as `android`, `bin` and `SP1` as early pre-releases.
- Forward `--settings` to the `bump --verify` build.
- Preserve runtime, provided and test scopes and the optional flag for `(optional)` entries in `dependency:list` output.
- Reject `--fresh --offline` and `bump --offline` before invalidating the project cache.
- Map Spring, Commons, Log4j 1.x, HttpComponents and embedded Tomcat artifacts whose packages differ from their coordinates, avoiding false LOW applicability in `audit --scan-usage`.

### Tests

- Complete suite: 199 passing tests. Of 57 new tests, 48 reproduced their bug RED before going GREEN, eight are compatibility guards that already passed, and one covers the OSV cache schema change. OSV pagination and advisory reintroduction use offline fixtures.

### Known limitations

- Fix-plan version ordering is conservative for same-number qualifiers: upgrades such as `5.3.7` to `5.3.7.SP1` can report `(no fix available)`. The advisory remains reported rather than being marked fixed.
- Fix plans remain heuristic: conflicting advisory records sharing a CVE can disagree about fixes, and an exact fix in one record can take precedence. Re-audit the proposed target before relying on a plan as security clearance.

## 0.1.12

Backward-compatible bug fixes; public commands and report schemas are unchanged.

### Fixed

- Preserve managed dependency and BOM coordinates when effective POM entries contain exclusions; excluded artifacts no longer replace the managed artifact's identity.
- Preserve resolved runtime, test and provided scopes in verbose dependency trees with scope-only annotations, including classified artifacts and mixed scope/version annotations.
- Do not interpret `scope managed from compile` as a managed version on omitted conflict or duplicate nodes, preventing false version-management metadata.

### Tests

- Complete suite: 142 passing tests, including three independently reproduced RED/GREEN regressions for the fixes above.

## 0.1.11

Backward-compatible bug fixes; public commands and report schemas are unchanged.

### Fixed

- Ignore `<exclusions>` coordinates when locating the dependency to bump, so bumping an excluded artifact no longer rewrites the excluding dependency's version and dependencies with exclusions are patched in place.
- Ignore exclusion coordinates and require both coordinates to come from one entry when choosing a bump fix strategy.
- Avoid out-of-bounds panics and misplaced property lookups in fix-strategy analysis of POMs containing non-ASCII text whose lowercase form changes byte length.
- Include explicitly named module POM files (for example `child/pom-custom.xml`) in the Maven cache fingerprint so edits invalidate cached data; fingerprints for conventional `pom.xml` layouts are unchanged.

### Tests

- Complete suite: 139 passing tests, including five RED/GREEN regression tests for the fixes above and a fingerprint compatibility guard.

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
