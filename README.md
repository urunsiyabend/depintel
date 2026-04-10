# depintel

Maven dependency intelligence CLI. Asks the questions `mvn dependency:tree` can't
answer: *why* is this version selected, *which* conflicts are actually dangerous,
*are any of my deps carrying known CVEs*, and *what happens if I bump this version*
— all with path context from the dependency graph.

depintel runs Maven under the hood (`dependency:tree`, `dependency:list`,
`help:effective-pom`), parses the output into a graph, and layers analysis on top.
It doesn't replace Maven — it sits next to it and answers questions Maven itself
won't.

## Install

Requires a working `mvn` (or `mvnw` / `mvnd`) on the system.

### Prebuilt binaries (recommended)

```bash
# macOS / Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/urunsiyabend/depintel/releases/latest/download/depintel-installer.sh | sh

# Windows (PowerShell)
irm https://github.com/urunsiyabend/depintel/releases/latest/download/depintel-installer.ps1 | iex
```

### From source

Requires Rust 1.74+.

```bash
cargo install --git https://github.com/urunsiyabend/depintel.git
```

## Quick start

Point depintel at any Maven project (single module or monorepo):

```bash
depintel --pom . list
depintel --pom . tree
depintel --pom . conflicts
depintel --pom . audit
depintel --pom . why org.apache.commons:commons-lang3
depintel --pom . bump com.google.guava:guava --to 33.0-jre
```

Or run it against a GitHub repo without cloning it yourself:

```bash
depintel --pom-url https://github.com/apache/druid conflicts
```

## Commands

### `list` — flat dependency list, grouped by scope

```
$ depintel --pom . list
Dependencies (23 found):

  [compile] (18):
    com.google.inject:guice:4.0
    com.google.guava:guava:32.1.3-jre
    ...
  [runtime] (1):
    org.apache.logging.log4j:log4j-core:2.14.1
  [test] (4):
    ...
```

### `tree` — dependency tree, conflict-aware

```
$ depintel --pom . tree
com.test:conflict-test:1.0.0:compile
+- com.google.inject:guice:4.0:compile
|  +- javax.inject:javax.inject:1:compile
|  \- com.google.guava:guava:16.0.1:compile (conflict: 32.1.3-jre wins)
+- com.google.guava:guava:32.1.3-jre:compile
...

23 dependencies, 4 conflicts
(use --verbose to show omitted duplicates)
```

### `why` — how did this artifact end up here?

Shows every path to a given artifact, the resolution reason, and *reconstructs
paths Maven elides under "omitted for duplicate"* — something `mvn
dependency:tree` cannot do:

```
$ depintel --pom-url https://raw.githubusercontent.com/.../pom.xml why org.yaml:snakeyaml
WHY: org.yaml:snakeyaml

Selected version: 2.5
Scope: compile

Resolution reason:
  dependencyManagement pins version 2.5

Dependency paths (12 found):
  [1] spring-petclinic -> spring-boot-starter-actuator -> spring-boot-starter -> snakeyaml:2.5  (selected)
  [2] spring-petclinic -> spring-boot-starter-cache -> spring-boot-starter -> snakeyaml:2.5  = (duplicate)
  [3] spring-petclinic -> spring-boot-starter-data-jpa -> spring-boot-starter -> snakeyaml:2.5  = (duplicate)
  ...

Warnings:
  Same version pulled from 12 independent paths
```

Flags: `--depth <N>`, `--all-versions`.

### `conflicts` — severity-scored version conflicts

Scans the graph for artifacts whose versions disagree, scores each conflict
(HIGH/MEDIUM/LOW), flags downgrades, and explains the runtime risk:

```
$ depintel --pom . conflicts
CONFLICTS: 4 found in com.test:conflict-test:1.0.0

  HIGH    com.google.guava:guava
          16.0.1 -> 32.1.3-jre (MAJOR jump)
          Selected: nearest_wins (compile)
          Risk: com.google.inject:guice:4.0 compiled against 16.x (16.0.1) -- resolved to 32.x, runtime errors possible
          Run: depintel why com.google.guava:guava

  HIGH    org.slf4j:slf4j-api
          1.7.25 -> 2.0.9 (MAJOR jump)
          ...

  LOW     com.fasterxml.jackson.core:jackson-databind
          2.14.0 -> 2.15.3 (minor jump)
          ...

Summary: 2 HIGH, 0 MEDIUM, 2 LOW
```

Severity rules:
- **HIGH** — major version jump (API break risk)
- **MEDIUM** — minor jump of 5+ versions, or a downgrade
- **LOW** — small minor/patch difference

Modifiers:
- `scope=test` drops severity one level
- `dependencyManagement`/BOM pin drops severity one level (intentional override)
- Any downgrade raises severity one level and gets a `[DOWNGRADE]` tag

Flags: `--severity high|medium|low`, `--group <prefix>`, `--include-managed`.

### `audit` — CVE scan against OSV.dev

For every selected artifact, queries `api.osv.dev` for known CVEs and attaches
graph context (path, scope, direct vs transitive):

```
$ depintel --pom . audit
SECURITY AUDIT: 4 vulnerability finding(s) in com.test:log4shell-demo:1.0.0 (6 artifacts scanned)

  org.apache.logging.log4j:log4j-core 2.14.1  (compile) [direct]  (3 CRITICAL, 1 HIGH, 1 MEDIUM)
    CRITICAL  CVE-2021-44228  Remote code injection in Log4j
              fixed in 2.12.2, 2.15.0, 2.3.1
    CRITICAL  CVE-2021-45046  Incomplete fix for Apache Log4j vulnerability
              fixed in 2.12.2, 2.16.0
    CRITICAL  CVE-2021-44832  Improper Input Validation and Injection in Apache Log4j2
    HIGH      CVE-2021-45105  Apache Log4j2 vulnerable to Uncontrolled Recursion
    MEDIUM    CVE-2025-68161  Apache Log4j does not verify the TLS hostname
    -> upgrade 2.14.1 -> 2.12.2

  com.fasterxml.jackson.core:jackson-databind 2.9.10  (compile) [direct]  (39 CRITICAL, 4 HIGH)
    ...
    -> upgrade 2.9.10 -> 2.9.10.8

Summary: 42 CRITICAL, 5 HIGH, 5 MEDIUM, 0 LOW
```

The `-> upgrade X -> Y` line is heuristic: Y is the fixed-version that closes
the largest number of findings. It's a starting point, not a blind recommendation.

Flags: `--severity low|medium|high|critical`, `--include-test`, `--fresh-cves`.

**Caveat.** OSV-based scanning reads Maven coordinates — it does not unpack JARs.
If your pipeline uses shading or fat-jars, pair depintel with OWASP
Dependency-Check for binary identification.

### `bump` — preview the impact of a version change

Mutates the POM temporarily, re-runs Maven, diffs the two graphs, and produces a
risk-scored report covering transitive changes, new/resolved conflicts, and
CVEs fixed or introduced:

```
$ depintel --pom . bump com.google.guava:guava --to 33.0-jre
BUMP PREVIEW: com.google.guava:guava 32.1.3-jre -> 33.0-jre

  Graph risk: MEDIUM
  Basis: graph-level signals only (no bytecode/API analysis)
  Scope: compile

  Reasons:
    - major version jump (32.x -> 33.x)
    - 2 new transitive dependencies added

  CVEs fixed (3):
    HIGH      CVE-2023-XXXXX  ...
    MEDIUM    CVE-2024-XXXXX  ...

  CVEs introduced: none

  Transitive changes:
    ~ com.google.guava:failureaccess 1.0.1 -> 1.0.2
    + com.google.guava:listenablefuture 1.0 (new)

  New conflicts: none

  Recommended actions:
    1. Run tests: major version bump, run full test suite
    2. Review changelog: check guava 33.x release notes for breaking changes
```

The POM is always restored to its original state after the preview.

Flags: `--to <version>`. Accepts full Maven coordinates (`group:artifact:version`
or `group:artifact --to version`). Returns exit code 2 on HIGH/CRITICAL risk.

## `--pom-url`: analyze remote projects without cloning

Takes any `github.com` or `raw.githubusercontent.com` URL and does a blobless,
sparse, shallow clone of **only** the POM files. Even huge monorepos clone in
seconds because source files are never fetched.

Supported URL forms:
- `https://github.com/owner/repo` — repo root
- `https://github.com/owner/repo/tree/branch/path/to/module`
- `https://github.com/owner/repo/blob/branch/path/to/pom.xml`
- `https://raw.githubusercontent.com/owner/repo/branch/path/to/pom.xml`

```bash
depintel --pom-url https://github.com/apache/hadoop/tree/trunk/hadoop-common-project/hadoop-common conflicts
depintel --pom-url https://github.com/apache/druid/tree/master/extensions-core/avro-extensions audit
```

## Global flags

| Flag | Effect |
|------|--------|
| `--pom <path>` | Path to pom.xml or project directory (default: `.`) |
| `--pom-url <url>` | Fetch POMs from a GitHub URL |
| `--module <name>` | Focus on a specific module in a multi-module project |
| `--output json` | Machine-readable JSON output (default: `text`) |
| `--fresh` | Ignore Maven cache and re-run Maven |
| `--offline` | Strict offline mode — fail if anything is not cached |
| `--no-color` | Disable colored output |
| `--verbose` | Show additional detail |

## CI integration

Both `conflicts` and `audit` exit non-zero when they find something bad:

| Exit | Meaning |
|------|---------|
| 0 | Clean (or filtered result is empty) |
| 1 | Error (bad input, missing cache in `--offline`, network failure) |
| 2 | CI gate tripped — at least one HIGH/CRITICAL finding |

`bump` also returns exit code 2 on HIGH/CRITICAL risk.

Example GitHub Actions step:

```yaml
- name: Fail on HIGH/CRITICAL CVEs
  run: depintel --pom . audit --severity high
```

JSON output is stable and suitable for piping:

```bash
depintel --pom . --output json conflicts | jq '.[] | .conflicts[] | select(.severity=="HIGH")'
depintel --pom . --output json audit | jq '[.[] | .findings[] | .vulnerabilities[]] | length'
```

## Caching

Three independent caches, all keyed by POM content hash or repo coordinates:

1. **Git clone cache** (`--pom-url`): sparse checkout of POM files, reused across runs
2. **Maven output cache** (`.depintel/` inside each POM dir): parsed results of
   `dependency:tree`, `dependency:list`, `help:effective-pom`. Invalidated when
   the POM fingerprint changes
3. **OSV CVE cache** (user cache dir): 24h TTL per coordinate

| Flag | Behaviour |
|------|-----------|
| (default) | Prefer cache; fetch whatever's missing |
| `--offline` | Strict: never touch the network, fail if anything needed is missing |
| `--fresh` | Ignore Maven cache and re-run Maven (also re-clones for `--pom-url`) |
| `--fresh-cves` | Ignore OSV cache (applies to `audit` only) |

Warm runs are typically ~300ms; cold runs are bounded by Maven's own startup time.

## What depintel is not

- **Not a Maven replacement.** It runs Maven under the hood. If `mvn dependency:tree` fails in your project, depintel will fail too.
- **Not a JAR scanner.** It reads coordinates from `pom.xml`/effective-pom. It doesn't unpack JARs and can't detect shaded or repackaged dependencies.
- **Not a compliance tool** on its own. For SOC2/PCI scope, pair it with OWASP Dependency-Check or equivalent binary scanners.
- **Not multi-ecosystem.** Maven/Java only. No Gradle, Cargo, npm, etc.

## License

MIT
