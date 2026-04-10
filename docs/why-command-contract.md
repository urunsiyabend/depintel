# `why` Command — API Contract

## Purpose

Answers: **"Why is this artifact in my dependency graph, at this version?"**

Three sub-questions, always answered together:

1. **How did it get here?** — All dependency paths leading to this artifact
2. **Which version was selected?** — The effective/resolved version
3. **Why that version?** — The resolution reason (nearest-wins, BOM override, dependencyManagement pin, etc.)

---

## CLI Interface

```
depintel why <group:artifact> [options]
```

### Examples

```bash
depintel why com.fasterxml.jackson.core:jackson-databind
depintel why org.yaml:snakeyaml --module auth-service
depintel why com.google.guava:guava --depth 5 --output json
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--module <name>` | root | Target module in multi-module project |
| `--depth <n>` | unlimited | Max path depth to display |
| `--output <format>` | `text` | `text` / `json` |
| `--all-versions` | false | Show all requested versions, not just selected |
| `--pom <path>` | `./pom.xml` | Root POM location |

---

## Output Contract — Text Format

```
WHY: com.fasterxml.jackson.core:jackson-databind

Selected version: 2.15.3
Scope: compile

Resolution reason:
  dependencyManagement pin in spring-boot-dependencies BOM (2.15.3)
  overrides 3 other requested versions

Requested versions:
  2.14.2  ← com.example:auth-service → kafka-clients:3.5.1 → jackson-databind
  2.15.3  ← com.example:app → spring-boot-starter-web → spring-web → jackson-databind
  2.15.0  ← com.example:app → some-lib:1.2.0 → jackson-databind
  2.13.5  ← com.example:data → legacy-sdk:4.0.0 → old-http:2.1 → jackson-databind

Dependency paths (4 found):

  [1] com.example:app
       └── org.springframework.boot:spring-boot-starter-web:3.2.2
            └── org.springframework:spring-web:6.1.3
                 └── com.fasterxml.jackson.core:jackson-databind:2.15.3 ✔ (selected)

  [2] com.example:auth-service
       └── org.apache.kafka:kafka-clients:3.5.1
            └── com.fasterxml.jackson.core:jackson-databind:2.14.2 ✘ (overridden)

  [3] com.example:app
       └── com.example:some-lib:1.2.0
            └── com.fasterxml.jackson.core:jackson-databind:2.15.0 ✘ (overridden)

  [4] com.example:data
       └── com.vendor:legacy-sdk:4.0.0
            └── com.vendor:old-http:2.1
                 └── com.fasterxml.jackson.core:jackson-databind:2.13.5 ✘ (overridden)

Warnings:
  ⚠ kafka-clients:3.5.1 was compiled against 2.14.x — version gap is 1 minor
  ⚠ legacy-sdk:4.0.0 was compiled against 2.13.x — version gap is 2 minor
```

---

## Output Contract — JSON Format

```json
{
  "query": "com.fasterxml.jackson.core:jackson-databind",
  "selected": {
    "group": "com.fasterxml.jackson.core",
    "artifact": "jackson-databind",
    "version": "2.15.3",
    "scope": "compile"
  },
  "resolution": {
    "reason": "dependency_management_pin",
    "source": {
      "type": "bom",
      "group": "org.springframework.boot",
      "artifact": "spring-boot-dependencies",
      "version": "3.2.2"
    }
  },
  "requested_versions": [
    {
      "version": "2.15.3",
      "status": "selected",
      "path": [
        "com.example:app",
        "org.springframework.boot:spring-boot-starter-web:3.2.2",
        "org.springframework:spring-web:6.1.3",
        "com.fasterxml.jackson.core:jackson-databind:2.15.3"
      ]
    },
    {
      "version": "2.14.2",
      "status": "overridden",
      "path": [
        "com.example:auth-service",
        "org.apache.kafka:kafka-clients:3.5.1",
        "com.fasterxml.jackson.core:jackson-databind:2.14.2"
      ]
    },
    {
      "version": "2.15.0",
      "status": "overridden",
      "path": [
        "com.example:app",
        "com.example:some-lib:1.2.0",
        "com.fasterxml.jackson.core:jackson-databind:2.15.0"
      ]
    },
    {
      "version": "2.13.5",
      "status": "overridden",
      "path": [
        "com.example:data",
        "com.vendor:legacy-sdk:4.0.0",
        "com.vendor:old-http:2.1",
        "com.fasterxml.jackson.core:jackson-databind:2.13.5"
      ]
    }
  ],
  "warnings": [
    {
      "type": "version_gap",
      "artifact": "org.apache.kafka:kafka-clients:3.5.1",
      "compiled_against": "2.14.x",
      "resolved_to": "2.15.3",
      "gap": "1 minor"
    },
    {
      "type": "version_gap",
      "artifact": "com.vendor:legacy-sdk:4.0.0",
      "compiled_against": "2.13.x",
      "resolved_to": "2.15.3",
      "gap": "2 minor"
    }
  ]
}
```

---

## Resolution Reasons (enum)

These are the possible values for `resolution.reason`:

| Value | Meaning |
|-------|---------|
| `nearest_wins` | Maven default: shortest path to root wins |
| `dependency_management_pin` | Pinned via `<dependencyManagement>` in current POM |
| `bom_pin` | Pinned via imported BOM |
| `parent_pin` | Pinned via parent POM's `<dependencyManagement>` |
| `direct_declaration` | Declared directly in `<dependencies>` |
| `first_declaration_wins` | Same depth, first in POM order wins |

Each reason must include `source` — which POM/BOM caused this resolution.

---

## Warnings (enum)

| Type | Trigger condition |
|------|-------------------|
| `version_gap` | A dependency was compiled against version X but resolved to Y where gap ≥ 1 minor |
| `major_version_mismatch` | Resolved version has different major than what a consumer expects |
| `scope_mismatch` | Artifact appears in multiple scopes (e.g., compile + runtime) |
| `multiple_paths_same_version` | Same version pulled from 3+ independent paths (info, not warning) |

---

## Edge Cases

### Artifact not found
```json
{
  "query": "com.example:nonexistent",
  "error": "not_found",
  "message": "Artifact not present in dependency graph"
}
```

Exit code: 1

### Artifact found only in test scope
Normal output, but `scope: "test"` and paths show test-only routes.

### Multi-module: artifact in some modules but not others

**Default behavior (no `--module` flag): scan all modules, show summary grouped by module.**

This is the correct default because when someone asks "why is jackson-databind here?", they want the full picture — not just the root module. Conflicts typically surface in non-root modules.

#### Default output (summary view)

```
WHY: com.fasterxml.jackson.core:jackson-databind

Found in 3 modules:

  Module: app
    Selected: 2.15.3 (BOM pin)
    Paths: 2

  Module: auth-service
    Selected: 2.15.3 (BOM pin)
    Paths: 1
    ⚠ kafka-clients compiled against 2.14.x

  Module: data
    Selected: 2.15.3 (BOM pin)
    Paths: 1
    ⚠ legacy-sdk compiled against 2.13.x

Run with --module <name> for full path details.
```

#### Focused output (`--module auth-service`)

When `--module` is specified, show full path details for that module only (same as the single-module output format defined above).

#### JSON: default multi-module structure

```json
{
  "query": "com.fasterxml.jackson.core:jackson-databind",
  "modules": [
    {
      "module": "com.example:app",
      "selected": {
        "version": "2.15.3",
        "scope": "compile"
      },
      "resolution": {
        "reason": "bom_pin",
        "source": { "type": "bom", "artifact": "spring-boot-dependencies", "version": "3.2.2" }
      },
      "requested_versions": [ ... ],
      "warnings": []
    },
    {
      "module": "com.example:auth-service",
      "selected": {
        "version": "2.15.3",
        "scope": "compile"
      },
      "resolution": {
        "reason": "bom_pin",
        "source": { "type": "bom", "artifact": "spring-boot-dependencies", "version": "3.2.2" }
      },
      "requested_versions": [ ... ],
      "warnings": [
        {
          "type": "version_gap",
          "artifact": "org.apache.kafka:kafka-clients:3.5.1",
          "compiled_against": "2.14.x",
          "resolved_to": "2.15.3",
          "gap": "1 minor"
        }
      ]
    }
  ]
}
```

#### Performance note

All modules are scanned in parallel. `--module` is a **display filter**, not a performance optimization — the engine resolves the full graph regardless. This keeps the architecture simple and ensures warnings that span modules are never missed.

#### Module not found

```json
{
  "query": "com.fasterxml.jackson.core:jackson-databind",
  "error": "module_not_found",
  "message": "Module 'payments' not found. Available: app, auth-service, data"
}
```

Exit code: 1

---

## What `why` Does NOT Do

- Does not fetch from Maven Central (works on local graph only)
- Does not suggest fixes (that's `impact` or `exclude-candidates`)
- Does not show the full tree (that's `tree`)
- Does not detect unused dependencies (that's `exclude-candidates`)

`why` is read-only, fast, and explanatory. It answers one question well.

---

## Internal Requirements

To produce this output, the engine needs:

1. **POM parser** — read `pom.xml`, resolve `<parent>`, `<dependencyManagement>`, `<properties>`, BOM imports
2. **Graph builder** — build full transitive dependency graph with all versions requested
3. **Resolution simulator** — apply Maven's mediation rules to determine selected version + reason
4. **Path tracer** — find all paths from root(s) to target artifact
5. **Warning generator** — compare compiled-against vs resolved versions

### Resolution order (must match Maven semantics)

```
1. dependencyManagement / BOM pin  →  always wins
2. nearest definition              →  shortest path to root
3. first declaration               →  same depth, POM order
```

This is the core of Maven's dependency mediation. Get this right and everything else follows.
