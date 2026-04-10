# `conflicts` Command — API Contract

## Purpose

Answers: **"Where do dependency version conflicts exist, and how were they resolved?"**

A "conflict" means: the same artifact is requested at 2+ different versions across the dependency graph. Maven silently picks one. This command surfaces all such decisions with full explanation.

This is different from `why`:
- `why` starts from **one artifact** and explains it
- `conflicts` scans the **entire graph** and finds all disagreements

---

## CLI Interface

```
depintel conflicts [options]
```

### Examples

```bash
depintel conflicts
depintel conflicts --module auth-service
depintel conflicts --severity high
depintel conflicts --output json
depintel conflicts --group com.fasterxml.jackson
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--module <name>` | all | Scope to a single module |
| `--severity <level>` | all | Filter: `low` / `medium` / `high` |
| `--group <prefix>` | all | Filter by groupId prefix |
| `--output <format>` | `text` | `text` / `json` |
| `--pom <path>` | `./pom.xml` | Root POM location |
| `--include-managed` | false | Also show conflicts resolved by dependencyManagement (normally silent) |

---

## Core Concept: What counts as a conflict?

```
Conflict = same (groupId, artifactId) requested at 2+ distinct versions
```

Every conflict has:
- **Requested versions** — which versions were asked for, by whom
- **Selected version** — which one Maven actually uses
- **Resolution reason** — why that version won
- **Severity** — how risky this resolution is

### What is NOT a conflict

- Same version from multiple paths → not a conflict (info only, shown with `--verbose`)
- Different classifiers (e.g., `sources`, `javadoc`) → different artifacts, not a conflict
- Different scopes requesting same version → scope merge, not a version conflict

---

## Severity Scoring

| Severity | Condition |
|----------|-----------|
| `high` | Major version mismatch between requested versions (e.g., 1.x vs 2.x) |
| `high` | Selected version is OLDER than what a consumer was compiled against |
| `medium` | Minor version gap ≥ 2 (e.g., 2.13 vs 2.16) |
| `medium` | Conflict resolved by nearest-wins overriding a dependencyManagement pin |
| `low` | Patch-level differences only (e.g., 2.15.2 vs 2.15.3) |
| `low` | All requested versions are within 1 minor of each other |

Severity is per-conflict, not per-project.

---

## Output Contract — Text Format

```
DEPENDENCY CONFLICTS
════════════════════

Found 3 conflicts (1 high, 1 medium, 1 low)

──────────────────────────────────────────────

[HIGH] com.fasterxml.jackson.core:jackson-databind

  Requested versions:
    2.15.3  ← app → spring-boot-starter-web → spring-web
    2.14.2  ← auth-service → kafka-clients:3.5.1
    2.13.5  ← data → legacy-sdk:4.0.0 → old-http:2.1

  Selected: 2.15.3
  Reason:   BOM pin (spring-boot-dependencies:3.2.2)

  ⚠ kafka-clients:3.5.1 compiled against 2.14.x — 1 minor gap
  ⚠ legacy-sdk:4.0.0 compiled against 2.13.x — 2 minor gap

──────────────────────────────────────────────

[MEDIUM] org.slf4j:slf4j-api

  Requested versions:
    2.0.9   ← app → spring-boot-starter-web → spring-boot-starter-logging
    1.7.36  ← data → legacy-sdk:4.0.0

  Selected: 2.0.9
  Reason:   nearest definition (depth 3 vs depth 4)

  ⚠ MAJOR version mismatch: legacy-sdk expects 1.x, resolved to 2.x

──────────────────────────────────────────────

[LOW] commons-codec:commons-codec

  Requested versions:
    1.16.0  ← app → httpclient5:5.2
    1.15    ← auth-service → some-sdk:2.0 → httpclient:4.5.14

  Selected: 1.16.0
  Reason:   nearest definition (depth 2 vs depth 3)

──────────────────────────────────────────────

Summary:
  Total conflicts:  3
  High severity:    1
  Medium severity:  1
  Low severity:     1
```

---

## Output Contract — JSON Format

```json
{
  "summary": {
    "total": 3,
    "high": 1,
    "medium": 1,
    "low": 1
  },
  "conflicts": [
    {
      "group": "com.fasterxml.jackson.core",
      "artifact": "jackson-databind",
      "severity": "high",
      "selected": {
        "version": "2.15.3",
        "reason": "bom_pin",
        "source": {
          "type": "bom",
          "artifact": "spring-boot-dependencies",
          "version": "3.2.2"
        }
      },
      "requested": [
        {
          "version": "2.15.3",
          "status": "selected",
          "shortest_path": [
            "com.example:app",
            "spring-boot-starter-web:3.2.2",
            "spring-web:6.1.3",
            "jackson-databind:2.15.3"
          ]
        },
        {
          "version": "2.14.2",
          "status": "overridden",
          "shortest_path": [
            "com.example:auth-service",
            "kafka-clients:3.5.1",
            "jackson-databind:2.14.2"
          ]
        },
        {
          "version": "2.13.5",
          "status": "overridden",
          "shortest_path": [
            "com.example:data",
            "legacy-sdk:4.0.0",
            "old-http:2.1",
            "jackson-databind:2.13.5"
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
    },
    {
      "group": "org.slf4j",
      "artifact": "slf4j-api",
      "severity": "medium",
      "selected": {
        "version": "2.0.9",
        "reason": "nearest_wins",
        "source": {
          "type": "path_depth",
          "selected_depth": 3,
          "overridden_depth": 4
        }
      },
      "requested": [
        {
          "version": "2.0.9",
          "status": "selected",
          "shortest_path": [
            "com.example:app",
            "spring-boot-starter-web:3.2.2",
            "spring-boot-starter-logging:3.2.2",
            "slf4j-api:2.0.9"
          ]
        },
        {
          "version": "1.7.36",
          "status": "overridden",
          "shortest_path": [
            "com.example:data",
            "legacy-sdk:4.0.0",
            "slf4j-api:1.7.36"
          ]
        }
      ],
      "warnings": [
        {
          "type": "major_version_mismatch",
          "artifact": "com.vendor:legacy-sdk:4.0.0",
          "compiled_against": "1.x",
          "resolved_to": "2.x"
        }
      ]
    },
    {
      "group": "commons-codec",
      "artifact": "commons-codec",
      "severity": "low",
      "selected": {
        "version": "1.16.0",
        "reason": "nearest_wins",
        "source": {
          "type": "path_depth",
          "selected_depth": 2,
          "overridden_depth": 3
        }
      },
      "requested": [
        {
          "version": "1.16.0",
          "status": "selected",
          "shortest_path": [
            "com.example:app",
            "httpclient5:5.2",
            "commons-codec:1.16.0"
          ]
        },
        {
          "version": "1.15",
          "status": "overridden",
          "shortest_path": [
            "com.example:auth-service",
            "some-sdk:2.0",
            "httpclient:4.5.14",
            "commons-codec:1.15"
          ]
        }
      ],
      "warnings": []
    }
  ]
}
```

---

## Resolution Reasons

Same enum as `why` command — shared across the tool:

| Value | Meaning |
|-------|---------|
| `nearest_wins` | Shortest path to root wins |
| `dependency_management_pin` | Pinned in current POM's `<dependencyManagement>` |
| `bom_pin` | Pinned via imported BOM |
| `parent_pin` | Pinned via parent POM |
| `direct_declaration` | Explicitly declared in `<dependencies>` |
| `first_declaration_wins` | Same depth, first in POM order wins |

---

## Multi-Module Behavior

Same principle as `why`:

- **Default:** scan all modules, report conflicts per-module and cross-module
- **`--module <name>`:** focus on one module only

### Cross-module conflicts

A conflict can exist **within** a module (two paths in the same module request different versions) or **across** modules (module A resolves to 2.15, module B resolves to 2.14 — both are "correct" per Maven, but inconsistent across the project).

Cross-module inconsistency is surfaced as a separate section:

```
CROSS-MODULE INCONSISTENCIES
─────────────────────────────

com.fasterxml.jackson.core:jackson-databind
  app:           2.15.3 (BOM pin)
  auth-service:  2.15.3 (BOM pin)
  legacy-batch:  2.14.2 (no BOM, nearest-wins)
  ⚠ legacy-batch resolves to a different version than the rest of the project
```

JSON: add `"cross_module_inconsistencies"` array at root level.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No conflicts found (or all low severity) |
| 1 | Error (bad POM, module not found, etc.) |
| 2 | Medium severity conflicts found |
| 3 | High severity conflicts found |

This makes CI integration simple:

```yaml
# fail pipeline on high-severity conflicts
- run: depintel conflicts --severity high && echo "clean" || exit 1
```

---

## `--include-managed` Flag

By default, `conflicts` only shows cases where Maven had to **choose** between competing versions. If a BOM or dependencyManagement pins a version and no other version is even requested, there's no conflict — that's just normal resolution.

With `--include-managed`, the output also includes artifacts where dependencyManagement overrode what a transitive dependency originally requested. This is useful for auditing BOM effects:

```
[MANAGED] org.springframework:spring-core

  dependencyManagement pins: 6.1.3
  Transitive request:        6.0.12 (via legacy-spring-lib:1.2)

  This is not a conflict — dependencyManagement always wins.
  Shown because --include-managed is set.
```

---

## Relationship to Other Commands

| Want to know... | Use |
|-----------------|-----|
| "Why is artifact X at version Y?" | `why` |
| "What conflicts exist in my project?" | `conflicts` |
| "What happens if I update X?" | `impact` |
| "What can I safely exclude?" | `exclude-candidates` |

`conflicts` is a **discovery** command — it finds problems.
`why` is an **explanation** command — it explains one artifact.

Typical workflow:
```
depintel conflicts          → "I have 3 conflicts"
depintel why jackson-databind   → "here's exactly why"
depintel impact jackson-databind:2.16.0  → "here's what updating would change"
```

---

## What `conflicts` Does NOT Do

- Does not suggest which version to pick (that's `impact`)
- Does not detect unused dependencies (that's `exclude-candidates`)
- Does not resolve conflicts automatically
- Does not fetch from Maven Central

`conflicts` is read-only, fast, and diagnostic. It finds disagreements and explains how Maven resolved them.

---

## Internal Requirements

Shares the same engine as `why`:

1. **POM parser** — same as `why`
2. **Graph builder** — same as `why`, but now must retain ALL requested versions (not just selected)
3. **Resolution simulator** — same as `why`
4. **Conflict detector** — group by (groupId, artifactId), filter where distinct version count ≥ 2
5. **Severity scorer** — apply severity rules from the table above
6. **Cross-module comparator** — compare selected versions across modules

Key insight: `conflicts` is essentially `why` run for every artifact, filtered to only those with version disagreements. If `why` works correctly, `conflicts` is mostly a loop + filter + sort.
