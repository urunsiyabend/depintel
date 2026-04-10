//! Risk scoring for a bump preview.
//!
//! Every rule that fires pushes a `reason` string into the output so the final
//! risk level is always *explained*. Never bucket without listing the signal
//! that drove it.

use serde::Serialize;

use crate::bump::diff::{any_critical_or_high_in, any_medium_in, CveDelta, GraphDiff};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    fn raise_to(self, target: RiskLevel) -> RiskLevel {
        if target > self {
            target
        } else {
            self
        }
    }

    fn down(self) -> RiskLevel {
        match self {
            RiskLevel::Critical => RiskLevel::High,
            RiskLevel::High => RiskLevel::Medium,
            RiskLevel::Medium => RiskLevel::Low,
            RiskLevel::Low => RiskLevel::Low,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    #[serde(rename = "basis")]
    pub basis: &'static str,
    pub reasons: Vec<String>,
}

pub struct VersionJumpInfo {
    pub major_jump: bool,
    pub minor_skipped: u32,
    pub is_downgrade: bool,
}

/// Parsed version: `(major, minor, patch, pre_rank)`.
/// `pre_rank = 0` means "stable release", higher values are progressively
/// *earlier* pre-releases (rc < beta < alpha < snapshot). Two stable releases
/// therefore compare by the numeric triple alone; a pre-release of the same
/// numeric version is *less than* the stable release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedVersion {
    major: u32,
    minor: u32,
    patch: u32,
    pre_rank: u32,
}

impl ParsedVersion {
    fn tuple(&self) -> (u32, u32, u32, i64) {
        // Invert pre_rank so that `pre_rank=0` (stable) sorts *after* any
        // pre-release for the same numeric triple.
        (self.major, self.minor, self.patch, -(self.pre_rank as i64))
    }
}

fn parse_semver(version: &str) -> ParsedVersion {
    // Strip a leading 'v' / 'V' so `v2.1.0` parses correctly.
    let v = version.strip_prefix(['v', 'V']).unwrap_or(version);

    // Split numeric head from pre-release tail. The tail starts at the first
    // character that is neither a digit nor a `.`.
    let split_idx = v
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
        .map(|(i, _)| i)
        .unwrap_or(v.len());
    let (num_part, tail) = v.split_at(split_idx);
    let tail = tail.trim_start_matches(|c: char| c == '-' || c == '.' || c == '_' || c == '+');

    let nums: Vec<u32> = num_part
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    let major = nums.first().copied().unwrap_or(0);
    let minor = nums.get(1).copied().unwrap_or(0);
    let patch = nums.get(2).copied().unwrap_or(0);

    let pre_rank = pre_rank(tail);

    ParsedVersion { major, minor, patch, pre_rank }
}

fn pre_rank(tail: &str) -> u32 {
    if tail.is_empty() {
        return 0;
    }
    let lc = tail.to_ascii_lowercase();
    // Higher = earlier (more risky). Ordered so that `rc > stable` is false:
    // stable=0 is the greatest via the inversion in `tuple()`.
    if lc.starts_with("rc") || lc.starts_with("cr") {
        1
    } else if lc.starts_with("m") && lc.chars().nth(1).map_or(false, |c| c.is_ascii_digit()) {
        // Milestone like "M1", "M2".
        2
    } else if lc.starts_with("beta") || lc.starts_with('b') {
        3
    } else if lc.starts_with("alpha") || lc.starts_with('a') {
        4
    } else if lc.starts_with("snapshot") {
        5
    } else {
        // Vendor qualifiers like "Final", "RELEASE", "GA" are effectively stable.
        if lc == "final" || lc == "release" || lc == "ga" {
            0
        } else {
            // Unknown qualifier — treat as slightly pre-release so downgrades
            // to it are still flagged, but not as risky as a SNAPSHOT.
            2
        }
    }
}

pub fn classify_version_jump(from: &str, to: &str) -> VersionJumpInfo {
    let f = parse_semver(from);
    let t = parse_semver(to);

    // SemVer-style: for 0.x, a minor bump is breaking, so treat it as a "major
    // jump" for risk-scoring purposes.
    let numeric_major_jump = f.major != t.major;
    let zerover_minor_jump = f.major == 0 && t.major == 0 && f.minor != t.minor;
    let major_jump = numeric_major_jump || zerover_minor_jump;

    let is_downgrade = t.tuple() < f.tuple();

    // Only report minor_skipped for same-major *forward* jumps; downgrades get
    // their own dedicated signal and shouldn't also be labelled "skipped N".
    let minor_skipped = if f.major == t.major && !is_downgrade && t.minor > f.minor {
        t.minor - f.minor
    } else {
        0
    };

    VersionJumpInfo {
        major_jump,
        minor_skipped,
        is_downgrade,
    }
}

pub struct ScoringInputs<'a> {
    pub from_version: &'a str,
    pub to_version: &'a str,
    pub scope: &'a str,
    pub graph_diff: &'a GraphDiff,
    pub conflicts_new_count: usize,
    pub conflicts_new_major_count: usize,
    pub cve_delta: &'a CveDelta,
    pub managed_override: bool,
}

pub fn score(inputs: &ScoringInputs) -> RiskAssessment {
    let mut level = RiskLevel::Low;
    let mut reasons: Vec<String> = Vec::new();

    let jump = classify_version_jump(inputs.from_version, inputs.to_version);

    // --- Version gap signals ---
    if jump.major_jump {
        level = level.raise_to(RiskLevel::High);
        let f = parse_semver(inputs.from_version);
        let t = parse_semver(inputs.to_version);
        if f.major == 0 && t.major == 0 {
            reasons.push(format!(
                "zerover_minor_change:0.{}→0.{}",
                f.minor, t.minor
            ));
        } else {
            reasons.push(format!(
                "major_version_change:{}→{}",
                f.major, t.major
            ));
        }
    } else if jump.minor_skipped >= 5 {
        level = level.raise_to(RiskLevel::High);
        reasons.push(format!("minor_versions_skipped_{}", jump.minor_skipped));
    } else if jump.minor_skipped >= 3 {
        level = level.raise_to(RiskLevel::Medium);
        reasons.push(format!("minor_versions_skipped_{}", jump.minor_skipped));
    }

    if jump.is_downgrade {
        level = level.raise_to(RiskLevel::High);
        reasons.push("downgrade".to_string());
    }

    // --- Conflict signals ---
    if inputs.conflicts_new_count > 0 {
        level = level.raise_to(RiskLevel::Medium);
        reasons.push(format!("new_conflicts_{}", inputs.conflicts_new_count));
    }
    if inputs.conflicts_new_major_count > 0 {
        level = level.raise_to(RiskLevel::High);
        reasons.push(format!(
            "new_conflicts_with_major_gap_{}",
            inputs.conflicts_new_major_count
        ));
    }

    // --- Dependency tree signals ---
    if !inputs.graph_diff.added.is_empty() {
        level = level.raise_to(RiskLevel::Medium);
        reasons.push(format!(
            "new_transitive_deps_{}",
            inputs.graph_diff.added.len()
        ));
    }
    if !inputs.graph_diff.removed.is_empty() {
        level = level.raise_to(RiskLevel::Medium);
        reasons.push(format!(
            "transitive_deps_removed_{}",
            inputs.graph_diff.removed.len()
        ));
    }

    // --- Scope / management drops come BEFORE CVE signals ---
    // The rationale: scope=test and managed_override are statements about *user
    // intent* ("this is a fixture / this was planned"). They legitimately reduce
    // the risk of a large version jump. But introducing a NEW CVE is always
    // worth flagging on its own merits, so CVE signals are applied last and
    // cannot be dropped away by intent modifiers.
    // Intent modifiers *cannot* erase a major version jump or a downgrade —
    // both are structural signals about the graph itself, not policy.
    let intent_modifiers_allowed = !jump.major_jump && !jump.is_downgrade;

    if inputs.scope == "test" && intent_modifiers_allowed {
        let before = level;
        level = level.down();
        if level != before {
            reasons.push("test_scope_only".to_string());
        }
    }
    if inputs.managed_override && intent_modifiers_allowed {
        let before = level;
        level = level.down();
        if level != before {
            reasons.push("managed_override".to_string());
        }
    }

    // --- CVE signals (final word) ---
    // A freshly-introduced HIGH/CRITICAL CVE is the only path to Critical.
    if any_critical_or_high_in(&inputs.cve_delta.introduced) {
        level = RiskLevel::Critical;
        reasons.push("cve_introduced_high_or_critical".to_string());
    } else if any_medium_in(&inputs.cve_delta.introduced) {
        level = level.raise_to(RiskLevel::Medium);
        reasons.push("cve_introduced_medium".to_string());
    }

    RiskAssessment {
        level,
        basis: "graph_only",
        reasons,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Action {
    RunTests {
        detail: String,
    },
    ReviewChangelog {
        detail: String,
    },
    CheckApiCompat {
        detail: String,
    },
    /// Emitted when BOM-mismatch detection fires (not yet implemented — placeholder
    /// for when we can read the effective POM's parent chain and spot cases where
    /// the consumer's BOM pins a different major of the bumped artifact).
    #[allow(dead_code)]
    BumpParentFirst {
        detail: String,
        artifact: String,
        suggested_version: Option<String>,
    },
    ManualReview {
        detail: String,
    },
}

pub fn recommended_actions(
    level: RiskLevel,
    from: &str,
    to: &str,
    cve_delta: &CveDelta,
) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::new();

    if level == RiskLevel::Critical {
        let mut detail = "Bump preview indicates CRITICAL graph-level risk".to_string();
        if any_critical_or_high_in(&cve_delta.introduced) {
            detail.push_str(" — a new HIGH/CRITICAL CVE is introduced by this target version");
        }
        out.push(Action::ManualReview { detail });
        out.push(Action::RunTests {
            detail: "mvn test".to_string(),
        });
        return out;
    }

    // Always: run tests.
    out.push(Action::RunTests {
        detail: "mvn test".to_string(),
    });

    let jump = classify_version_jump(from, to);

    if level >= RiskLevel::Medium || jump.minor_skipped >= 3 || jump.major_jump {
        out.push(Action::ReviewChangelog {
            detail: format!(
                "Review the changelog for {} → {}",
                from, to
            ),
        });
    }
    if level >= RiskLevel::High || jump.major_jump {
        out.push(Action::CheckApiCompat {
            detail: format!(
                "{} → {} spans versions likely to contain API signature changes",
                from, to
            ),
        });
    }

    out
}
