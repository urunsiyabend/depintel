use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::audit::cache::OsvCache;

const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns/";

/// Severity bucket for display + filtering. Mirrors CVSS thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VulnSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnSeverity::Critical => "CRITICAL",
            VulnSeverity::High => "HIGH",
            VulnSeverity::Medium => "MEDIUM",
            VulnSeverity::Low => "LOW",
            VulnSeverity::Unknown => "UNKNOWN",
        }
    }

    pub fn from_cvss_score(score: f64) -> Self {
        if score >= 9.0 {
            VulnSeverity::Critical
        } else if score >= 7.0 {
            VulnSeverity::High
        } else if score >= 4.0 {
            VulnSeverity::Medium
        } else if score > 0.0 {
            VulnSeverity::Low
        } else {
            VulnSeverity::Unknown
        }
    }

    /// Parse a label like "HIGH" or "MODERATE" coming from GHSA database_specific.
    pub fn from_label(label: &str) -> Self {
        match label.to_uppercase().as_str() {
            "CRITICAL" => VulnSeverity::Critical,
            "HIGH" => VulnSeverity::High,
            "MEDIUM" | "MODERATE" => VulnSeverity::Medium,
            "LOW" => VulnSeverity::Low,
            _ => VulnSeverity::Unknown,
        }
    }
}

/// A single vulnerability after we've enriched the OSV record into something usable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: VulnSeverity,
    /// Best-effort CVSS base score if we could parse one.
    pub cvss_score: Option<f64>,
    /// Versions OSV says fix this vulnerability for the affected package.
    pub fixed_versions: Vec<String>,
    /// Source DB names (e.g., "GHSA", "NVD").
    pub sources: Vec<String>,
}

/// Query argument: identifies one (Maven coordinate, version) pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsvQuery {
    pub group: String,
    pub artifact: String,
    pub version: String,
}

impl OsvQuery {
    pub fn maven_name(&self) -> String {
        format!("{}:{}", self.group, self.artifact)
    }
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.maven_name(), self.version)
    }
}

/// HTTP client over OSV.dev with on-disk caching.
pub struct OsvClient {
    agent: ureq::Agent,
    cache: OsvCache,
}

impl OsvClient {
    pub fn new(cache: OsvCache) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("depintel/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent, cache }
    }

    /// Look up vulnerabilities for many (group, artifact, version) tuples in one shot.
    /// Returns a vector aligned with `queries`: result[i] is the list of vulns for queries[i].
    /// Cached results are returned without hitting the network.
    pub fn query_batch(&self, queries: &[OsvQuery]) -> Result<Vec<Vec<Vulnerability>>> {
        // First pass: collect cache hits and remember which queries still need fetching.
        let mut results: Vec<Option<Vec<Vulnerability>>> = vec![None; queries.len()];
        let mut to_fetch_idx: Vec<usize> = Vec::new();
        for (i, q) in queries.iter().enumerate() {
            match self.cache.get(&q.cache_key())? {
                Some(cached) => results[i] = Some(cached),
                None => to_fetch_idx.push(i),
            }
        }

        if to_fetch_idx.is_empty() {
            return Ok(results.into_iter().map(|r| r.unwrap_or_default()).collect());
        }

        eprintln!(
            "Querying OSV.dev for {} artifacts ({} cached)...",
            to_fetch_idx.len(),
            queries.len() - to_fetch_idx.len()
        );

        // OSV's batch endpoint accepts up to ~1000 queries; chunk to be safe.
        const BATCH_SIZE: usize = 500;
        for chunk in to_fetch_idx.chunks(BATCH_SIZE) {
            let body = build_querybatch_body(chunk.iter().map(|&i| &queries[i]));
            let resp: QueryBatchResponse = self
                .agent
                .post(OSV_QUERYBATCH_URL)
                .send_json(body)
                .context("OSV /v1/querybatch failed")?
                .into_json()
                .context("Failed to decode OSV /v1/querybatch response")?;

            if resp.results.len() != chunk.len() {
                anyhow::bail!(
                    "OSV returned {} results for {} queries — protocol mismatch",
                    resp.results.len(),
                    chunk.len()
                );
            }

            // For each query in this chunk, OSV gives us only vuln IDs.
            // Fetch full details for each unique ID and assemble the per-query result.
            let mut id_cache: std::collections::HashMap<String, Vulnerability> =
                std::collections::HashMap::new();

            for (slot, batch_result) in chunk.iter().zip(resp.results.iter()) {
                let mut vulns: Vec<Vulnerability> = Vec::new();
                if let Some(ref ids) = batch_result.vulns {
                    for vuln_ref in ids {
                        let v = if let Some(cached) = id_cache.get(&vuln_ref.id) {
                            cached.clone()
                        } else {
                            let detail = self
                                .fetch_vuln(&vuln_ref.id)
                                .with_context(|| format!("Failed to fetch {}", vuln_ref.id))?;
                            let v = enrich_vuln(detail, &queries[*slot]);
                            id_cache.insert(vuln_ref.id.clone(), v.clone());
                            v
                        };
                        vulns.push(v);
                    }
                }
                self.cache.put(&queries[*slot].cache_key(), &vulns)?;
                results[*slot] = Some(vulns);
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap_or_default()).collect())
    }

    fn fetch_vuln(&self, id: &str) -> Result<OsvVuln> {
        let url = format!("{}{}", OSV_VULN_URL, id);
        let resp: OsvVuln = self
            .agent
            .get(&url)
            .call()
            .with_context(|| format!("GET {}", url))?
            .into_json()
            .with_context(|| format!("Decode {}", url))?;
        Ok(resp)
    }
}

fn build_querybatch_body<'a>(queries: impl Iterator<Item = &'a OsvQuery>) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = queries
        .map(|q| {
            serde_json::json!({
                "package": {
                    "ecosystem": "Maven",
                    "name": q.maven_name(),
                },
                "version": q.version,
            })
        })
        .collect();
    serde_json::json!({ "queries": arr })
}

/// Convert a raw OSV vuln record into our cleaner internal form, scoped to a particular query.
fn enrich_vuln(raw: OsvVuln, query: &OsvQuery) -> Vulnerability {
    // Severity: prefer CVSS_V3 score; fall back to database_specific.severity label.
    let mut cvss_score: Option<f64> = None;
    let mut severity = VulnSeverity::Unknown;
    if let Some(ref sevs) = raw.severity {
        for s in sevs {
            if s.r#type.eq_ignore_ascii_case("CVSS_V3") || s.r#type.eq_ignore_ascii_case("CVSS_V4")
            {
                if let Some(score) = parse_cvss_base_score(&s.score) {
                    cvss_score = Some(score);
                    severity = VulnSeverity::from_cvss_score(score);
                    break;
                }
            }
        }
    }
    if matches!(severity, VulnSeverity::Unknown) {
        if let Some(ref ds) = raw.database_specific {
            if let Some(label) = ds.get("severity").and_then(|v| v.as_str()) {
                severity = VulnSeverity::from_label(label);
            }
        }
    }

    // Fixed versions: pull from `affected[*].ranges[*].events` where event.fixed is set,
    // restricted to entries that match this artifact.
    let mut fixed_versions: Vec<String> = Vec::new();
    if let Some(ref affected) = raw.affected {
        for aff in affected {
            let matches = aff
                .package
                .as_ref()
                .map(|p| {
                    p.ecosystem.eq_ignore_ascii_case("Maven")
                        && p.name.eq_ignore_ascii_case(&query.maven_name())
                })
                .unwrap_or(false);
            if !matches {
                continue;
            }
            if let Some(ref ranges) = aff.ranges {
                for range in ranges {
                    if let Some(ref events) = range.events {
                        for ev in events {
                            if let Some(ref fixed) = ev.fixed {
                                if !fixed_versions.contains(fixed) {
                                    fixed_versions.push(fixed.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fixed_versions.sort();

    // Sources: distinct values of `database_specific.source` plus the prefix of the ID.
    let mut sources: Vec<String> = Vec::new();
    let prefix: String = raw.id.split('-').next().unwrap_or("").to_string();
    if !prefix.is_empty() && !sources.contains(&prefix) {
        sources.push(prefix);
    }
    if let Some(ref aliases) = raw.aliases {
        for a in aliases {
            let p: String = a.split('-').next().unwrap_or("").to_string();
            if !p.is_empty() && !sources.contains(&p) && p != raw.id {
                sources.push(p);
            }
        }
    }

    Vulnerability {
        id: raw.id,
        aliases: raw.aliases.unwrap_or_default(),
        summary: raw.summary.unwrap_or_else(|| "(no summary)".to_string()),
        severity,
        cvss_score,
        fixed_versions,
        sources,
    }
}

/// Extract the base score from a CVSS vector string like "CVSS:3.1/AV:N/...".
/// We don't fully parse the vector; instead we look for an explicit score field
/// or fall back to crude heuristics. OSV typically supplies the vector, not the
/// pre-computed score. To keep this dependency-free, we apply a small lookup
/// against well-known severity letters as a backup.
fn parse_cvss_base_score(score: &str) -> Option<f64> {
    // Some OSV records put a numeric score directly here.
    if let Ok(n) = score.parse::<f64>() {
        return Some(n);
    }
    // Otherwise it's a vector. Try to read AV/AC/PR/UI/S/C/I/A and rebuild a score.
    // This is intentionally a coarse approximation — good enough to bucket into
    // CRITICAL/HIGH/MEDIUM/LOW for triage, not for exact reporting.
    let mut metrics = std::collections::HashMap::new();
    for part in score.split('/').skip(1) {
        if let Some((k, v)) = part.split_once(':') {
            metrics.insert(k.to_string(), v.to_string());
        }
    }
    let av = metrics.get("AV").map(String::as_str).unwrap_or("");
    let ac = metrics.get("AC").map(String::as_str).unwrap_or("");
    let pr = metrics.get("PR").map(String::as_str).unwrap_or("");
    let ui = metrics.get("UI").map(String::as_str).unwrap_or("");
    let c = metrics.get("C").map(String::as_str).unwrap_or("");
    let i = metrics.get("I").map(String::as_str).unwrap_or("");
    let a = metrics.get("A").map(String::as_str).unwrap_or("");

    if av.is_empty() && c.is_empty() {
        return None;
    }

    // Approximate base impact: HIGH on any of C/I/A → strong contribution.
    let impact_count = [c, i, a].iter().filter(|x| **x == "H").count();
    let mut score: f64 = match impact_count {
        3 => 9.0,
        2 => 7.5,
        1 => 6.0,
        _ => 3.5,
    };

    // Network attack vector + low complexity + no privileges = bump.
    if av == "N" {
        score += 0.5;
    }
    if ac == "L" {
        score += 0.3;
    }
    if pr == "N" {
        score += 0.4;
    }
    if ui == "N" {
        score += 0.3;
    }

    Some(score.min(10.0))
}

// --- Wire types matching OSV API responses ---

#[derive(Debug, Deserialize)]
struct QueryBatchResponse {
    results: Vec<QueryBatchResult>,
}

#[derive(Debug, Deserialize)]
struct QueryBatchResult {
    vulns: Option<Vec<VulnRef>>,
}

#[derive(Debug, Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub aliases: Option<Vec<String>>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    pub affected: Option<Vec<OsvAffected>>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsvSeverity {
    pub r#type: String,
    pub score: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsvRange {
    #[serde(default)]
    pub events: Option<Vec<OsvEvent>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_from_score_buckets() {
        assert_eq!(VulnSeverity::from_cvss_score(9.8), VulnSeverity::Critical);
        assert_eq!(VulnSeverity::from_cvss_score(7.5), VulnSeverity::High);
        assert_eq!(VulnSeverity::from_cvss_score(5.0), VulnSeverity::Medium);
        assert_eq!(VulnSeverity::from_cvss_score(2.0), VulnSeverity::Low);
        assert_eq!(VulnSeverity::from_cvss_score(0.0), VulnSeverity::Unknown);
    }

    #[test]
    fn severity_from_label() {
        assert_eq!(VulnSeverity::from_label("HIGH"), VulnSeverity::High);
        assert_eq!(VulnSeverity::from_label("moderate"), VulnSeverity::Medium);
        assert_eq!(VulnSeverity::from_label("CRITICAL"), VulnSeverity::Critical);
    }

    #[test]
    fn cvss_vector_parses_to_high_for_log4shell_pattern() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H is Log4Shell, score 10.0
        let s = parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert!(s >= 9.0, "expected critical-tier, got {}", s);
    }

    #[test]
    fn querybatch_body_shape() {
        let q = OsvQuery {
            group: "org.apache.logging.log4j".to_string(),
            artifact: "log4j-core".to_string(),
            version: "2.14.1".to_string(),
        };
        let body = build_querybatch_body(std::iter::once(&q));
        assert_eq!(body["queries"][0]["package"]["ecosystem"], "Maven");
        assert_eq!(
            body["queries"][0]["package"]["name"],
            "org.apache.logging.log4j:log4j-core"
        );
        assert_eq!(body["queries"][0]["version"], "2.14.1");
    }
}
