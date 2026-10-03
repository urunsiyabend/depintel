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
        self.query_batch_at(queries, OSV_QUERYBATCH_URL, OSV_VULN_URL)
    }

    fn query_batch_at(
        &self,
        queries: &[OsvQuery],
        querybatch_url: &str,
        vuln_url: &str,
    ) -> Result<Vec<Vec<Vulnerability>>> {
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
                .post(querybatch_url)
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
            let mut id_cache: std::collections::HashMap<String, OsvVuln> =
                std::collections::HashMap::new();

            for (slot, batch_result) in chunk.iter().zip(resp.results.iter()) {
                let mut vulns: Vec<Vulnerability> = Vec::new();
                if let Some(ref ids) = batch_result.vulns {
                    for vuln_ref in ids {
                        let detail = if let Some(cached) = id_cache.get(&vuln_ref.id) {
                            cached.clone()
                        } else {
                            let detail = self
                                .fetch_vuln(&vuln_ref.id, vuln_url)
                                .with_context(|| format!("Failed to fetch {}", vuln_ref.id))?;
                            id_cache.insert(vuln_ref.id.clone(), detail.clone());
                            detail
                        };
                        if detail.withdrawn.is_some() {
                            continue;
                        }
                        // A shared advisory can specify different fixes for each package.
                        vulns.push(enrich_vuln(detail, &queries[*slot]));
                    }
                }
                self.cache.put(&queries[*slot].cache_key(), &vulns)?;
                results[*slot] = Some(vulns);
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap_or_default()).collect())
    }

    fn fetch_vuln(&self, id: &str, vuln_url: &str) -> Result<OsvVuln> {
        let url = format!("{}{}", vuln_url, id);
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

    // CVSS v3 has a zero base score when all three impact metrics are None,
    // regardless of exploitability. Do not let heuristic bonuses invent impact.
    if (score.starts_with("CVSS:3.0/") || score.starts_with("CVSS:3.1/"))
        && c == "N"
        && i == "N"
        && a == "N"
    {
        return Some(0.0);
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
    pub withdrawn: Option<String>,
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

    // Exercise the real HTTP/decode/enrichment/cache path without external services.
    fn fixture_server(
        replies: Vec<(&'static str, serde_json::Value)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            for (expected, body) in replies {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing request: {expected}");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(e) => panic!("accept failed: {e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break request.len();
                    }
                };
                let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
                assert!(headers.starts_with(expected), "{headers}");
                let content_length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body_bytes = vec![0; content_length];
                stream.read_exact(&mut body_bytes).unwrap();
                let body = body.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        (base, thread)
    }

    #[test]
    fn shared_advisory_keeps_fixed_versions_scoped_per_package() {
        let dir = tempfile::tempdir().unwrap();
        let client = OsvClient::new(OsvCache::in_directory(dir.path().to_path_buf()));
        let queries: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|artifact| OsvQuery {
                group: "org.example".into(),
                artifact: artifact.into(),
                version: "1.0".into(),
            })
            .collect();
        let (base, server) = fixture_server(vec![
            (
                "POST /querybatch ",
                serde_json::json!({"results": [
                    {"vulns": [{"id": "GHSA-shared"}]},
                    {"vulns": [{"id": "GHSA-shared"}]}
                ]}),
            ),
            (
                "GET /vulns/GHSA-shared ",
                serde_json::json!({
                    "id": "GHSA-shared",
                    "affected": [
                        {"package": {"ecosystem": "Maven", "name": "org.example:first"},
                         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]},
                        {"package": {"ecosystem": "Maven", "name": "org.example:second"},
                         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2"}]}]}
                    ]
                }),
            ),
        ]);
        let results = client
            .query_batch_at(
                &queries,
                &format!("{base}/querybatch"),
                &format!("{base}/vulns/"),
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(results[0][0].fixed_versions, vec!["1.1"]);
        assert_eq!(results[1][0].fixed_versions, vec!["2.2"]);
        // The per-coordinate disk entry must not perpetuate a different package's fix.
        let cached = client
            .query_batch_at(&queries, "http://127.0.0.1:0", "http://127.0.0.1:0")
            .unwrap();
        assert_eq!(cached[1][0].fixed_versions, vec!["2.2"]);
    }

    #[test]
    fn withdrawn_advisories_are_excluded_from_results_and_disk_cache() {
        let dir = tempfile::tempdir().unwrap();
        let client = OsvClient::new(OsvCache::in_directory(dir.path().to_path_buf()));
        let queries = vec![OsvQuery {
            group: "org.example".into(),
            artifact: "lib".into(),
            version: "1.0".into(),
        }];
        let (base, server) = fixture_server(vec![
            (
                "POST /querybatch ",
                serde_json::json!({"results": [{"vulns": [
                    {"id": "GHSA-withdrawn"}, {"id": "GHSA-active"}
                ]}]}),
            ),
            (
                "GET /vulns/GHSA-withdrawn ",
                serde_json::json!({
                    "id": "GHSA-withdrawn", "withdrawn": "2024-01-01T00:00:00Z",
                    "database_specific": {"severity": "CRITICAL"},
                    "affected": [{"package": {"ecosystem": "Maven", "name": "org.example:lib"}}]
                }),
            ),
            (
                "GET /vulns/GHSA-active ",
                serde_json::json!({
                    "id": "GHSA-active", "database_specific": {"severity": "LOW"},
                    "affected": [{"package": {"ecosystem": "Maven", "name": "org.example:lib"}}]
                }),
            ),
        ]);
        let results = client
            .query_batch_at(
                &queries,
                &format!("{base}/querybatch"),
                &format!("{base}/vulns/"),
            )
            .unwrap();
        server.join().unwrap();
        let ids: Vec<_> = results[0].iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["GHSA-active"]);
        let cached = client
            .query_batch_at(&queries, "http://127.0.0.1:0", "http://127.0.0.1:0")
            .unwrap();
        assert_eq!(cached[0].len(), 1);
        assert_eq!(cached[0][0].id, "GHSA-active");

        // Verify the report's actual serialized output and CI severity inputs too.
        let trees = crate::collector::verbose_tree::parse_verbose_tree(
            "[INFO] org.fixture:app:jar:1.0\n[INFO] \\- org.example:lib:jar:1.0:compile",
        )
        .unwrap();
        let graph = crate::graph::builder::build_graph(&trees[0]);
        let report = crate::audit::report::build_report(&graph, &client, false).unwrap();
        assert_eq!(report.summary.critical, 0);
        assert_eq!(report.summary.high, 0);
        assert_eq!(report.summary.low, 1);
        let output = serde_json::to_value(&report).unwrap();
        assert_eq!(
            output["findings"][0]["vulnerabilities"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            output["findings"][0]["vulnerabilities"][0]["id"],
            "GHSA-active"
        );
    }

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
    fn zero_impact_cvss_v3_is_not_reported_as_medium() {
        let query = OsvQuery {
            group: "org.example".to_string(),
            artifact: "lib".to_string(),
            version: "1.0".to_string(),
        };
        for version in ["3.0", "3.1"] {
            for scope in ["U", "C"] {
                let vector = format!("CVSS:{version}/AV:N/AC:L/PR:N/UI:N/S:{scope}/C:N/I:N/A:N");
                let raw: OsvVuln = serde_json::from_value(serde_json::json!({
                    "id": "GHSA-test",
                    "severity": [{"type": "CVSS_V3", "score": vector}],
                }))
                .unwrap();
                let vuln = enrich_vuln(raw, &query);
                assert_eq!(vuln.cvss_score, Some(0.0), "{vector}");
                assert_eq!(vuln.severity, VulnSeverity::Unknown, "{vector}");
            }
        }
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
