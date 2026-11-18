//! Output event formats: native, OCSF (Detection Finding) and ECS.
//!
//! No raw excerpt of the scanned content is ever included: SIEM-side LLM
//! assistants could read it back and be poisoned in turn.

use serde_json::{json, Value};

use crate::rules::Severity;
use crate::scan::{ScanReport, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Native,
    Ocsf,
    Ecs,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "native" | "json" => Ok(Format::Native),
            "ocsf" => Ok(Format::Ocsf),
            "ecs" => Ok(Format::Ecs),
            _ => Err(format!("unknown format {s:?} (native|ocsf|ecs)")),
        }
    }
}

fn max_severity(r: &ScanReport) -> Severity {
    r.findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Info)
}

fn ocsf_severity_id(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "Informational",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn techniques(r: &ScanReport) -> Vec<String> {
    let mut t: Vec<String> = r.findings.iter().flat_map(|f| f.mitre.iter().cloned()).collect();
    t.push("AML.T0070".into());
    t.sort();
    t.dedup();
    t
}

/// Render one report. `time_ms` is the event time (Unix epoch, milliseconds),
/// passed in by the caller since the core performs no I/O (including clocks).
pub fn render(r: &ScanReport, format: Format, time_ms: i64) -> Value {
    match format {
        Format::Native => json!({ "schema": crate::OUTPUT_SCHEMA, "time": time_ms, "report": r }),
        Format::Ocsf => ocsf(r, time_ms),
        Format::Ecs => ecs(r, time_ms),
    }
}

/// OCSF 1.x, class Detection Finding (2004).
fn ocsf(r: &ScanReport, time_ms: i64) -> Value {
    let sev = max_severity(r);
    let action_id = match r.verdict {
        Verdict::Allow => 1,
        Verdict::Flag => 1,
        Verdict::Quarantine => 2,
    };
    json!({
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "time": time_ms,
        "severity_id": ocsf_severity_id(sev),
        "severity": severity_name(sev),
        "status_id": 1,
        "action_id": action_id,
        "risk_score": r.score,
        "metadata": {
            "version": "1.3.0",
            "product": { "name": "poisonscan", "vendor_name": "poisonscan project", "version": env!("CARGO_PKG_VERSION") },
            "labels": [format!("verdict:{:?}", r.verdict).to_lowercase(), format!("rules:{}", r.rules_fingerprint)]
        },
        "finding_info": {
            "uid": format!("{}:{}", r.document_id, r.content_sha),
            "title": r.findings.first().map(|f| f.title.as_str()).unwrap_or("No finding"),
            "types": ["Collection-to-LLM poisoning"],
            "analytic": { "type_id": 1, "type": "Rule", "uid": r.findings.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>().join(",") },
            "attacks": techniques(r).iter().map(|t| json!({ "technique": { "uid": t }, "tactic": { "name": "MITRE ATLAS" } })).collect::<Vec<_>>()
        },
        "resources": [{
            "uid": r.document_id,
            "type": r.source_type,
            "name": r.source_uri,
            "data": { "content_xxh3": r.content_sha, "truncated": r.truncated }
        }],
        "unmapped": { "poisonscan": { "findings": r.findings } }
    })
}

/// Elastic Common Schema 8.x.
fn ecs(r: &ScanReport, time_ms: i64) -> Value {
    let sev = max_severity(r);
    json!({
        "@timestamp": time_ms,
        "ecs": { "version": "8.11.0" },
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["indicator"],
            "action": format!("{:?}", r.verdict).to_lowercase(),
            "module": "poisonscan",
            "dataset": "poisonscan.finding",
            "severity": ocsf_severity_id(sev),
            "risk_score": r.score,
            "hash": r.content_sha
        },
        "rule": {
            "id": r.findings.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>().join(","),
            "name": r.findings.first().map(|f| f.title.as_str()).unwrap_or("No finding"),
            "ruleset": r.rules_fingerprint
        },
        "threat": {
            "framework": "MITRE ATLAS",
            "technique": { "id": techniques(r) }
        },
        "url": { "original": r.source_uri },
        "labels": { "document_id": r.document_id, "source_type": r.source_type, "truncated": r.truncated },
        "poisonscan": { "findings": r.findings }
    })
}
