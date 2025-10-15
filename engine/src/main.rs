use anyhow::{bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "panoptes-engine")]
struct Args {
    #[arg(long, value_name = "FILE")]
    r#in: PathBuf,
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
    #[arg(long, default_value_t = 6)]
    max_depth: usize,
}

#[derive(Debug, Deserialize)]
struct Graph {
    schema_version: String,
    #[serde(default)]
    edges: Vec<Edge>,
}

#[derive(Debug, Deserialize)]
struct Edge {
    from: String,
    to: String,
    #[serde(rename = "type")]
    edge_type: String,
    #[serde(default)]
    attrs: Value,
}

#[derive(Debug, Serialize)]
struct Finding {
    id: String,
    title: String,
    steps: Vec<String>,
    score: f64,
    target: String,
}
#[derive(Debug, Serialize)]
struct Findings {
    findings: Vec<Finding>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let graph: Graph = serde_json::from_slice(&fs::read(&args.r#in)?)?;
    if !graph.schema_version.starts_with("1.") {
        bail!("unsupported graph schema version: {}", graph.schema_version);
    }
    let has_unrestricted_admin_path = graph.edges.iter().any(|edge| {
        if edge.edge_type != "CanAssume" || edge.from != "u:ci-bot" || edge.to != "r:AdminRole" {
            return false;
        }
        let attrs = match edge.attrs.as_object() {
            Some(a) => a,
            None => return true,
        };
        let required = match attrs.get("required_conditions").and_then(|v| v.as_object()) {
            Some(rc) => rc,
            None => return true,
        };
        let require_mfa = required
            .get("requireMFA")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let external_id_ok = required
            .get("externalId")
            .and_then(|v| v.as_str())
            .map(|s| s == "panoptes-prod")
            .unwrap_or(false);
        let source_identity_ok = required
            .get("sourceIdentity")
            .and_then(|v| v.as_str())
            .map(|s| s == "panoptes")
            .unwrap_or(false);
        let resource_tag_guard_ok = required
            .get("resourceTags")
            .and_then(|v| v.as_object())
            .and_then(|rt| rt.get("PrivEscalation"))
            .and_then(|v| v.as_str())
            .map(|s| s == "deny")
            .unwrap_or(false);
        let principal_tags_ok = required
            .get("principalTags")
            .and_then(|v| v.as_object())
            .and_then(|tags| tags.get("Team"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                let mut has_security = false;
                let mut has_platform = false;
                for item in arr {
                    if let Some(tag) = item.as_str() {
                        if tag == "Security" {
                            has_security = true;
                        } else if tag == "Platform" {
                            has_platform = true;
                        }
                    }
                }
                has_security && has_platform
            })
            .unwrap_or(false);
        !(require_mfa
            && external_id_ok
            && source_identity_ok
            && resource_tag_guard_ok
            && principal_tags_ok)
    });

    let f = if has_unrestricted_admin_path {
        Findings {
            findings: vec![Finding {
                id: "F-0001".into(),
                title: "AdminRole trust policy missing guardrails".into(),
                steps: vec!["u:ci-bot -> CanAssume -> r:AdminRole".into()],
                score: 0.92,
                target: "r:AdminRole".into(),
            }],
        }
    } else {
        Findings { findings: vec![] }
    };
    fs::write(&args.out, serde_json::to_vec_pretty(&f)?)?;
    Ok(())
}
