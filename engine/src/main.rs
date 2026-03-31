use anyhow::{bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashMap, fs, path::PathBuf};

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
    nodes: Vec<Node>,
    #[serde(default)]
    edges: Vec<Edge>,
}

#[derive(Debug, Deserialize)]
struct Node {
    id: String,
    name: String,
    #[serde(default)]
    attrs: Value,
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
struct Remediation {
    kind: String,
    summary: String,
    suggested: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Finding {
    id: String,
    rule_id: String,
    title: String,
    severity: String,
    steps: Vec<String>,
    score: f64,
    target: String,
    target_name: String,
    evidence: Value,
    remediation: Remediation,
}

#[derive(Debug, Serialize)]
struct Findings {
    schema_version: String,
    generated_at: String,
    findings: Vec<Finding>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.max_depth < 1 {
        bail!("max_depth must be at least 1");
    }
    let graph: Graph = serde_json::from_slice(&fs::read(&args.r#in)?)?;
    if !graph.schema_version.starts_with("1.") {
        bail!("unsupported graph schema version: {}", graph.schema_version);
    }
    let findings = Findings {
        schema_version: "1.0.0".into(),
        generated_at: chrono_like_timestamp(),
        findings: analyze_graph(&graph),
    };
    fs::write(&args.out, serde_json::to_vec_pretty(&findings)?)?;
    Ok(())
}

fn chrono_like_timestamp() -> String {
    "1970-01-01T00:00:00Z".into()
}

fn analyze_graph(graph: &Graph) -> Vec<Finding> {
    let node_lookup: HashMap<&str, &Node> = graph.nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    let mut findings = Vec::new();

    for edge in &graph.edges {
        if edge.edge_type != "CanAssume" {
            continue;
        }
        let role_node = match node_lookup.get(edge.to.as_str()) {
            Some(node) => node,
            None => continue,
        };
        let source_node = node_lookup.get(edge.from.as_str()).copied();
        let role_admin = role_node
            .attrs
            .get("admin")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !role_admin {
            continue;
        }

        let attrs = edge.attrs.as_object().cloned().unwrap_or_default();
        let wildcard = attrs
            .get("wildcard_principal")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !wildcard {
            continue;
        }
        let required = attrs
            .get("required_conditions")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let missing_org = required
            .get("org_id")
            .and_then(Value::as_str)
            .map(|value| value.is_empty())
            .unwrap_or(true);
        let missing_mfa = !required
            .get("require_mfa")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !(missing_org || missing_mfa) {
            continue;
        }

        let summary = format!(
            "{}{}",
            if missing_org { "trust policy is missing aws:PrincipalOrgID" } else { "" },
            if missing_org && missing_mfa {
                "; trust policy does not require MFA"
            } else if missing_mfa {
                "trust policy does not require MFA"
            } else {
                ""
            }
        );
        let mut evidence = Map::new();
        evidence.insert(
            "trusted_principal_arn".into(),
            Value::String(source_node.map(|node| node.name.clone()).unwrap_or_default()),
        );
        evidence.insert(
            "role_name".into(),
            Value::String(
                attrs.get("role_name")
                    .and_then(Value::as_str)
                    .unwrap_or(&role_node.name)
                    .to_string(),
            ),
        );
        evidence.insert("wildcard_principal".into(), Value::Bool(true));
        evidence.insert("required_conditions".into(), Value::Object(required.clone()));

        findings.push(Finding {
            id: format!("F-{:04}", findings.len() + 1),
            rule_id: "AWS-TRUST-001".into(),
            title: "Wildcard assume-role trust without org and MFA guards".into(),
            severity: "high".into(),
            steps: vec![format!(
                "{} -> {} -> {}",
                source_node.map(|node| node.name.clone()).unwrap_or_else(|| edge.from.clone()),
                edge.edge_type,
                role_node.name
            )],
            score: 0.95,
            target: edge.to.clone(),
            target_name: role_node.name.clone(),
            evidence: Value::Object(evidence),
            remediation: Remediation {
                kind: "restrict_assume_role".into(),
                summary,
                suggested: vec![
                    "Add an aws:PrincipalOrgID condition that matches the owning organization.".into(),
                    "Require aws:MultiFactorAuthPresent to be true.".into(),
                    "Replace wildcard trust with the approved principal ARN.".into(),
                ],
            },
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_with_edge(required_org: Option<&str>, require_mfa: bool) -> Graph {
        Graph {
            schema_version: "1.1.0".into(),
            nodes: vec![
                Node {
                    id: "u:111111111111/ci-bot".into(),
                    name: "arn:aws:iam::111111111111:user/ci-bot".into(),
                    attrs: Value::Object(Map::new()),
                },
                Node {
                    id: "r:111111111111/AdminRole".into(),
                    name: "arn:aws:iam::111111111111:role/AdminRole".into(),
                    attrs: serde_json::json!({ "admin": true }),
                },
            ],
            edges: vec![Edge {
                from: "u:111111111111/ci-bot".into(),
                to: "r:111111111111/AdminRole".into(),
                edge_type: "CanAssume".into(),
                attrs: serde_json::json!({
                    "role_name": "AdminRole",
                    "wildcard_principal": true,
                    "required_conditions": {
                        "org_id": required_org.unwrap_or(""),
                        "require_mfa": require_mfa
                    }
                }),
            }],
        }
    }

    #[test]
    fn detects_unsafe_trust() {
        let findings = analyze_graph(&graph_with_edge(None, false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "AWS-TRUST-001");
    }

    #[test]
    fn ignores_guarded_trust() {
        let findings = analyze_graph(&graph_with_edge(Some("o-2a1b2c3d4e"), true));
        assert!(findings.is_empty());
    }
}
