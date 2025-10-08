use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name="panoptes-engine")]
struct Args {
    #[arg(long, value_name="FILE")]
    r#in: PathBuf,
    #[arg(long, value_name="FILE")]
    out: PathBuf,
    #[arg(long, default_value_t = 6)]
    max_depth: usize,
}

#[derive(Debug, Deserialize)]
struct Graph {
    version: String,
    // rest omitted for bootstrap
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
    let _g: Graph = serde_json::from_slice(&fs::read(&args.r#in)?)?;
    // Stub analysis output
    let f = Findings {
        findings: vec![Finding {
            id: "F-0001".into(),
            title: "Demo path to AdminRole".into(),
            steps: vec!["u:alice -> CanAssume -> r:AdminRole".into()],
            score: 0.92,
            target: "r:AdminRole".into(),
        }],
    };
    fs::write(&args.out, serde_json::to_vec_pretty(&f)?)?;
    Ok(())
}
