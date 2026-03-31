# Panoptes

AWS IAM attack-path MVP with fixture-driven collection and Terraform remediation hints. Currently for development and personal use only; NOT PRODUCTION SAFE.

## Layout

- `cmd/panoptes` — Go CLI.
- `internal/*` — Go packages for fixture ingestion, normalization, rule evaluation, and remediation.
- `fixtures/aws` — Deterministic AWS state fixtures used by the collector and tests.
- `rules/aws` — Active AWS rule pack consumed by `analyze`.
- `engine` — Experimental Rust parity layer for graph analysis.
- `ui` — Minimal React UI to visualize findings.
- `docs/graph-model.md` — Canonical node/edge taxonomy and schema pointers.

## Quickstart

The project expects Go 1.22, Rust stable, and Node.js 20 (see `.tool-versions` for exact pins).

```bash
# clone and enter the project
git clone https://github.com/nmapaye/panoptes.git
cd panoptes

# build everything via make
make all

# generate AWS MVP artifacts from the demo fixture
mkdir -p out
./bin/panoptes collect aws --fixture fixtures/aws/demo_state.json --org o-2a1b2c3d4e --out out/state.json
./bin/panoptes normalize out/state.json --out out/graph.json
./bin/panoptes analyze out/graph.json --rules rules/aws --out out/findings.json
./bin/panoptes remediate out/findings.json --emit out/terraform
```

## Current scope

- The collector is fixture-driven for the AWS MVP. There is no live AWS API ingestion in this branch yet.
- The active detector focuses on unsafe `sts:AssumeRole` trust on privileged roles.
- Generated outputs live under `out/` and are intentionally not tracked in git.
