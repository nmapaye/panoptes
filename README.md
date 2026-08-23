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

## Safety and review behavior

`analyze --max-depth N` searches deterministic, cycle-free `CanAssume` paths up
to `N` edges. Rule files are parsed as strict YAML, so unknown fields and
duplicate rule IDs stop analysis instead of being ignored.

`remediate` emits Terraform only when a finding contains a valid role name,
organization ID, and specific principal ARN. Incomplete findings remain in
`remediation.json` with `requires_review` and a reason, while the Terraform file
contains no resource block for them. Generated Terraform is a review artifact,
not an instruction to apply changes to an AWS account.

The UI reads `findings.json` entirely in the browser. It validates schema 1.x,
then provides severity counts, filtering, path details, evidence, and remediation
notes without uploading the file.
