# Panoptes
Multi-cloud IAM attack-path finder with auto-remediation diffs. Currently for development and personal use only; NOT PRODUCTION SAFE.

## Layout
- `cmd/panoptes` — Go CLI.
- `internal/*` — Go packages (IO, CLI handlers).
- `engine` — Rust path engine (JSON in/out).
- `rules/aws` — Rule pack stubs.
- `ui` — Minimal React UI to visualize findings.
- `infra/demo/terraform` — Synthetic misconfig estate (stub).

## Quickstart
The project expects Go 1.22, Rust stable, and Node.js 20 (see `.tool-versions` for exact pins).

```bash
# clone and enter the project
git clone https://github.com/nmapaye/panoptes.git
cd panoptes

# bootstrap dependencies
go mod tidy
cargo build --manifest-path engine/Cargo.toml
(cd ui && npm ci)

# build everything via make
make all

# run the CLI (binary is placed in ./bin)
./bin/panoptes --help
```
