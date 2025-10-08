# Panoptes
Multi-cloud IAM attack-path finder with auto-remediation diffs. Currently for development and personal use only; NOT PRODUCTION SAFE.

## Layout
- `cmd/panoptes` — Go CLI
- `internal/*` — Go packages (IO, CLI handlers)
- `engine` — Rust path engine (JSON in/out)
- `rules/aws` — Rule pack
- `ui` — React UI
- `infra/demo/terraform` 
