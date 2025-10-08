# Contributing to Panoptes

Thanks for your interest in improving Panoptes! This guide covers the basics of setting up your environment, making changes, and submitting them for review.

## Development setup

Panoptes targets the toolchain versions pinned in `.tool-versions`:

- Go 1.22
- Rust stable
- Node.js 20

Quick bootstrap:

```bash
go mod tidy
cargo build --manifest-path engine/Cargo.toml
(cd ui && npm ci)
```

You can build all components with `make all`, re-run the CLI build with `make cli`, or target subprojects directly (`cargo build` inside `engine`, `npm run build` inside `ui`, etc.).

## Coding guidelines

- Favor small, focused pull requests. Describe the motivation and testing strategy in your PR description.
- Follow existing coding styles (gofmt, rustfmt, Prettier). The provided pre-commit hooks keep most of this consistent.
- When touching the Rust or Go components, keep the JSON contract between the CLI and engine stable or call out the change explicitly.

## Testing

Before submitting changes, run:

```bash
go test ./...
cargo test --manifest-path engine/Cargo.toml
(cd ui && npm run build)
```

If you add rules or data files, include unit tests or fixtures so the behavior stays verifiable.

## Pre-commit hooks

Install pre-commit and enable the hooks:

```bash
pip install pre-commit  # or use your package manager of choice
pre-commit install
```

This repository's configuration runs:

- `golangci-lint run ./...`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `npx tsc --noEmit` inside `ui`
- `prettier --check` for frontend assets

Running `pre-commit run --all-files` before pushing is a great sanity check.

## Submitting changes

1. Fork the repository (or create a feature branch if you have direct access).
2. Make and test your changes.
3. Ensure all linters and hooks pass.
4. Open a pull request with context about the problem you're solving and how you validated it.

Maintainers will review your proposal as soon as possible. Thanks again for contributing!
