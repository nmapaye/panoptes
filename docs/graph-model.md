# Graph Model

Panoptes currently emits three JSON documents for the AWS MVP:

- `state.json` — fixture-driven AWS IAM inventory
- `graph.json` — normalized access graph derived from state
- `findings.json` — rule findings emitted by `analyze`

The schemas under `schemas/` describe those artifacts. This document focuses on the normalized graph produced by `normalize`.

## Schema versions

| Document      | Current version | Notes                                       |
| ------------- | --------------- | ------------------------------------------- |
| state.json    | `1.1.x`         | AWS account, principal, and role inventory. |
| graph.json    | `1.1.x`         | Access graph plus metadata and edges.       |
| findings.json | `1.0.x`         | Rule findings and remediation hints.        |

Breaking changes bump the major version; additive changes increment the minor version. Patch versions denote bug fixes or documentation-only updates.

## Node types

| Type        | ID prefix | Description                         | Required attrs |
| ----------- | --------- | ----------------------------------- | -------------- |
| `Principal` | `u:`      | IAM user or other trusted identity. | none           |
| `Role`      | `r:`      | IAM role or assumable identity.     | none           |

Node identifiers must remain unique and stable within a single graph.

## Edge types and preconditions

| Edge type   | From → To                   | Preconditions    | Common attrs                                                                                    |
| ----------- | --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------- |
| `CanAssume` | `Principal`/`Role` → `Role` | `sts:AssumeRole` | `trusted_principal_ref`, `wildcard_principal`, `required_conditions`, `account_id`, `role_name` |

Every edge captures the AWS action required to traverse it in the `preconditions` array. For the current AWS MVP that means `sts:AssumeRole`. Additional trust metadata lives under `attrs.required_conditions`.

## Validation workflow

1. Run `go test ./...` to validate the fixture-driven state, graph, rule, and remediation pipeline.
2. Generate fresh artifacts with the CLI into `out/`.
3. Use the schemas as the contract reference for any new fixtures or UI consumers.
