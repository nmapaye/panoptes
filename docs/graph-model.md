# Graph Model

Panoptes emits two JSON documents: a `state.json` snapshot of the cloud estate and a `graph.json` access graph derived from that state. Both are versioned and validated with JSON Schema (see `schemas/state.schema.json` and `schemas/graph.schema.json`). This document describes the canonical node and edge types plus the preconditions that must be satisfied before an edge is considered valid.

## Schema versions

| Document   | Current version | Notes                                 |
| ---------- | --------------- | ------------------------------------- |
| state.json | `1.0.x`         | Provider inventory and metadata.      |
| graph.json | `1.0.x`         | Access graph plus metadata and edges. |

Breaking changes bump the major version; additive changes increment the minor version. Patch versions denote bug fixes or documentation-only updates.

## Node types

| Type            | ID prefix | Description                                                                   | Required attrs |
| --------------- | --------- | ----------------------------------------------------------------------------- | -------------- |
| `Principal`     | `u:`      | Human or service principal (IAM user, workload identity, external principal). | none           |
| `Role`          | `r:`      | IAM role or assumable identity.                                               | none           |
| `Group`         | `g:`      | IAM group or similar container for principals.                                | none           |
| `Policy`        | `p:`      | IAM policy document (managed or inline).                                      | `document_id`  |
| `PermissionSet` | `perm:`   | Normalized permission bundle derived from a policy statement.                 | `actions`      |
| `Resource`      | `res:`    | Target resource (ARN, service identifier, path).                              | none           |
| `Service`       | `svc:`    | Cloud service boundary (e.g., `iam`, `s3`).                                   | none           |
| `Condition`     | `cond:`   | Condition expression that scopes another node or edge.                        | `expression`   |

Node identifiers must remain unique and stable within a single graph.

## Edge types and preconditions

| Edge type          | From → To                             | Preconditions                                                                                                      | Common attrs                                   |
| ------------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------- |
| `CanAssume`        | `Principal`/`Role` → `Role`           | Trust policy contains an `Allow` for the source principal; `sts:AssumeRole` (and `iam:PassRole` if service-linked) | `condition` (JSON), `source_policy_id`         |
| `AttachedPolicy`   | `Principal`/`Role`/`Group` → `Policy` | Policy attachment exists and is in scope (AWS account/region checks).                                              | `attachment_type` (`managed`/`inline`), `path` |
| `PolicyGrant`      | `Policy` → `PermissionSet`            | Policy statement evaluates to `Effect:Allow` after condition expansion.                                            | `statement_sid`, `actions`, `resources`        |
| `ConditionBound`   | `PermissionSet` → `Condition`         | Statement includes condition keys or resource condition context.                                                   | `keys`, `operators`                            |
| `DataAccess`       | `PermissionSet` → `Resource`          | Normalized action applies to the target resource ARN or resource type.                                             | `actions`, `resource_scope`                    |
| `TransitiveRole`   | `Role` → `Role`                       | Second-order assume chain (intermediate role is assumable by source).                                              | `via` (intermediate role IDs), `depth`         |
| `Reachability`     | `Resource` → `Resource`               | Network/service path validated (security group allows traffic, trust relationship, etc.).                          | `path`, `protocol`, `port_range`               |
| `ServiceOwnership` | `Service` → `Resource`                | Resource is managed by the service namespace.                                                                      | `scope`                                        |

Every edge captures the AWS (or provider-specific) actions required to traverse it in the `preconditions` array using the `<service>:<Action>` form (supports wildcards like `s3:GetObject*`). Additional provider-specific metadata lives under the `attrs` object. All edges in a graph **must** satisfy the listed preconditions; ingest pipelines should drop edges that cannot be proven.

## Validation workflow

1. Generate or update `state.json` and `graph.json`.
2. Validate both against the JSON Schemas:

```bash
npx ajv validate -s schemas/state.schema.json -d state.json
npx ajv validate -s schemas/graph.schema.json -d graph.json
```

3. Reject or flag any graph where an edge violates the preconditions defined above. This keeps analytical output aligned with the CLI and UI expectations.
