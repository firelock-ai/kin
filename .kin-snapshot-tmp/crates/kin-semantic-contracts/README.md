# kin-semantic-contracts

Semantic contract discovery and cross-language linking for Kin.

## Overview

kin-semantic-contracts discovers API contracts from schema files (OpenAPI, Protobuf, GraphQL, DB schemas, event schemas) and links producers to consumers across language boundaries. It detects breaking changes, tracks semver version bumps, and propagates contract impact through the dependency graph.

## Key Types

- **`DiscoveredContract`** -- A contract detected from a schema file.
- **`SemverBump`** -- Detected version bump classification (major, minor, patch).
- **`LinkResult`** -- Result of linking a contract to its producers and consumers.
- **`ContractBreakage`** / **`BreakageKind`** -- Detected breaking change with classification.

## Key Functions

- **`detect_contract`** -- Scan a file for contract definitions.
- **`detect_version_bump`** -- Detect semver version changes in a contract.
- **`link_contract`** -- Link a contract to producer/consumer entities in the graph.
- **`propagate_contract_impact`** -- Propagate contract changes to downstream consumers.
- **`detect_breaking_changes`** -- Identify breaking changes between contract versions.

## Testing

```bash
cargo test -p kin-semantic-contracts
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
