# kin-spine

Federation spine -- cross-repo metadata index and query routing.

## Overview

kin-spine is the federation layer for cross-repo intelligence. It maintains a metadata index that knows where every entity lives across all repos, resolves cross-repo queries by routing hops to the correct daemon, and provides federated BFS for cross-repo impact analysis. The architecture follows a DNS model: each repo is authoritative for its zone, and the spine acts as a recursive resolver with caching.

## Key Types

- **`SpineIndex`** -- Central metadata index mapping entity fingerprints to repo locations.
- **`EntityEntry`** -- Metadata for a single entity in the spine (repo, kind, fingerprint).
- **`CrossRepoEdge`** -- A relation that spans two different repositories.
- **`RoutingTable`** / **`RepoEndpoint`** -- Maps repo IDs to daemon endpoints for query routing.
- **`FederatedImpact`** / **`FederatedNode`** / **`FederatedEdge`** -- BFS result types for cross-repo impact analysis.
- **`UnresolvedImport`** / **`ResolveResult`** -- Cross-repo import resolution types.

## Modules

| Module | Role |
|--------|------|
| `index` | Spine metadata index and entity registry |
| `routing` | Repo-to-endpoint routing table |
| `federation` | Federated BFS for cross-repo impact analysis |
| `xref` | Cross-repo import collection, resolution, and edge materialization |

## Testing

```bash
cargo test -p kin-spine
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
