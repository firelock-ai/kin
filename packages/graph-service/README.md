# kin-graph-service

`kin-graph-service` is the graph-facing backend boundary for Kin-native editors.

Today it still projects through Kin's current source-root or compat filesystem reality. The important shift is architectural: editors and adapters can now target a graph-native service surface instead of talking directly to projected files.

Shared workspace and file-operation payload shapes are defined in `@kin/boundary-contracts`, and this package validates the payloads it serves and emits against those contracts.

## Current scope

- Resolve Kin repositories and current repo mode
- Expose graph-native workspace operations over HTTP or one-shot CLI commands
- Keep control-surface files hidden from editor workspaces
- Provide a stable service contract for `kin-fs-adapter` and future editor integrations

## Commands

```bash
kin-graph-service context --repo /path/to/repo
kin-graph-service read-dir --repo /path/to/repo --path /
kin-graph-service serve --repo /path/to/repo --port 4311 --json-ready
```

The HTTP service exposes:

- `GET /health`
- `GET /context`
- `GET /stat?path=/src`
- `GET /read-dir?path=/`
- `GET /read-file?path=/src/app.ts`
- `PUT /write-file?path=/src/app.ts&create=1&overwrite=1`
- `POST /mkdir?path=/docs`
- `DELETE /delete?path=/docs&recursive=1`
- `POST /rename?from=/old&to=/new&overwrite=1`

Contract resolution order:

- installed `@kin/boundary-contracts` package
- `KIN_BOUNDARY_CONTRACTS_PATH`

## Direction

This package is the place to evolve from source-root projection to true graph-native reads, writes, search, and history. `kin-fs-adapter` should stay as the editor-facing compatibility layer that chooses between brownfield bridging and this service.
