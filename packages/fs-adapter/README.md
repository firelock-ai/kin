# kin-fs-adapter

`kin-fs-adapter` is the headless filesystem bridge for Kin-native editors and tools.

It lives under `kin/packages/` so products like `kin-code` do not need to own Kin repository discovery, native-mode source-root mapping, hidden control-surface rules, or compatibility fallbacks directly in editor code.

Shared workspace payload shapes are defined in `@kin/boundary-contracts`, and this package validates workspace/file payloads against those contracts at runtime.

Current responsibilities:

- discover a Kin repository from any nested path
- resolve Kin `compat` vs `native` workspace roots
- hide control-surface paths such as `.kin/` and `.git/` from the virtual workspace
- expose file and directory operations against the Kin-visible workspace
- provide a small CLI for editor integrations

Current backend modes:

- `sourceRootBridge`: bridges to the repo root in compat mode and `.kin/source-root/` in native mode
- `graphNative`: prefers `kin-graph-service` when configured or auto-detected, and falls back to `sourceRootBridge` when the service is unavailable

## CLI

Examples:

```bash
kin-fs-adapter context --repo /path/to/repo
kin-fs-adapter read-dir --repo /path/to/repo --path /
kin-fs-adapter read-file --repo /path/to/repo --path src/main.rs
kin-fs-adapter status --repo /path/to/repo
```

Optional flags:

- `--backendMode sourceRootBridge|graphNative`
- `--graphServiceUrl http://127.0.0.1:4311`
- `--graphServicePath /path/to/kin-graph-service.js`

Contract resolution order:

- installed `@kin/boundary-contracts` package
- `KIN_BOUNDARY_CONTRACTS_PATH`

`read-file` returns JSON with base64-encoded bytes.

`write-file` reads raw bytes from stdin:

```bash
printf 'hello\n' | kin-fs-adapter write-file --repo /path/to/repo --path notes.txt --create --overwrite
```
