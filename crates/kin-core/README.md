# kin-core

Shared runtime, config, and initialization for Kin.

## Overview

kin-core is the foundation crate that all other Kin crates build on. It handles repository initialization (`.kin/` directory structure), layout management, configuration (world presets, remote config, execution policies), the multi-repo registry, assistant adapter integration, and branch management. It also provides import resolvers for cross-file symbol linking.

## Key Types

- **`KinLayout`** -- Filesystem layout for `.kin/` directories (HEAD, snapshots, blobs, config).
- **`KinConfig`** / **`WorldConfig`** / **`WorldPreset`** -- Repository and world configuration.
- **`KinManifest`** -- Manifest for repo metadata.
- **`RepoMode`** -- `Compat` (files alongside `.kin/`) or `Native` (files in `.kin/source-root/`).
- **`ImportResolver`** / **`TypeScriptResolver`** / **`PythonResolver`** -- Cross-file symbol resolution.
- **`AssistantAdapterConfig`** / **`AssistantKind`** -- AI assistant integration and adapter management.

## Usage

```rust
use kin_core::{init, KinLayout, read_repo_mode, RepoMode};

// Initialize a new Kin repo
let result = init(&workspace_path, &graph)?;

// Read layout and mode
let layout = KinLayout::discover(&workspace_path)?;
let mode = read_repo_mode(&layout);
```

## Modules

| Module | Role |
|--------|------|
| `init` | Repository initialization and genesis change |
| `layout` | `.kin/` directory structure |
| `config` | World presets, remote config, execution policies |
| `registry` | Multi-repo registry (`~/.kin/registry.toml`) |
| `assistant` | AI assistant adapter management |
| `resolver` | TypeScript/Python import resolution |
| `hooks` | Claude Code hook generation |

## Testing

```bash
cargo test -p kin-core
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
