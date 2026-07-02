# Changelog

All notable changes to Kin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.6] - 2026-07-01

Session-aware runtime, a shadow-mode merge gate, a hardened first-run installer, and a central environment registry.

### Added

- Session runtime for ordinary tools: `kin exec -- <cmd>` (new alias `kin run`) runs commands in a graph-backed session workspace, reconciles on success, and preserves the workspace with recovery commands on failure; `--keep` defers reconcile and `--discard` skips it.
- Agent session launches: `kin with --session <assistant> -- <task>` starts the assistant inside a session workspace with its cwd, file shims, session identity (`KIN_SESSION`, `KIN_SESSION_ID`, `KIN_SESSION_DIR`), and daemon binding (`KIN_DAEMON_URL`, `KIN_REPO_ID`) pointed at the same repository — MCP tools spawned by the assistant bind to the same daemon and session.
- External-tool detection now covers package managers (`npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bun`, `bunx`, `corepack`), which widen scoped execution to a full workspace under the default policy.
- `kin doctor` gains a session-runtime check that teaches the `kin exec` / `kin shell` / `kin with --session` path and reports leftover session workspaces with recovery commands.
- Session workspace materialization resolves `entity:`/`artifact:` scopes against graph truth for every session surface, failing loudly on unknown entities instead of silently widening.
- New [Session Runtime](docs/session-runtime.md) guide: execution contract, closeout flags, generated-file policy, and Docker/Compose caveats.
- `kin review shadow`: a non-blocking shadow-mode merge-gate report that evaluates a proposed change and emits a structured JSON verdict, so an AI-authored change can be judged before merge without gating the workflow.
- A central `KIN_*` environment registry with startup validation and zero-safe bound parsing: unknown or malformed `KIN_*` overrides are surfaced at startup instead of being silently ignored.
- `kin locate` and the agent search surfaces now report a confidence score and the end of each match's line span in their JSON output.

### Changed

- `kin exec` executes commands locally in the materialized session workspace instead of requiring the daemon's gated remote-exec capability; the daemon endpoint remains opt-in via `KIN_DAEMON_ALLOW_EXEC`.

### Fixed

- `kin setup` and `kin doctor --fix` now write MCP client entries that start (`kin mcp start`); the previously written `--global` mode was refused at startup, leaving agents with a dead kin MCP server. `kin doctor` flags the retired entries and `--fix` repairs them.
- First-run installer: `curl … | sh` now survives POSIX `dash` (the default `/bin/sh` on Debian/Ubuntu and most container base images), parses the resolved version correctly, and logs daemon startup at info level.
- `kin setup` no longer truncates the bundled VFS shim to 0 bytes, so transparent filesystem projection works on a fresh install.
- `get_entity_source` distinguishes "entity not found" from "entity found but has no source" instead of collapsing both into one error.
- Release builds no longer self-report a spurious `-dirty` version suffix: the in-tree CI checkouts of `kin-vfs`/`kin-db` are ignored, so a clean tagged tree stamps a clean version.
- Unified `sha1`/`sha2` on `digest` 0.11 to repair a registry checksum break, and refreshed pinned dependencies (`anyhow`, `uuid`, `tree-sitter-rust`, `notify`, `sysinfo`).

## [0.2.5] - 2026-07-01

Cross-repo intelligence, more informative retrieval surfaces, and a guided first-run experience.

### Added

- Guided first-run setup: `kin` detects whether the daemon is running and walks through initial configuration, with a scriptable `kin doctor` for health checks.
- `kin locate` and the agent retrieval surfaces now return inline, bounded source snippets alongside each result, so callers see the relevant code without a second fetch.
- Cross-repo spine now resolves transitive (2-hop) and multi-consumer blast radius: a repository's entities are registered as resolution targets on every refresh, so impact and cross-references span the full dependency chain rather than stopping at direct neighbours.
- The daemon can ingest multi-repo graphs into the spine directly from durable storage.
- `kin release`: a cross-repo release orchestrator (`plan`, `apply`, `intent`, `snapshot`) for bottom-up version and dependency-pin management.
- `@kin/boundary-contracts` gains intent-scope, intent-summary, and lock-type schemas.
- Opt-in `semantic_locate` re-ranking (role demotion + exact-name boost), off by default.

### Changed

- Cross-repo spine queries now distinguish "spine configured but unavailable" from "genuinely no cross-repo impact" instead of silently collapsing both into an empty result; the gap is observable across the CLI, MCP, and hosted gateways.
- Locate ranking constants are environment-overridable for tuning.

### Fixed

- Locate priority injectors no longer surface fixture or VCS-internal paths.
- Cross-repo imports bind by normalized crate root and refresh across every repository.
- The cross-encoder re-rank gates on graph presence rather than workspace-root presence.
- The daemon honours `KIN_PRIMARY_REPO_ID` when selecting the primary repository.

## [0.2.4] - 2026-06-25

Portable Linux release. The Linux binaries are now statically linked against musl with rustls, removing the OpenSSL and glibc-version runtime dependencies, so `kin` and `kin-daemon` run on any Linux distribution including Alpine/musl and older glibc systems.

### Changed
- Linux release binaries switched from glibc dynamic linking to static musl, and from native-tls/OpenSSL to rustls. The binaries no longer require libssl/libcrypto at runtime or a minimum glibc version.

## [0.2.3] - 2026-06-24

Signed release. The macOS binaries are now code-signed with a Developer ID certificate and notarized by Apple.

### Changed

- The `kin-macos-x86_64` and `kin-macos-aarch64` archives are now code-signed (Developer ID Application) and notarized, so they launch without a Gatekeeper warning on first run.

## [0.2.2] - 2026-06-24

Corrective release adding Intel Mac (`x86_64`) to the public install matrix.

### Fixed

- The `kin-vfs` native shim now builds on `x86_64-apple-darwin`. Xcode 16's SDK declares `stat64`/`lstat64`/`fstat64` with a distinct `struct stat64`, which conflicted with the manual forward-declarations needed on `arm64`; these are now guarded by `#ifndef __x86_64__`. The `kin-macos-x86_64` archive is now produced and is no longer experimental.

## [0.2.1] - 2026-06-16

Corrective public install release for first-run setup.

### Changed

- Release archives now include `kin-daemon` alongside `kin`, so clean public installs can run daemon-backed commands without relying on a developer PATH or pre-existing daemon.
- Generated MCP setup config now defaults to the small `agent-default` tool profile while preserving the full surface for advanced users.

### Fixed

- Public installers now hard-fail on daemon-less archives and support checksum-verified release downloads for first-run install proof.

## [0.2.0] - 2026-06-16

First `0.2.0` release. Supersedes the `0.1.0-alpha.*` line.

### Added

- macOS transparent VFS interposition: an unmodified process now reads graph-backed files — including paths that do not exist on disk — through the shim's `__DATA,__interpose` table, verified end-to-end.
- Graph-assigned artifact identity on the `GraphStore` trait (`artifact_id_for_path`); the context-pack builder resolves graph-owned ids instead of re-deriving them from paths.

### Changed

- VFS write authority is now graph-first: write-notify is lossless (unbounded channel, replacing the 64-slot drop-on-full queue) and materialize-on-write seeds from graph content rather than trusting a stale on-disk copy.
- `ArtifactId::from_path`/`from_file_id` deprecation is fully enforced; every internal caller uses the non-deprecated seed primitives and the `-A deprecated` CI mask is removed.

### Fixed

- kinlab release-publish and branch-protection gates no longer trust client-asserted booleans; gate decisions derive only from server-authoritative state.
- kin-search lock-order inversion between mutation and commit that could deadlock the staged/live/segment path.

### Security

- Closed a control-plane gate bypass where forged request booleans could approve a protected release or push.

## [0.1.0-alpha.25] - 2026-03-28

### Added

- `kin locate` — structural issue-to-file retrieval that fuses eight signals with reciprocal rank fusion to map a problem description to the files most likely to need changes
- Automatic semantic search — embeddings are graph-native and built during indexing, with zero CLI configuration required
- Full-text search fallback backed by Tantivy, plus weighted relation traversal in the context builder for richer context packs
- Review mutation surface — new MCP tools, CLI commands, and daemon HTTP endpoints for deciding, discussing, and resolving reviews
- Cargo registry support — the daemon serves a registry and the CLI can publish crates, with npm, OCI, and Go registry adapters wired through the daemon
- Cross-repo federation — the `kin-spine` federation index resolves relationships across repositories and powers federated impact analysis
- Four additional language adapters and an expanded benchmark suite (graph-scale, spine-scale, and parser-throughput subcommands)

### Changed

- Removed legacy compatibility mode in favor of the native execution path
- Global registry awareness is always on, so cross-repo and sibling-graph context loads without extra setup

### Fixed

- `kin locate` retrieval quality recovered and improved on ContextBench after an upstream regression
- Cleared all compiler warnings across the workspace and repaired library tests
- Upgraded tree-sitter 0.24 → 0.25 and fixed the HCL, Kotlin, and shallow-parse adapters

## [0.1.0-alpha.5] - 2026-03-21

### Fixed

- CI: upgraded GitHub Actions runtime pins to current supported majors for checkout, setup-node, upload-artifact, and download-artifact to avoid the Node 20 deprecation path

## [0.1.0-alpha.4] - 2026-03-21

### Added

- Hosted remotes: `kin clone` and `kin pull` now work directly against KinLab native snapshot remotes, including `kinlab://org/repo` and `https://kinlab.ai/org/repo`
- npm: `kin-mcp` auto-initializes a local `.kin/` repo when MCP startup runs in a workspace that has not been initialized yet

### Fixed

- Semantic commit scanning now tracks real dotfiles and hidden repo content like `.github/`, avoiding immediate dirty-state mismatches after native clone
- CLI: released snapshot handles cleanly in note persistence tests to avoid Linux lock contention
- CLI: transport repo bootstrap now satisfies strict `clippy -D warnings` in CI

## [0.1.0-alpha.3] - 2026-03-21

### Added

- README: demo GIFs for MCP setup, Git interop, semantic exploration, and the full walkthrough
- Scripts: `scripts/record-demos.sh` for regenerating the README demo assets

### Fixed

- npm: `kin-mcp` stays side-effect-free and no longer tries to auto-initialize `.kin/` on MCP startup
- README: brownfield adoption guidance now explicitly documents `kin init`, `kin git import`, and `kin commit`

## [0.1.0-alpha.2] - 2026-03-21

### Added

- CLI: `kin clone` -- clone a repository (native Kin or Git compat fallback)
- CLI: `kin pull` -- pull changes from a remote (native Kin or Git compat fallback)
- CLI: `kin checkout` -- restore a file from any point in the semantic history
- CLI: `kin push` now executes Git push for git-export remotes (previously only prepared the export)
- npm: `kin-mcp` wrapper package for assistant-native MCP setup via `npx`

### Fixed

- CHANGELOG crate count: 17 → 19
- README clone URLs: pointed to correct `firelock-ai` organization
- Assistant setup guidance now includes the npm-based MCP shortcut

## [0.1.0-alpha.1] - 2026-03-20

### Added

- CLI: `kin clone`, `kin pull`, and `kin checkout`
- CLI: wired `kin push` to execute Git push for Git export remotes

## Pre-alpha Foundation - 2026-03-13

Historical note: this snapshot predates the public GitHub prerelease series and was not published as a tagged GitHub release.

### Added

- Semantic graph engine backed by KinDB for entity/relationship storage
- Tree-sitter parsing for TypeScript, Python, Go, Java, Rust, JavaScript, and C
- Content-addressable blob store for source text
- CLI: `kin init`, `kin commit`, `kin status`, `kin trace`, `kin context`, `kin diff`, `kin review`
- MCP server for AI agent context delivery (`kin-mcp`)
- Git import/export interop via `kin-git`
- Session workspaces with file reconciliation
- Benchmark harness for measuring context quality and token savings (`kin bench`)
- Compat and native execution modes for assistant integration
- Semantic fingerprinting for identity tracking across renames and refactors
- Token-budgeted context packs via graph traversal
- Daemon mode for background file watching (`kin-daemon`)
- 19-crate workspace architecture

[unreleased]: https://github.com/firelock-ai/kin/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/firelock-ai/kin/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/firelock-ai/kin/compare/v0.1.0-alpha.25...v0.2.0
[0.1.0-alpha.25]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.25
[0.1.0-alpha.5]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.1
