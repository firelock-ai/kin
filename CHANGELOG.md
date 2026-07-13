# Changelog

All notable changes to Kin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.20] - 2026-07-13

This patch makes cross-repository spine evidence fail closed when a resolver or
legacy durable record describes an impossible same-repository relationship.

### Fixed

- Cross-repository import resolution no longer resolves an import back into its
  source repository, and materialization counts only edges accepted by the spine.
- The spine index and Firestore persistence boundary reject same-repository
  cross-repo edges. Legacy invalid rows are ignored during hydration instead of
  being restored as public cross-repository evidence.

## [0.2.19] - 2026-07-13

This patch restores legacy graph snapshot reopening, makes Python rename review
fail closed on incomplete evidence, hardens the post-release follow-up boundary,
and aligns the public OSS surface with the behavior and proof that Kin actually
ships.

### Changed

- Post-release Homebrew and installer follow-ups are consolidated behind a
  main-only protected environment and short-lived GitHub App authority. The
  workflow remains dormant until its credentials are installed and
  `RELEASE_FOLLOWUP_READY` is explicitly enabled.
- Public positioning now separates citable retrieval evidence from report-only
  review behavior and links the artifact-backed public proof package.
- External contributions now use the documented DCO sign-off only; the
  nonfunctional base-branch CLA allowlist gate has been removed.

### Fixed

- Daemon reopen now reads persisted graph snapshots whose positional
  `SemanticFingerprint` records predate `equivalence_hash`; the missing field uses
  the zero not-computed sentinel, while current six-field fingerprints preserve
  their recorded value.
- Python parameter rename review now preserves declaration defaults and every
  call-site shape. Default changes, incomplete call coverage, ambiguous receiver
  resolution, and otherwise unproven calls remain blocking.

## [0.2.18] - 2026-07-11

This patch supersedes the quarantined v0.2.17 prerelease. It carries forward
the graph-backed VFS bridge and release-verification hardening from that tag,
then fixes the defects exposed by the mandatory clean-install proof.

The v0.2.17 signed assets remain available for audit, but npm, GHCR version
tags, Homebrew, installers, and GitHub Latest were never promoted. The complete
last-stable diff is [v0.2.16...v0.2.18](https://github.com/firelock-ai/kin/compare/v0.2.16...v0.2.18).

### Fixed

- `kin-vfs` translates intercepted host paths into repo-relative graph keys,
  preserves canonical and lexical workspace roots, and rejects ambiguous or
  escaping paths before they can reach graph authority.
- Windows daemon reopen no longer applies the Unix-only parent-directory fsync
  primitive that caused `ERROR_ACCESS_DENIED` after loading a persisted graph.
- Public install proof now preserves the selected Unix shell across Actions
  steps, reports the exact unhealthy checks, and exercises a native Windows
  init-to-daemon-reopen smoke before a release can reach npm or GitHub Latest.
- README install links now follow the proven GitHub Latest release instead of
  advertising an unpromoted tag.

## [0.2.17] - 2026-07-11

This patch restores the promised graph-backed filesystem bridge and tightens the
automatic release verifier without changing Kin's public CLI surface.

### Fixed

- `kin-vfs` now translates intercepted host paths into repo-relative graph keys before
  daemon requests, preserves launcher-verified canonical and lexical workspace roots,
  and rejects traversal, containment, or alias ambiguity from graph authority.
- Post-release verification now waits for complete npm integrity metadata, and
  cross-platform checksum aggregation normalizes Windows CRLF sidecars to LF.

## [0.2.16] - 2026-07-11

Graph authority is more durable across long imports and daemon restarts, while
agent-facing retrieval and review surfaces explain their evidence more clearly and the
release path fails closed on artifact provenance.

### Added

- History hydration checkpoints let interrupted imports resume from deterministic,
  graph-owned progress instead of replaying completed work.
- `semantic_locate` now reports per-hit `match_evidence` on both the default cosine
  path and the opt-in fused path; fused multi-query fan-out and reciprocal-rank fusion
  are available without changing the honest default.
- Shadow review keeps rename-neutral downstream risk proportionate, excludes
  derived-copy consumers, and stamps range depth plus a non-demoting deep-history
  evidence ceiling when a deep range yields no blast radius.

### Changed

- Graph-derived VFS snapshot materialization is cached with single-flight fills, so
  concurrent readers reuse the same authoritative projection work.
- `history` and `blame` route lazy hydration through the owning graph authority:
  HEAD-owned growth is persisted and broadcast only when changes were inserted, while
  session-scoped growth stays private.
- Pin `kin-db` 0.2.35 for the storage and snapshot-lock lifecycle used by restart-safe
  daemon authority.

### Fixed

- Daemon reopen now replays the authoritative storage delta chain and restores the exact
  generation; completed HEAD hydration survives restart without replay, and its
  invalidation event is emitted once its persistence generation finalizes.
- Reconcile bursts retain their full bounded backlog instead of discarding events past
  the first batch.
- Release automation now binds Windows checksums to exact archives, gates GitHub Latest
  on anonymous install proof and automatically published, provenance-verified npm
  packages, preserves tracked lockfile bytes across operating systems, validates the
  public Homebrew formula outcome, and attests the immutable daemon image.

## [0.2.15] - 2026-07-08

Sharper shadow review: behavior-equivalence fingerprinting, call-site argument shapes,
and arity-aware overload binding let review distinguish behavior-preserving refactors
from real changes with far less noise.

### Added

- Behavior-equivalence fingerprint: `SemanticFingerprint` now carries an
  `equivalence_hash` capturing a change's behavior-equivalence class. Review uses it to
  downgrade behavior-preserving consumer fanout instead of flagging it, so a refactor
  that keeps behavior no longer cascades warnings across its callers.
- Type-identity and annotation-neutral equivalence: type-only and annotation-only edits
  are recognized as behavior-preserving and folded into the same equivalence class,
  keeping their review impact proportionate.
- Call-site argument shapes: the Python parser records the argument shape at each call
  site on `Calls` edges and the linker persists it onto resolved calls, so review can
  gate arity-preserving parameter renames against how a function is actually called.
- Arity-aware C++ overload binding: overloaded C++ calls bind to the overload whose
  arity matches the call site rather than fanning out across every same-named overload.

### Changed

- Pin `kin-model` 0.2.4 for the `SemanticFingerprint.equivalence_hash` surface.

### Fixed

- `kin-cli`: cover the equivalence-downgrade fanout kind in `inline_comment_severity`
  so downgraded fanout is rendered at its intended severity.

## [0.2.14] - 2026-07-08

First-run setup becomes Kin-native by default for new repos and smoother for agent
workflows, npm installs, shell sessions, and managed install roots.

### Added

- Revert-history review channel: shadow review flags revert-shaped changes — an added
  entity that restores content removed in the recent past (behavior-fingerprint match),
  a reintroduction of a recently-removed surface (same name and kind, modified content),
  and removals of recently-introduced entities. The evidence is temporal, read from a
  bounded window of the base ref's ancestry at review time, and feeds the gate as
  ordinary warning findings; when the base has too little history to scan, the report
  carries an explicit evidence gap instead of a silent pass.
- Fresh no-Git `kin init` bootstraps managed `AGENTS.md` guidance before the first
  snapshot so brand-new repositories start Kin-native, with graph truth as authority
  and Git kept as an optional export path.

### Changed

- `kin setup` and the native installers now prefer `KIN_HOME` for the managed install
  root while keeping `KIN_DIR` as a compatibility alias; shell hooks, health checks,
  docs, and the env-var registry all agree on that contract.
- `kin shell` now exports the same session-coherent daemon/repo/session context used by
  agent sessions (`KIN_SESSION`, `KIN_SESSION_ID`, `KIN_SESSION_DIR`,
  `KIN_DAEMON_URL`, and `KIN_REPO_ID`).

### Fixed

- `kin setup` now appends and ledgers the managed-bin PATH block idempotently, and
  `kin setup status` treats an rc-declared PATH as healthy after shell restart.
- Setup shim discovery checks the managed `KIN_HOME/lib` before development fallback
  paths, so cargo-bin launches no longer claim the VFS shim is missing when the
  installed shim is already in place.

## [0.2.13] - 2026-07-07

Distribution becomes first-class: Kin installs from npm as `@kinlab/kin`, doctor heals its own VFS shim, and history hydration gains parse reuse and a timing profile.

### Added

- Canonical npm package `@kinlab/kin`: installs the platform Kin CLI + daemon and
  exposes the `kin` and `kin-mcp` binaries; MCP stays included via `kin mcp start`.
  `@kinlab/kin-mcp` remains as a compatibility wrapper.
- History hydration can emit a machine-readable per-stage timing profile
  (`KIN_HYDRATE_STAGE_TIMINGS`) for replay analysis.
- Blob parses are memoized across history hydration: identical file contents parse
  once per adapter version instead of once per touching commit.

### Fixed

- `kin doctor --fix` repairs a missing or zero-byte VFS shim by fetching the release
  shim matching the installed version — or fails honestly — instead of printing
  circular fix advice.
- `kin refs` and rename queries answer only from graph truth; the raw source-tree
  scan fallback is removed from the authority path.

### Security

- crossbeam-epoch updated to 0.9.20 (RUSTSEC-2026-0204).

## [0.2.12] - 2026-07-06

First-touch review latency: ancestor..descendant review pairs hydrate git history once instead of twice.

### Changed

- `kin review shadow` resolves the head ref before the base ref, so an
  ancestor..descendant pair (the common review shape) hydrates git history in a
  single pass instead of re-walking the ancestry for each side — first reviews on
  large-history repos start substantially faster.

## [0.2.11] - 2026-07-06

Python inheritance-aware dispatch: the graph now knows that a subclass calling an inherited method consumes the ancestor that defines it.

### Fixed

- Python method calls dispatched through `self`/`cls` now resolve through the class's
  inheritance chain to the defining ancestor, in batch linking, incremental linking, and
  reopened graphs alike: `self.validate()` inside `Command(BaseCommand)` links to
  `BaseCommand.validate` as a verdict-driving consumer edge instead of vanishing into the
  bare-name fan-out. Deleting an inherited-but-consumed API is therefore flagged as
  breaking — this extends 0.2.10's removed-entity rule, whose consumer harvest was scoped
  to directly-captured edges, to inheritance-reached consumers. Local overrides still
  shadow the base, unknown-receiver calls keep their previous behavior, and unresolvable
  hierarchies fall back to the old fan-out so recall never regresses.

## [0.2.10] - 2026-07-06

Review-accuracy hardening across the shadow-review gate, the semantic substrate, and the language adapters — the graph now reasons about entity roles and the base-vs-head sides of a change the way a reviewer does.

### Added

- Toolchain-surface channel: edits that only add or remove lint-suppression and deprecation directives (`//nolint`, `# noqa`, `eslint-disable`, `#[allow]`, `@deprecated`, …) now surface a non-blocking review signal, diffed graph-natively from content-addressed blobs.
- Executable per-language capability matrix covering all thirteen full adapters (entity extraction, cosmetic stability, call/import edges, cross-file resolution) as permanent regression tests.

### Changed

- Fingerprints and declaration signatures are formatting-independent across every language adapter: comment-only, whitespace-only, and line-wrapping edits no longer read as behavior or signature changes.
- Entity role now scopes review findings consistently: test, generated, and vendored declarations are covering evidence, never a contract surface — a test's signature change no longer escalates a benign diff, and amalgamated single-header bundles no longer count as consumers.
- Adding a strengthening qualifier (`constexpr`/`inline`/`[[nodiscard]]`) is no longer reported as a signature change.
- One shared definition of "entity semantically changed" now governs every write path (commit, history hydration, daemon delta generation), so graph truth no longer depends on which path recorded a change.

### Fixed

- Deleting a public entity that has live non-test consumers is now flagged as a breaking change: removed-entity impact is harvested from the base graph (where the entity and its inbound edges still exist) instead of the head graph (where it is already gone), and the removed entity resolves to its real name rather than an opaque id.
- Java and C# method calls resolve to their rightmost name (matching every other adapter), so cross-file call edges are no longer lost to dotted callees; Kotlin declaration signatures no longer leak the method body.

## [0.2.9] - 2026-07-04

First-touch hardening: the daemon's git-ancestry hydration is serialized (no more concurrent-review crashes), whole-repo ingest routes every full language adapter, and agents get a budgeted batch source tool.

### Added

- `get_entity_sources` MCP tool: batched entity-source fetch (1–50 ids) with a shared token budget, per-body line/byte clamps, compact signature-only mode, and per-row fault isolation — one envelope instead of N iterative calls.
- `docs/language-support.md`: the honest per-language support matrix (extraction depth, shallow tiers, LSP enrichment, and current routing gaps).

### Changed

- Shadow review verdicts are calibrated on per-entity inbound evidence: findings key on each entity's own consumers and covering tests (never diff-global counts), docs/CI-only changes can pass cleanly, removed entities are named in findings, and a consumer-fanout check flags body-only changes consumed from multiple files.
- Whole-repo ingest now routes Swift, PHP, and HCL/Terraform to their full semantic adapters (previously shallow or opaque despite complete adapters), and no longer advertises shallow support for nine languages that have no grammar wired — they classify opaque, honestly.
- The coverage self-report recognizes import syntax across all deep-adapter languages, so cross-file depth is no longer understated for C, C++, C#, Ruby, and Kotlin.

### Fixed

- Concurrent reviews (or review + locate/blame/history) that both needed git-ancestry hydration could double peak memory and crash the daemon mid-request; hydration is now single-flight behind a per-daemon gate with a lock-free warm path.
- A test-suite race on process-global environment reads in the status command's tests.

## [0.2.8] - 2026-07-03

Call-graph recall and byte-deterministic review on the blast-radius surface, plus default-on SIMD and container-aware resource planning through refreshed primitives.

### Added

- Python call-resolution regression tests across the parser and linker pipelines (bare-import, module-attribute, and instance-method calls, same-file and cross-file, with innermost-enclosing-function attribution pins).
- `kin setup` records a fingerprinted install ledger, `kin doctor`/`status` verify every recorded artifact against disk, and `kin setup uninstall` removes exactly the recorded slice — never clobbering entries the user modified — with `kin setup ledger` to inspect.
- `kin embed` reports live throughput and ETA per pass, and under the interactive/small resource profiles a single invocation is bounded by a total wall budget (`KIN_EMBED_MAX_TOTAL_SECONDS`, default 600s) returning a resumable partial index.
- A confidence-calibrated declaration cutoff for locate file lists (`KIN_LOCATE_DECLARATION_CUTOFF`, off for every profile) with prune-ledger attribution for anything it trims.

### Fixed

- Path-qualified call expressions (`crate::mod::func(...)`, `Type::method(...)`) now resolve to Calls/References edges in both the batch and incremental linkers via conservative suffix resolution — impact and refs no longer under-report callers reached through qualified paths. The Rust adapter also descends into inline module bodies, so module-scoped functions get entities and their calls attribute to the innermost enclosing function.
- Review output is byte-deterministic: emitted entity and relation changes are sorted, and the contract-surface finding selects a stable representative among tied entities.
- The locate capability tier respects cgroup CPU and memory quotas (a constrained container no longer mis-detects as a high-resource host), and any sub-Performance tier emits an explicit degradation naming the disabled signals and the `KIN_LOCATE_PROFILE` override.
- `kin init` genesis no longer holds two full copies of every entity in memory, reducing peak RSS on large repositories.
- Dependency and registry metadata scanning work under toml 1.x (three call sites ported off document-parsing `FromStr`; serialization is byte-stable with 0.8).

### Changed

- kin-vector 0.1.6: the NEON SIMD kernel is enabled by default (scalar remains reachable via `KIN_VECTOR_SIMD=0` for A/B).
- kin-infer 0.2.40: resource planning caps cores and memory by cgroup v2/v1 quotas when present; bare-metal hosts are unchanged.
- The public daemon image is version-tagged (`:X.Y.Z` and `:vX.Y.Z`) on tagged releases via a registry-side retag of the already-smoked commit image.

## [0.2.7] - 2026-07-02

Determinism hardened end to end — real-inference byte-identity, deterministic history import, change-set session reconcile — plus the Accelerate compute default and wider parser fidelity.

### Added

- Apple Accelerate is the compiled CPU-BLAS default for `kin` and `kin-daemon` (`metal`+`accelerate` features). Proof and freeze paths stay pinned to the deterministic pure-Rust backend via `KIN_INFER_CPU_BACKEND=pure-rust`; the gate re-proved bit-identical embeddings across five independent cache-cold runs on the new default.
- Behavior-environment divergence warnings: the daemon's `/health` reports its effective behavior-relevant environment, and env-sensitive commands warn per diverging variable (value on each side plus the remedy) when the invoking shell's `KIN_*` levers differ from the running daemon's. `KIN_STRICT_BEHAVIOR_ENV=1` escalates the warning to an error.
- The environment registry now covers downstream sibling-crate levers (CPU backend, occupancy dispatch, embed backend/hybrid family, embed cache, VFS bypass, container workspace/storage selectors) with honest classification — live levers are no longer mislabeled as unrecognized typos — and a completeness test keeps kin's own env reads registered.
- MCP `semantic_locate` hits on the default profile carry `start_line`/`end_line` from the entity span, and `semantic_search` clamps caller-supplied limits to the shared maximum.
- Parser fidelity: Rust `macro_rules!` definitions extract as first-class `Macro` entities (`#[macro_export]`-aware visibility), C and C++ `union` declarations extract as entities in both adapters, and Java `record` / `@interface` declarations extract as classes and interfaces respectively.
- Update channels for `kin update` and a `kin doctor --drift` surface for projection-drift inspection.
- Entity re-key and port-handshake hardening in the daemon; write-veto warnings on protected paths; `--explain` output carries the active retrieval profile; entity-centric locate output improvements.

### Changed

- Session-workspace reconcile is change-set based: materialization records the workspace's base (projected graph head plus per-file content hashes), and reconcile replays only the workspace's own delta. Files the workspace never touched are left untouched when the source has advanced; both-moved divergence fails loudly naming each conflicting file — newer source truth is never silently overwritten. Legacy workspaces without a recorded base apply pure additions only.
- Git history import selects and orders commits by a content-total order at commit-time ties, so two preps of identical history produce identical change partitions and revision ids (the long-standing cross-prep retrieval-variance root).
- Container entrypoint resolves a writable workspace identically in both storage modes (`KIN_WORKSPACE_DIR` override, `/tmp/kin-workspace` default backed by an emptyDir), materializes a complete repository layout, and owns the authoritative `--repo` argument; unwritable resolution fails with one actionable diagnostic. The docker workflow gains a creds-free entrypoint smoke covering both modes.
- `quick-xml` is pinned under the dependency deny policy.

### Fixed

- The stale-kept-workspace data-loss edge on `kin exec` / `kin run` / `kin shell` / `kin with --session` closeout (see the reconcile change above).
- Object lookups during parallel history import retry once before failing loud, closing a transient loose-object miss window under concurrency.
- Multi-commit test fixtures across the workspace carry explicit increasing timestamps, removing wall-clock dependence from order-sensitive suites.

## [0.2.6] - 2026-07-01

Session-aware runtime, a shadow-mode merge gate, a hardened first-run installer, and a central environment registry.

### Added

- Retrieval quality profiles (`KIN_PROFILE`): `compat-v0` (default, the pre-profile serving behavior) and `accuracy-v1` (opt-in candidate: fused `semantic_locate` serving, entity-granularity fusion, lexical parity floor, promotion-only cross-encoder blend). Both ship structured `degradations[]` reporting and a per-stage prune ledger for miss forensics; the candidate graduates to default only on measured wins.
- Go interface methods are extracted as first-class graph entities, closing a symbol-recall gap on Go codebases.
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
- `kin-daemon --compat-json` emits its payload before logging or env validation can write to stdout, so a `KIN_*` override warning can no longer corrupt the CLI's daemon-compat probe into a spurious "daemon stale" failure; a regression test guards the probe's stdout purity.

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

[unreleased]: https://github.com/firelock-ai/kin/compare/v0.2.20...HEAD
[0.2.20]: https://github.com/firelock-ai/kin/compare/v0.2.19...v0.2.20
[0.2.19]: https://github.com/firelock-ai/kin/compare/v0.2.18...v0.2.19
[0.2.18]: https://github.com/firelock-ai/kin/compare/v0.2.17...v0.2.18
[0.2.17]: https://github.com/firelock-ai/kin/compare/v0.2.16...v0.2.17
[0.2.16]: https://github.com/firelock-ai/kin/compare/v0.2.15...v0.2.16
[0.2.1]: https://github.com/firelock-ai/kin/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/firelock-ai/kin/compare/v0.1.0-alpha.25...v0.2.0
[0.1.0-alpha.25]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.25
[0.1.0-alpha.5]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.1
