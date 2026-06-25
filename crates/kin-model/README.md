# kin-model

> Canonical types and domain models for Kin's semantic VCS.

`kin-model` contains the canonical shared types for Kin's semantic repository
substrate.

It defines the graph objects that the public Kin stack uses across the local
engine, CLI, daemon, MCP server, projection layer, and supporting crates:

- entities, artifacts, relations, revisions, and retrieval keys
- sessions, intents, locks, traffic reports, and coordination events
- review, work, provenance, verification, and temporal records
- projection, reconciliation, preset, and policy types

This crate is intentionally small and dependency-light. It is the schema and
domain boundary for the open local substrate, not the hosted KinLab control
plane.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the semantic system of record for AI-native software — your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

## Versioning & release policy

`kin-model` is the **release/version source of truth** for the canonical Kin
types. Downstream crates (`kin`, `kin-db`, `kin-bench`, …) pin it from the `kin`
cargo registry, so its version is a compatibility contract, not just a label.

**Semver (pre-1.0).** While the crate is `0.MINOR.PATCH`:

- **MINOR bump** (`0.2.x → 0.3.0`) for any **API-affecting / breaking** change —
  renamed/removed/retyped public items, changed serialization, new required
  fields. Cargo treats `0.2` and `0.3` as incompatible, so this is what forces
  downstream consumers to move deliberately.
- **PATCH bump** (`0.2.0 → 0.2.1`) for additive, backward-compatible changes and
  fixes (new optional items, docs, internals).

**The registry is immutable.** A published `(name, version)` can never be
overwritten. So **every change you intend to publish must carry a new, not-yet-
published version** — there is no way to ship a fix under an already-published
number. `scripts/publish-kinlab-crates.sh` refuses to re-publish an existing
version (it reads the index first and skips), and `scripts/check-version-bump.sh`
fails CI when `src/` changes without a version move.

**Downstream bump + smoke process.** When you make a breaking (MINOR) bump:

1. Bump `version` in `Cargo.toml`.
2. Update the affected `req` values in [`downstream-pins.json`](downstream-pins.json)
   — the declared contract of which version each downstream consumer pins. This
   is the explicit, reviewable signal that those repos must move.
   `scripts/check-downstream-pins.sh` fails CI if any declared pin cannot accept
   the version you are about to publish.
3. After the new version publishes, each downstream repo bumps its `kin-model`
   pin and runs the fresh-cache consumer smoke
   (`scripts/registry-consumer-smoke.sh <version>`), which builds a throwaway
   consumer against the published registry from an empty cache — proving the new
   release actually resolves and builds, not just that it packaged.

These three scripts (version-bump gate, downstream-pin compatibility, fresh-cache
consumer smoke) run in CI; see `.github/workflows/`.

## License

[Apache-2.0](LICENSE).
