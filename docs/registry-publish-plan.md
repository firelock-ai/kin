<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Firelock, LLC
-->

# Registry Publish Plan — determinism-fix crates

**Status:** PLAN ONLY. Nothing is published by this document. `cargo publish`
requires the kin-registry token, which is Troy-gated. This is the exact
command sequence to run once that decision lands.

**Registry:** `sparse+https://kinlab.ai/registry/cargo/` (alias `kin`).
Download endpoint: `https://kinlab.ai/registry/cargo/dl/{crate}/{version}`.

**Verified:** 2026-06-11 by diffing the *published tarball* `src/` of every
kin registry crate against its repo `main` `src/` (the rigorous check — not
git-log inference). Method: `curl .../dl/<crate>/<ver>` → `tar xzf` → `diff -rq`.

---

## 1. What is unpublished (verified by tarball diff vs main)

| Crate | Published | main version | src changed? | Needs bump? | Why |
|---|---|---|---|---|---|
| **kin-infer** | 0.2.0 | 0.2.0 | **5 files** (lib, metal_backend, cuda_backend, gpu, watchdog) | **YES → 0.2.1** | Metal batched-embedding bit-determinism (58a38f0 concat-cache collision; d182105/8dcbf73 threadgroup_barrier), typed `InferError`, metal-as-Linux-no-op |
| **kin-vector** | 0.1.0 | 0.1.0 | **1 file** (lib.rs) | **YES → 0.1.1** | HNSW determinism (efe77db stable-key level/tie-breaks; af0af40 entry-point reselection); additive APIs `IndexDescriptor`/`keys()`/`load_checked()`/`descriptor()` that kin-db **already consumes** |
| **kin-db** | 0.1.0 | 0.1.0 | **5 files** (engine/graph, storage/snapshot, storage/tiered, vector/hnsw, vector/mod) | **YES → 0.1.1** | ad52251 sort entity ids before vector invalidation; 1e0ec81 deterministic insert/evict; consumes kin-vector self-description APIs |
| **kin-blobs** | 0.1.0 | 0.1.0 | **1 file** (lib.rs, 289 lines) | **YES → 0.1.1** | Atomic **and durable** blob writes — fsync contents + rename + fsync dir (crash-safety for content-addressed objects) |
| **kin-search** | 0.1.0 | 0.1.0 | **1 file** (lib.rs, 352 lines) | **YES → 0.1.1** | Typed `CorruptIndex` error (archive-and-rebuild instead of brick) + durable index persistence (fsync, unique temp paths) |
| kin-model | 0.1.0 | 0.1.0 | none | no | matches published |
| kin-vfs-core | 0.1.0 | 0.1.0 | none | no | matches published |
| kin-lsp | 0.1.0 | 0.1.0 | none | no | matches published |

> Scope note: the relops task scoped this to **kin-vector + kin-infer**, but the
> verified tarball diff shows **kin-db, kin-blobs, kin-search** also carry
> unpublished `src` changes at their current published version. They are
> included here so the publish is complete — a partial publish (vector+infer
> only) would leave kin-db **uncompilable against the registry** (it now calls
> `kin-vector::keys()`/`IndexDescriptor`, absent from published 0.1.0) and would
> ship none of the kin-db/blobs/search durability+determinism fixes. Lead to
> confirm whether to publish the full set or a subset.

## 2. Bump levels (pre-1.0 cargo semver)

All bumps are **PATCH** (`0.1.0 → 0.1.1`, `0.2.0 → 0.2.1`). Rationale:

- Cargo treats `0.1.x` versions as mutually compatible and `0.1` vs `0.2` as
  **incompatible**. A *minor* bump (e.g. kin-vector 0.1.0 → 0.2.0) would break
  every `kin-* = "0.1.0"` (`^0.1.0`) requirement in kin-db **and** kin, forcing
  requirement edits across the tree. A patch bump is picked up automatically.
- All changes are **additive** (new pub items / new enum variant / internal
  durability), so existing consumers still compile.

**Caveats to confirm with `cargo publish --dry-run` (and ideally
`cargo-semver-checks`) before each publish:**

- **kin-search**: adds enum variant `CorruptIndex`. If `KinSearchError` is not
  `#[non_exhaustive]`, this is technically breaking for an exhaustive external
  matcher. The only consumer is kin-db (which we control, and which falls back
  on `open` errors rather than exhaustively matching). Recommend adding
  `#[non_exhaustive]` to the error enum as hardening; still ship as 0.1.1.
- **kin-infer**: typed-error conversion. The crate's `lib.rs` public-fn
  signatures are unchanged vs published 0.2.0 (verified: no `pub fn`/`pub
  struct` signature lines in the diff), so 0.2.1 is correct. If `--dry-run` +
  semver-checks flag a public break, bump to **0.3.0** instead — safe because
  kin-db requires `kin-infer >=0.1.1` (open upper bound, accepts 0.3.0).

## 3. Dependency order (topological)

Leaves first; each `cargo publish` verifies its deps resolve from the live
registry, so a dependent cannot be published until its deps' new versions are
indexed.

```
Wave A  (leaves — no kin-* deps; publish in any order, parallel-safe)
   kin-blobs  0.1.1
   kin-search 0.1.1
   kin-vector 0.1.1
   kin-infer  0.2.1
        │   (kin-model 0.1.0 unchanged — do NOT republish)
        ▼
Wave B  (depends on Wave A)
   kin-db 0.1.1     — needs kin-vector 0.1.1, kin-search 0.1.1, kin-infer 0.2.1 live
        ▼
Wave C  (consumer — NOT a registry crate; not published)
   kin              — refresh the registry-flavoured Cargo.lock to pull the new
                      versions; commit the lock. This is what delivers the
                      determinism fixes into kin's build + the eval.
```

Dependency facts (from `crates/kin-db/Cargo.toml`):
`kin-model = "0.1.0"` (unchanged), `kin-infer = ">=0.1.1"` (accepts 0.2.1),
`kin-vector = "0.1.0"` (^0.1.0 → accepts 0.1.1), `kin-search = "0.1.0"`
(^0.1.0 → accepts 0.1.1). kin-blobs/kin-search/kin-vector/kin-infer have **no**
kin-* deps.

## 4. Required Cargo.toml edits before publishing

Version strings live at the crate root unless noted:

- `kin-infer/Cargo.toml`  → `version = "0.2.1"`
- `kin-vector/Cargo.toml` → `version = "0.1.1"`
- `kin-blobs/Cargo.toml`  → `version = "0.1.1"`
- `kin-search/Cargo.toml` → `version = "0.1.1"`
- `kin-db/Cargo.toml` `[workspace.package]` → `version = "0.1.1"` (kin-db crate
  inherits via `version.workspace = true`), **and** in
  `kin-db/crates/kin-db/Cargo.toml` raise the dep floors so a fresh resolve
  cannot pick the old, API-incompatible versions:
  - `kin-vector = { version = "0.1.1", registry = "kin", optional = true }`
  - `kin-search = { version = "0.1.1", registry = "kin" }`
  - `kin-infer  = { version = ">=0.2.1", registry = "kin", optional = true }`
    (forces the determinism build; current `>=0.1.1` would also *accept* 0.2.1
    but does not *require* it)

## 5. Exact publish command sequence

```bash
ECO=/Users/troyfortinjr/GitHub/kin-ecosystem

# 0. One-time auth (Troy-gated token). Either:
export CARGO_REGISTRIES_KIN_TOKEN="<KIN_REGISTRY_TOKEN>"
#    or:  cargo login --registry kin "<KIN_REGISTRY_TOKEN>"
# Each repo must be able to resolve the 'kin' registry alias. If a repo lacks
# .cargo/config.toml (it is gitignored), create the alias-only file first:
#   printf '[registries.kin]\nindex = "sparse+https://kinlab.ai/registry/cargo/"\n' > .cargo/config.toml

# --- WAVE A : leaves (bump version, dry-run, then publish) ---
cd "$ECO/kin-blobs"  && cargo publish --registry kin --dry-run && cargo publish --registry kin
cd "$ECO/kin-search" && cargo publish --registry kin --dry-run && cargo publish --registry kin
cd "$ECO/kin-vector" && cargo publish --registry kin --dry-run && cargo publish --registry kin
cd "$ECO/kin-infer"  && cargo publish --registry kin --dry-run && cargo publish --registry kin

# --- Gate : confirm Wave A is indexed before Wave B ---
for c in kin-blobs kin-search kin-vector kin-infer; do
  echo -n "$c -> "; curl -sS "https://kinlab.ai/registry/cargo/ki/n-/$c" | tail -1 \
    | python3 -c "import sys,json;print(json.loads(sys.stdin.read()).get('vers'))"
done   # expect 0.1.1 / 0.1.1 / 0.1.1 / 0.2.1

# --- WAVE B : kin-db (after Wave A live; Cargo.toml edits from §4 applied) ---
cd "$ECO/kin-db" && cargo publish --registry kin -p kin-db --dry-run \
                 && cargo publish --registry kin -p kin-db

# --- WAVE C : kin consumer (NOT published — refresh the registry lock) ---
cd "$ECO/kin"
# .cargo/config.toml must contain ONLY [registries.kin] (no [patch]) for a
# registry-only resolve — same shape used to generate the committed lock.
cargo update -p kin-blobs -p kin-search -p kin-vector -p kin-infer -p kin-db
cargo check --workspace --locked        # must pass before committing
git add Cargo.lock
git commit -s -m "build: pull determinism-fix registry crates into lock

kin-blobs 0.1.1, kin-search 0.1.1, kin-vector 0.1.1, kin-infer 0.2.1, kin-db 0.1.1"
```

## 6. Caveats / preconditions

- **In-flight branches change the publish point.** Do not publish until the
  following land on each crate's `main`, or the published version will lag:
  - kin-infer task #1 *LAYER 7* (batch/context-invariant embeddings) —
    worktree `kininfer-wt-l7`. If it lands API changes, re-evaluate 0.2.1 vs 0.3.0.
  - kin-vector self-description — worktree `kinvector-wt-sd`.
  - kin-db vector-determinism — worktree `kindb-wt-det`.
  Publish **after** these merge so the registry reflects final determinism state.
- **Index propagation:** the Wave-A→B gate (curl the sparse index) is required;
  a custom registry may not serve a just-published version instantly.
- **Always `--dry-run` first** — it packages + verifies the registry resolve
  without uploading; catches a missing dep or a semver break before it is
  permanent (published versions cannot be overwritten, only yanked).
- **kin is not a registry crate** (the index serves model/blobs/lsp/db/
  vfs-core/search/vector/infer — not `kin`). Wave C only updates kin's lock.
- After Wave C, the registry-flavoured lock check restored in CI
  (`cargo build/test --locked`) will enforce the new versions on every build.
