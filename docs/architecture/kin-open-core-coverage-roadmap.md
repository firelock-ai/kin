# Kin Open-Core Coverage Roadmap

This document defines how the **public Kin core** expands language and file coverage over time.

The goal is not "AST support for every file." The goal is:

- **every file in a repo is represented**
- **semantic depth is explicit and honest**
- **unsupported files degrade gracefully instead of failing indexing**
- **the current high-value languages become excellent before breadth explodes**

This roadmap applies to the open local-first Kin core in this repository. It does **not** cover hosted federation, org-graph infrastructure, or other proprietary layers.

## 1. Current State

Today, the public core already has the right foundation:

- full tree-sitter adapters for **TypeScript, JavaScript, Python, Go, Java, and Rust**
- a `TrackedFile` model with:
  - `EntitySource`
  - `StructuredArtifact`
  - `OpaqueArtifact`
- inline `TODO` / `FIXME` / `HACK` import for supported source files
- end-to-end acceptance coverage in `tests/integration/`

The main gaps are:

- unsupported source files still fail indexing instead of degrading
- `TrackedFile` artifact variants exist in the model but are not yet the default indexing path
- structured repo files like `Dockerfile`, manifests, CI configs, and migrations are not yet first-class in the indexing pipeline
- the current supported languages still need stronger **cross-file relations** and better semantic confidence before breadth should expand aggressively

## 2. Product Promise

The open-core promise for coverage is:

> Kin never drops a file. It indexes every repo with the best semantic depth it can honestly provide.

That means:

- a file may be deeply semantic
- a file may be shallow but still queryable
- a file may be structured but not "code"
- a file may be opaque but still tracked

But a file should not disappear from Kin just because no rich parser exists yet.

## 3. Coverage Model

Kin should publish support as **coverage levels**, not a fake binary supported/unsupported flag.

### C0: Opaque

The file is tracked as content plus metadata only.

What Kin knows:

- path
- content hash
- MIME hint if available
- work items, notes, provenance, and change history can still attach to it

Examples:

- images
- binary assets
- unknown extensions
- generated blobs with no useful structure

### C1: Structured Artifact

The file is not source code in the entity/relation sense, but it has meaningful structure.

What Kin knows:

- artifact kind
- normalized semantic fingerprint
- key semantic fields
- artifact-level change tracking
- work items and annotations scoped to the artifact

Examples:

- `Dockerfile`
- `Cargo.toml`
- `package.json`
- `pyproject.toml`
- CI YAML
- `Makefile`
- SQL migrations
- Terraform / Compose / Kubernetes manifests

### C2: Shallow Syntax

The file has a parser or grammar, but Kin only extracts safe coarse structure.

What Kin knows:

- top-level declarations or blocks
- imports / includes when reliable
- spans and stable-ish fingerprints
- comments / TODO import

What Kin does **not** claim here:

- strong relation accuracy
- merge confidence equal to tier-1 languages
- rich semantic review quality

This tier exists to avoid a false choice between "full semantic support" and "opaque blob."

Implementation note:

- tree-sitter or another real parser is preferred
- **narrow regex helpers are acceptable** for bounded tasks such as import sniffing, TODO/comment capture, or bootstrap declaration detection
- regex output at this tier must stay low-confidence and must not be promoted into strong semantic guarantees

### C3: Entity Extraction

Kin can identify stable semantic entities within the file.

What Kin knows:

- functions, classes, types, methods, modules, and similar entities
- entity fingerprints
- entity history and blame lineage
- entity-scoped work items and annotations

### C4: Intra-File Semantics

Kin can extract relations within the file with useful confidence.

What Kin knows:

- calls
- inheritance / implements
- references
- imports within confidence boundaries

### C5: Cross-File Semantics

This is the mature tier.

What Kin knows:

- cross-file relations
- projection and reconcile confidence
- meaningful impact analysis
- stronger merge and review quality
- high-confidence semantic blame and context packs

## 4. Architectural Direction

Kin should follow a **four-lane indexing strategy**:

1. **Full semantic source**
   - tree-sitter + rich extraction
   - used for current tier-1 languages and future high-confidence adapters

2. **Shallow syntax source**
   - grammar-backed, conservative extraction only
   - no regex swamp
   - no pretending weak guesses are full semantics

3. **Structured artifact**
   - dedicated extractors for repo infrastructure files
   - canonical normalization and artifact-specific fingerprints

4. **Opaque artifact**
   - universal fallback when nothing better is available

The indexing invariant should be:

> blob write succeeds -> file classification succeeds -> Kin stores something useful, even when rich parsing is unavailable

Regex is acceptable in the open core when used as a **scoped utility**, not as the semantic foundation:

- good uses:
  - TODO extraction
  - simple import/include sniffing
  - artifact classification by filename or header
  - bootstrap symbol detection for shallow tiers
- bad uses:
  - pretending regex understands full language semantics
  - high-confidence relation extraction across a real codebase
  - merge or projection logic that depends on fragile text guesses

## 5. Priority Order

### Priority A: Make the current six languages excellent

Before aggressively expanding breadth, the open core should harden the supported languages:

- cross-file relation resolution
- stronger projection round-trips
- better merge confidence
- more stable fingerprints across refactors and formatting churn
- clearer coverage metrics per language

If TypeScript, Python, Rust, Go, Java, and JavaScript are only half-semantic, adding 20 more languages will dilute the product.

### Priority B: Never-drop indexing

The next structural step is making unsupported files degrade gracefully instead of erroring.

That means the indexing pipeline should:

- classify every file before extraction
- route unsupported code to `ShallowSyntax` or `OpaqueArtifact`
- route repo infrastructure files to `StructuredArtifact`
- always store the blob and metadata

### Priority C: First-class repo artifacts

These should be the first structured extractors in the public core:

- `Dockerfile`
- `Cargo.toml`
- `package.json`
- `pyproject.toml`
- GitHub Actions / CI YAML
- `Makefile`
- SQL migrations

These files carry huge operational meaning and often matter more than adding a weak adapter for the fifteenth programming language.

### Priority D: Language expansion through adapter depth

After universal fallback and artifact coverage are in place, language expansion should grow by depth:

- start at `C2` when a grammar exists but rich semantics are not ready
- move to `C3` / `C4` as entity and relation extraction stabilizes
- only claim `C5` once cross-file semantics, projection, and merge behavior are proven

## 6. Artifact Fingerprints

Non-code files need semantic fingerprints too.

Kin should fingerprint artifacts by **normalized meaning**, not raw text formatting.

### Dockerfile

Normalize and hash:

- stage list and order
- `FROM`
- `COPY` / `ADD`
- `RUN`
- `ENV`
- `EXPOSE`
- `ENTRYPOINT` / `CMD`

Ignore:

- whitespace
- comments
- formatting-only churn

### Package manifests

For `Cargo.toml`, `package.json`, and `pyproject.toml`, normalize and hash:

- package identity
- dependencies and versions
- workspace membership
- scripts / entry points where meaningful

Ignore:

- key order when the format is semantically unordered
- whitespace and formatting

### CI configs

Normalize and hash:

- jobs
- step order
- action references
- commands
- environment configuration

### Makefiles

Normalize and hash:

- targets
- dependencies
- recipe bodies

### SQL migrations

Normalize and hash:

- migration identity
- create / alter / drop operations
- touched tables / objects

Ignore:

- whitespace-only changes
- comments that do not affect execution

## 7. Test Strategy

Coverage work should be tested with a capability matrix, not only crate-level unit tests.

### Unit tests

For each adapter or extractor:

- parse / classify success
- fingerprint normalization
- graceful failure behavior
- no false claims beyond the declared coverage tier

### Golden fixtures

Each language and artifact kind should have fixtures with expected:

- entities
- relations
- artifact facts
- fingerprints
- TODO extraction behavior

### Mixed-repo acceptance

Acceptance tests should cover real mixed repositories with:

- code
- manifests
- infra files
- unsupported extensions
- broken syntax

Core assertions:

- Kin does not drop files
- unsupported files remain queryable
- structured artifacts are classified correctly
- opaque files remain tracked and attachable

### Corpus runs

Corpus testing should be an optimization loop, not a ship blocker.

Run Kin against a small set of real repos and record:

- files indexed
- files by coverage tier
- unsupported extensions seen
- parse success rate
- fallback rate
- round-trip stability

The first corpus should come from real repos in `~/GitHub`, then expand over time.

## 8. Contributor Model

Language and artifact expansion should be cheap to contribute.

The public core should eventually provide:

- a documented adapter trait
- a conformance checklist
- a fixture format
- a coverage-tier declaration per adapter
- a regression suite for fingerprints and extraction quality

The goal is that adding a language or artifact extractor feels like:

> implement extractor -> declare coverage tier -> pass conformance suite

not:

> modify core behavior ad hoc until tests happen to pass

## 9. Open-Core Scope

This entire coverage roadmap belongs in the **open local-first Kin core**.

That includes:

- parser and extractor expansion
- artifact classification
- fallback indexing
- coverage metrics
- adapter SDK and conformance tests
- mixed-repo corpus testing

This work should **not** be held back for proprietary layers. Better universal coverage and better semantic depth are core product quality, not enterprise add-ons.

## 10. Implementation Sequence

The recommended build order is:

1. **Harden the current six languages**
   - finish cross-file relations
   - improve semantic confidence where Kin already claims support

2. **Add file classification to `kin-index`**
   - never-drop indexing
   - route files into semantic source, structured artifact, or opaque fallback

3. **Add first-class structured artifact extractors**
   - start with `Dockerfile`, manifests, CI, `Makefile`, and SQL migrations

4. **Add shallow syntax support where grammars already exist**
   - conservative extraction only
   - prefer real parsers, but allow scoped regex utilities where they keep the fallback practical

5. **Expand language coverage with a contributor path**
   - adapter kit
   - conformance suite
   - published coverage matrix

6. **Run recurring corpus checks on real repos**
   - measure what actually breaks
   - prioritize by repo pain, not abstract language popularity

## 11. Success Criteria

This roadmap is working when:

- unsupported files no longer hard-fail indexing
- Kin can index mixed-language repos without semantic blind spots at the repo level
- repo infrastructure files become first-class graph objects
- current tier-1 languages provide useful cross-file context
- language support can grow without turning the parser layer into an unmaintainable mess

The end-state is:

> universal repo coverage, variable semantic depth, and honest guarantees.
