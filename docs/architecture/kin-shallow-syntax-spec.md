# Kin C2 Shallow Syntax Spec

This document defines the **C2 shallow syntax tier** for the open-core Kin repository.

The purpose of `C2` is simple:

> make more source files queryable and classifiable without overstating semantic confidence

`C2` is not a weaker version of `C5`. It is a separate tier with tighter guarantees.

## Goal

When Kin has a parser or grammar for a file class but does not yet support rich semantic extraction, Kin should still be able to:

- represent the file as source, not just as an opaque blob
- extract safe top-level structure
- surface shallow declarations, imports/includes, and TODO/comment signals
- provide stable-enough file-level fingerprints and parse health
- expose this honestly in `kin support`, search, and context

## Non-Goals

`C2` must **not** claim:

- strong call graph accuracy
- strong cross-file resolution
- semantic merge confidence equal to tier-1 languages
- projection/reconcile authority equal to `C5`
- entity-stable blame guarantees equal to full semantic support

If Kin cannot defend a semantic claim, it should stay out of `C2`.

## Coverage Ladder

- `C0`: opaque artifact
- `C1`: structured artifact
- `C2`: shallow syntax
- `C3`: entity extraction
- `C4`: intra-file semantics
- `C5`: cross-file semantics

`C2` sits between “I know this file is code” and “I deeply understand this file.”

## Canonical C2 Payload

The open core should introduce a parser output shape like:

```rust
pub struct ShallowFile {
    pub file_id: FilePathId,
    pub language_hint: Option<LanguageId>,
    pub parse_state: ParseState,
    pub declarations: Vec<ShallowDecl>,
    pub imports: Vec<ShallowImport>,
    pub todos: Vec<TodoSeed>,
    pub fingerprint: ShallowFingerprint,
}

pub struct ShallowDecl {
    pub kind: ShallowDeclKind,
    pub name: String,
    pub span: SourceRegion,
}

pub enum ShallowDeclKind {
    FunctionLike,
    TypeLike,
    ModuleLike,
    ConstantLike,
    Unknown,
}

pub struct ShallowImport {
    pub raw_path: String,
    pub alias: Option<String>,
    pub span: Option<SourceRegion>,
}

pub struct ShallowFingerprint {
    pub syntax_hash: Hash256,
    pub signatureish_hash: Option<Hash256>,
}
```

This does **not** need to be stored under those exact names, but the semantics should match.

## Architectural Rules

### 1. Parser-backed first

`C2` should prefer real parsers or grammars.

Allowed helpers:

- TODO/comment extraction
- simple import/include sniffing
- bootstrap declaration detection

Not allowed as the main implementation:

- broad regex-only pseudo-parsing
- fragile cross-file relation inference

### 2. Conservative storage

`C2` files should be persisted distinctly from:

- `StructuredArtifact`
- `OpaqueArtifact`
- full `EntitySource`

The UI and CLI must be able to say: “this file is shallow syntax.”

### 3. Conservative downstream behavior

`C2` can participate in:

- support reporting
- semantic search
- context packs
- TODO import
- file-level fingerprint change detection

`C2` must not silently participate in:

- strong merge resolution
- high-confidence impact claims
- automatic semantic blame promises

## Minimum Open-Core Behavior

To count as a valid `C2` implementation, a file should provide:

1. classification as `C2`
2. parse health (`complete` / `incomplete`)
3. top-level declaration list
4. import/include list when reliable
5. TODO/comment seeds
6. normalized shallow fingerprint

## Search and Context Behavior

`C2` should improve the user experience immediately in two places:

### Search

`kin search` should be able to return:

- shallow declaration names
- file path
- language hint
- coverage tier `C2`

### Context

`kin context` should be able to include:

- shallow declarations
- shallow imports
- TODOs / notes attached to the file
- explicit warning that the file is shallow syntax, not full semantics

## Support Reporting

`kin support` should report `C2` explicitly.

Minimum report fields:

- total files by `C0` / `C1` / `C2` / `C3+`
- per-extension counts
- parse success/failure counts for `C2`
- note that `C2` is read-mostly semantic coverage

## Acceptance Criteria

A `C2` pilot is complete when:

1. at least one real file class can be classified as `C2`
2. `kin support` reports those files as `C2`
3. `kin search` can surface shallow declarations from them
4. `kin context` can include shallow declarations/imports/TODOs
5. tests prove `C2` files are not treated as `C5` during merge/review/projection

## Recommended Pilot Strategy

Do not start with many languages at once.

Pick one of:

- a single language/parser where a grammar exists but Kin lacks full extraction depth
- a generic parser-backed shallow mode for files that parse but do not have a rich adapter yet

Good pilot success criteria:

- narrow scope
- visible CLI value
- no semantic overclaim
- no interference with current tier-1 language behavior

## Audit Rules

Codex should reject a `C2` implementation if:

- it is mostly regex pretending to be language understanding
- it feeds strong merge or impact decisions
- it is not visible in support reporting
- it lacks acceptance coverage proving conservative behavior
