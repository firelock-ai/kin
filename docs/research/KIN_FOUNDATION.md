# Kin Foundation

**Date:** March 10, 2026  
**Purpose:** Consolidate the research, product analysis, naming work, and first-principles strategy for building Kin.

## Decision Snapshot

- **Product name:** `Kin`
- **Working research folder:** `/Users/troyfortinjr/GitHub/kin`
- **Core thesis:** AI coding tools are constrained by file-based storage. Kin should treat code as a graph of semantic entities and relationships, then serve precise context to agents and developers.
- **Initial wedge:** local-first semantic context + MCP server, not a full Git replacement on day one

## The Core Insight

The strongest idea across all of the research is simple:

**Git tracks text history. AI needs code relationships.**

Modern AI coding tools still operate on files, chunks, and token stuffing. That creates predictable failures:

- too much irrelevant context
- weak cross-file reasoning
- brittle large-repo performance
- line-level diffs for logic-level changes
- poor trust when agents do not understand architecture

Kin should solve that by indexing code as semantic entities:

- functions
- classes
- types
- API contracts
- tests
- modules

And then linking them through relationships:

- calls
- imports
- implementations
- ownership
- type references
- test coverage
- change history

That relationship layer is the real product.

## What Holds Up From the Research

Several parts of the original SCG thesis are strong and worth carrying forward:

1. **A semantic graph is a better AI substrate than files.**  
   Tree-sitter, code graphs, structural diffing, incremental analysis, and graph-based retrieval are all real and technically grounded.

2. **Context delivery is the best wedge.**  
   The most credible first product is not a new VCS. It is a context engine that gives agents the right code neighborhood under a token budget.

3. **Local-first + MCP is the right entry point.**  
   It matches current tool adoption, minimizes workflow disruption, and gives immediate value inside Claude Code, Cursor, Codex, and similar tools.

4. **Benchmarking should be part of the product.**  
   Proving better context quality, lower token waste, and stronger impact analysis on a customer's own repo is a major advantage.

5. **Git compatibility matters.**  
   Teams will adopt an augmentation layer much faster than a full platform replacement.

## What Needs Tighter Framing

The concept is stronger than some of the pitch language around it. The following claims should be tightened:

1. **Do not lead with "GitHub killer."**  
   That is an end-state fantasy, not the right opening product story.

2. **Do not say "nobody has built this" too broadly.**  
   CodeQL, Kythe, Sourcegraph, Augment, and Ataraxy each cover pieces of the space.

3. **Do not overstate semantic merge.**  
   Structural merge is valuable. Semantic conflict detection is still genuinely hard.

4. **Do not overclaim benchmark numbers as universal truths.**  
   GraphRAG and structural diff data are useful support, but product messaging should stay repo-specific and measurable.

The right framing is:

**Kin is the relationship layer that lets AI understand codebases like systems, not files.**

## Recommended Product Direction

### Phase 1: The Real MVP

Build the smallest version that proves the thesis on live repositories.

Core commands:

- `kin index`
- `kin search`
- `kin context`
- `kin impact`
- `kin diff`
- `kin mcp`

Core capabilities:

- parse TS/JS and Python first
- extract entities and references
- map imports, callers, types, and tests
- answer "what is related to this change?"
- produce a context bundle under a fixed token budget
- expose that through MCP

This should be positioned as:

**Kin gives AI agents just-in-time semantic context for real codebases.**

### Phase 2: Proof and Expansion

Once the context engine is reliable:

- add repo benchmark mode
- add CI impact analysis
- add semantic docs / agent context generation
- add better diffing and change explanation

### Phase 3: Harder Platform Moves

Only after the above works:

- structural merge
- org-wide graph and memory
- multi-agent orchestration
- deeper Git bridge behavior

## Recommended Technical Shape

### Architecture

- **Core engine:** Rust
- **Parsing:** Tree-sitter
- **Semantic enrichment:** LSP / SCIP / compiler metadata where available
- **Storage:** local embedded store first, not a heavy distributed graph stack
- **Interface:** CLI + MCP server

### Data Model

Treat the codebase as:

- **entities** as first-class objects
- **edges** as typed relationships
- **snapshots** for incremental updates
- **context packs** as product output

### Product Principle

Do not try to prove semantic purity first. Prove usefulness first.

That means:

- accurate entity extraction
- fast graph updates
- high-signal context bundles
- reliable impact analysis
- obvious ROI on large repos

## The Best Positioning

The strongest positioning from all the analysis is:

**Kin is semantic context infrastructure for AI-native software development.**

Secondary variants:

- Kin is the code relationship graph for AI agents.
- Kin gives coding agents the exact code they need, not entire files.
- Kin turns a repo into a queryable semantic system.

The most important distinction:

- **Git** remains the system of record for history and collaboration.
- **Kin** becomes the system of understanding for code and agents.

## Name Decision

### Why The Earlier Names Fell Short

- `ctx` had baggage and weak ownership
- `syn` was too occupied, especially in Rust
- `neu` was light on metrics but weak in speech and search
- `nod` was more crowded than it first appeared

Many short names were already claimed across npm, PyPI, crates.io, or GitHub. The cleanest names numerically were not always the best names strategically.

### Why `Kin`

`Kin` works because it is:

- short
- easy to type
- easy to say
- distinct enough to brand
- directly connected to relationships, lineage, and code kinship

The narrative that makes it work:

- Git is the file-era ancestor.
- Kin is the AI-era descendant.
- Git tracks changes to text.
- Kin tracks relationships in code.

That makes Kin feel like a next-step evolution rather than a random AI brand.

### How To Relate `Kin` Back To The Concept

Use language around:

- lineage
- relationships
- code kinship
- born from Git, but built for AI
- related code, not just adjacent files
- semantic neighborhoods and dependency families

Good internal framing:

**Kin is what comes after file-based source control when AI needs structure, not blobs.**

Good external framing:

**Git stores the past. Kin understands the code.**

### Naming Guidance

Do not force a public acronym. The word is stronger than the acronym.

`Kin` already carries the right meaning:

- code related by calls, imports, types, and tests
- the next generation after Git
- a graph of relationships instead of a pile of files

The product should simply be called **Kin**.

## Why This Can Matter

If Kin works, it matters because it attacks the actual bottleneck in AI coding:

- not model quality alone
- not editor UX alone
- not prompt tricks

The bottleneck is getting the right code understanding into the model at the right time.

That is the wedge with the best chance of becoming foundational infrastructure.

## Immediate Build Priorities

1. Create a minimal Rust CLI.
2. Support indexing for TS/JS and Python.
3. Define the first entity and edge schema.
4. Build `kin context` and `kin impact` first.
5. Add MCP exposure.
6. Build a benchmark mode on real repos.

## Success Criteria For The First Version

The first version should prove:

- lower token usage than file-based context assembly
- better relevance in context returned
- faster impact analysis across files
- useful outputs in monorepos and medium-sized repos
- clear value inside existing AI coding workflows

## Research Assets Moved Into This Folder

- `SCG_PRODUCT_ARCHITECTURE.md`
- `research_market_landscape.md`
- `research_technical_foundations.md`
- `research_ai_trends.md`
- `research_developer_ux.md`

## Final Statement

The strongest path forward is not to replace Git immediately.

The strongest path forward is to build Kin as the semantic relationship layer for code, expose it to agents through MCP, prove that it delivers better context and better reasoning on real repositories, and only then expand into deeper version-control behavior.

That is the practical foundation for turning the original semantic code graph thesis into a real product.
