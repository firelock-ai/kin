# Semantic Code Graph (SCG) Platform
## Master Product Architecture Document

**Version:** 1.0.0
**Date:** March 10, 2026
**Classification:** Confidential — Investor Grade
**Status:** Architecture Blueprint

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Market Context and Competitive Landscape](#2-market-context-and-competitive-landscape)
3. [Core Architecture: The Dual-Store Engine](#3-core-architecture-the-dual-store-engine)
4. [The Semantic Compiler](#4-the-semantic-compiler)
5. [The Git Bridge](#5-the-git-bridge)
6. [AI-Native Features](#6-ai-native-features)
7. [The MCP Server Entry Point](#7-the-mcp-server-entry-point)
8. [Developer Experience and UX](#8-developer-experience-and-ux)
9. [Enterprise Features](#9-enterprise-features)
10. [Technical Moats and Defensibility](#10-technical-moats-and-defensibility)
11. [Business Strategy and Acquisition Path](#11-business-strategy-and-acquisition-path)
12. [Technical Stack and MVP Scope](#12-technical-stack-and-mvp-scope)
13. [Risk Analysis](#13-risk-analysis)
14. [Appendix](#14-appendix)
15. [VCS-Bench: The Built-In Benchmarking Engine](#15-vcs-bench-the-built-in-benchmarking-engine)
16. [The GitHub-to-Graph Migration Pipeline](#16-the-github-to-graph-migration-pipeline)

---

## 1. Executive Summary

### The Thesis

Every AI coding tool built today — Cursor, Windsurf, Copilot, Sourcegraph Cody — shares a fatal architectural constraint: they bolt AI intelligence onto a storage model designed in 2005. Git tracks files as opaque blobs. AI needs to understand code as a graph of interconnected semantic entities. This impedance mismatch is why 66% of developers spend more time fixing AI-generated code than writing it from scratch, and why context quality degrades catastrophically beyond 100K tokens.

**The Semantic Code Graph (SCG) platform eliminates this mismatch.**

SCG replaces the file-as-atom paradigm with a fundamentally new primitive: the **semantic entity**. Functions, classes, types, API contracts, and schemas become first-class, content-addressed nodes in a persistent knowledge graph. Relationships — calls, imports, data flows, type hierarchies — become typed, queryable edges. Every AI interaction, every diff, every merge, every search operates on this graph, not on text files.

The result:

- **AI agents receive surgically precise context** via BFS graph traversal instead of dumping entire files into context windows
- **Merges that Git cannot resolve become trivial** — entity-level semantic diffs achieve 31/31 clean merges vs. Git's 15/31 on identical conflict sets (Ataraxy Labs benchmark)
- **Dead code, dependency rot, and architectural drift become queryable** — a single Cypher query replaces weeks of manual auditing
- **Multi-agent workflows get native versioning** — commits capture intent, validation state, and impact analysis as first-class metadata

SCG maintains full Git compatibility through a bidirectional translation layer (the "Git Bridge"), meaning adoption requires zero workflow disruption. Developers continue using `git push`, `git pull`, and their existing tools. The semantic graph is built and maintained transparently.

### Business Model

**Open Core.** The MCP server, IDE plugins, and Git Bridge are open-source (Apache 2.0). The Semantic Compiler, Intent Engine, cross-repository Knowledge Graph, and enterprise features are proprietary. This follows the proven Jujutsu/GitButler path of earning developer trust through an open wedge before monetizing platform capabilities.

### Market Timing

Three forces converge in 2026:

1. **OpenAI is building a GitHub competitor** (reported March 2026) — validating that the AI-native code platform market is real and venture-scale
2. **GitHub's reliability crisis** — 58% increase in incidents YoY — is driving major projects to explore alternatives
3. **The AGENTS.md standard** (Linux Foundation) signals industry consensus that AI agents need structured code metadata, exactly what SCG provides natively

### Financial Targets

| Metric | Year 1 | Year 2 | Year 3 |
|---|---|---|---|
| Phase | Local MCP Wedge | Semantic Build/CI | Multi-Agent Platform |
| Target Users | 10K developers | 50K developers | 500K+ developers |
| Revenue Model | Free + Donations | Team Plans ($20/seat/mo) | Enterprise ($50/seat/mo) + Platform Fees |
| ARR Target | — | $2M | $25M+ |

---

## 2. Market Context and Competitive Landscape

### 2.1 The AI Coding Tools Landscape (2026)

The AI-assisted development market has exploded, with 85% of developers now using AI tools in their daily workflow. Yet satisfaction remains paradoxically low — a direct consequence of the file-level context problem.

```
                    AI CODING TOOL MARKET MAP (March 2026)

    ┌─────────────────────────────────────────────────────────────────┐
    │                     CODE INTELLIGENCE LAYER                     │
    │                                                                 │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
    │  │  Cursor   │  │ Windsurf │  │  Replit   │  │  Augment Code│   │
    │  │  $29B val │  │ (Codeium)│  │ AI-native │  │  Enterprise  │   │
    │  │  IDE+AI   │  │ IDE+AI   │  │ IDE+AI    │  │  context     │   │
    │  └─────┬─────┘  └────┬─────┘  └────┬──────┘  └──────┬───────┘   │
    │        │              │              │                │           │
    │        ▼              ▼              ▼                ▼           │
    │  ┌─────────────────────────────────────────────────────────┐     │
    │  │              FILE-LEVEL CONTEXT (THE CEILING)            │     │
    │  │   • Dump entire files into LLM context windows          │     │
    │  │   • Context rot beyond 100K tokens                      │     │
    │  │   • No structural understanding of cross-file deps      │     │
    │  │   • Merges/diffs operate on text, not semantics          │     │
    │  └─────────────────────────┬───────────────────────────────┘     │
    │                            │                                     │
    │                            ▼                                     │
    │  ┌──────────────────────────────────────────────────────────┐    │
    │  │                  GIT (Blob Storage)                       │    │
    │  │   • Files are opaque blobs                               │    │
    │  │   • No semantic awareness                                │    │
    │  │   • Line-based diffs miss structural changes             │    │
    │  │   • Merge conflicts are syntactic, not semantic           │    │
    │  └──────────────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────────────┘

                          ▲ CURRENT STATE ▲

    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─

                          ▼ SCG TARGET STATE ▼

    ┌─────────────────────────────────────────────────────────────────┐
    │                     SEMANTIC CODE GRAPH                         │
    │                                                                 │
    │  ┌──────────────────────────────────────────────────────────┐   │
    │  │           GRAPH-NATIVE AI CONTEXT DELIVERY               │   │
    │  │   • BFS traversal delivers precise subgraph              │   │
    │  │   • Entity-level diffs, not line-level                   │   │
    │  │   • Cross-repo semantic search                           │   │
    │  │   • Agent-aware versioning with intent metadata          │   │
    │  └──────────────────────────┬───────────────────────────────┘   │
    │                             │                                    │
    │  ┌──────────┐  ┌───────────┴────────────┐  ┌──────────────┐    │
    │  │ Graph DB  │  │  Content-Addressed DAG  │  │  Vector DB   │    │
    │  │(Neo4j /   │◄─┤  (Entities + Edges)     ├─►│ (Qdrant /    │    │
    │  │ Memgraph) │  │  SHA-256 identity        │  │  pgvector)   │    │
    │  └──────────┘  └───────────┬────────────┘  └──────────────┘    │
    │                             │                                    │
    │                    ┌────────┴────────┐                           │
    │                    │   Git Bridge     │                           │
    │                    │ (Bidirectional)  │                           │
    │                    └────────┬────────┘                           │
    │                             │                                    │
    │                    ┌────────┴────────┐                           │
    │                    │   Git Blob Store │                           │
    │                    │  (Compatibility) │                           │
    │                    └─────────────────┘                           │
    └─────────────────────────────────────────────────────────────────┘
```

### 2.2 Competitor Analysis

| Company | Valuation / Funding | Approach | SCG Advantage |
|---|---|---|---|
| **Cursor** | $29B (2026) | AI-powered IDE, file-level context | SCG provides graph-level context to ANY IDE |
| **GitHub Copilot** | Microsoft subsidiary | File-level completion, repo-level RAG | SCG's graph traversal eliminates context rot |
| **Sourcegraph Cody** | $2.6B (2023) | Code search + AI, SCIP indexing | SCIP is read-only index; SCG is read-write graph |
| **Augment Code** | $977M (2025) | Enterprise context engine | SCG's open-source wedge undercuts closed-source lock-in |
| **Windsurf (Codeium)** | $3B+ (2025) | IDE + Cascade multi-file editing | SCG's semantic diffs make multi-file edits reliable |
| **Replit** | $1.16B (2023) | Cloud IDE, AI-native | SCG is local-first, not cloud-dependent |
| **Tabnine** | $200M+ raised | Privacy-focused AI completion | SCG matches privacy (local-first) + adds semantic depth |
| **Potpie AI** | $2.2M pre-seed | Neo4j code knowledge graphs | Closest competitor — but indexing only, no version control |
| **Ataraxy Labs** | Pre-seed | Entity-level semantic VCS (sem + weave) | Closest technical vision — but CLI-only, no platform |

### 2.3 Critical Market Signals

**Signal 1: OpenAI GitHub Competitor (March 2026)**
OpenAI is reportedly building a GitHub competitor. This validates the thesis that AI-native code platforms represent a venture-scale market. SCG's differentiation — the semantic graph layer — positions it as infrastructure that OpenAI's platform would need to acquire or replicate.

**Signal 2: GitHub Reliability Crisis**
GitHub suffered a 58% increase in service incidents year-over-year. Major open-source projects are actively evaluating alternatives. This creates a rare window where developer migration cost decreases.

**Signal 3: AGENTS.md Standard (Linux Foundation)**
The emerging AGENTS.md standard under the Linux Foundation codifies the industry need for structured code metadata that AI agents can consume. SCG generates this metadata natively from its graph — every other tool must bolt it on as an afterthought.

**Signal 4: MCP Protocol Adoption**
The Model Context Protocol (MCP) has reached 97 million monthly downloads, establishing it as the de facto standard for AI tool integration. SCG's MCP server entry point rides this adoption wave directly.

### 2.4 The Key Gap

No existing product combines all three of:

1. **Semantic code graph** (structural understanding of code as entities and relationships)
2. **Version control** (commits, branches, merges operating on semantic entities)
3. **AI context delivery** (graph-traversal-based context for LLMs and agents)

Potpie AI has (1) but not (2) or (3). Ataraxy Labs has (1) and (2) but not (3). Sourcegraph has partial (1) and (3) but not (2). SCG builds all three as a unified platform.

---

## 3. Core Architecture: The Dual-Store Engine

### 3.1 The Paradigm Shift: Files to Entities

Traditional version control treats the **file** as the atomic unit of code. SCG treats the **semantic entity** as the atom. A function, a class, a type definition, an API endpoint, a database schema — each becomes a discrete, content-addressed node in a persistent directed acyclic graph (DAG).

```
    TRADITIONAL (Git)                    SCG (Semantic Code Graph)
    ─────────────────                    ────────────────────────

    Repository                           Repository
        │                                    │
        ├── src/                             ├── Entity Graph (DAG)
        │   ├── auth.ts    ◄─ blob           │   ├── fn:authenticate
        │   ├── user.ts    ◄─ blob           │   ├── fn:validateToken
        │   ├── db.ts      ◄─ blob           │   ├── class:UserService
        │   └── api.ts     ◄─ blob           │   ├── type:UserPayload
        │                                    │   ├── schema:users_table
        ├── tests/                           │   ├── api:/auth/login
        │   └── auth.test.ts ◄─ blob         │   ├── fn:hashPassword
        │                                    │   └── test:auth_flow
        └── .git/                            │
            └── objects/  ◄─ SHA-1 blobs     ├── Edges (Typed Relationships)
                                             │   ├── authenticate ──CALLS──► validateToken
                                             │   ├── UserService ──CONTAINS──► authenticate
                                             │   ├── authenticate ──REFERENCES──► UserPayload
                                             │   ├── authenticate ──DATA_FLOWS_TO──► hashPassword
                                             │   └── auth_flow ──TESTS──► authenticate
                                             │
                                             └── Git Bridge (compatibility layer)
                                                 └── Reconstructs files on demand
```

### 3.2 Entity Object Schema

Every code entity is stored as a content-addressed **Entity Object**:

```
EntityObject {
    // Identity (content-addressed)
    hash:           SHA-256(normalized_ast)    // Unique identity derived from structure
    entity_type:    enum {                     // Semantic classification
                        Module, Function, Class, Method,
                        Variable, Type, Interface, Enum,
                        Schema, APIEndpoint, Test, Import
                    }

    // Metadata
    name:           string                     // Human-readable name (mutable label)
    language:       string                     // Source language (typescript, python, etc.)
    file_origin:    string                     // Original file path (for Git Bridge)
    byte_range:     (start, end)               // Position in original file

    // Content
    source:         string                     // Raw source code
    ast:            TreeSitterNode             // Parsed AST subtree
    normalized_ast: bytes                      // Canonicalized AST (for hashing)
    signature:      string                     // Type signature (if applicable)
    docstring:      string | null              // Documentation

    // Embedding
    vector:         float[768]                 // Semantic embedding for vector search

    // Versioning
    parent_hashes:  Vec<SHA-256>               // Previous versions (DAG lineage)
    commit_id:      UUID                       // Owning commit
    timestamp:      ISO-8601                   // Creation time
}
```

This draws directly from the **Unison programming language** model: code identity is determined by the SHA-256 hash of its normalized AST, not by its name or file location. Renaming a function does not change its hash. Moving a function between files does not change its hash. Only structural changes to the AST produce a new hash, creating a new node in the DAG.

### 3.3 The Dual-Store Architecture

SCG maintains three synchronized storage layers, each optimized for a different query pattern:

```
    ┌─────────────────────────────────────────────────────────────┐
    │                    SEMANTIC COMPILER                         │
    │              (Ingestion + Transformation)                    │
    │                                                             │
    │   Source Code ──► Tree-sitter ──► AST ──► Entity Objects    │
    │                                                             │
    └───────────┬──────────────────┬──────────────────┬───────────┘
                │                  │                  │
                ▼                  ▼                  ▼
    ┌───────────────┐  ┌───────────────────┐  ┌──────────────┐
    │   GRAPH DB     │  │    VECTOR DB       │  │  GIT BLOB    │
    │  (Memgraph)    │  │   (Qdrant)         │  │   STORE      │
    │                │  │                    │  │              │
    │ • Entity nodes │  │ • 768-dim vectors  │  │ • SHA-1 blobs│
    │ • Typed edges  │  │ • Cosine similarity│  │ • Tree objects│
    │ • Cypher query │  │ • Filtered search  │  │ • Git compat │
    │                │  │                    │  │              │
    │ QUERY TYPES:   │  │ QUERY TYPES:       │  │ QUERY TYPES: │
    │ • "What calls  │  │ • "Find functions  │  │ • git log    │
    │    function X?"│  │    similar to this  │  │ • git diff   │
    │ • "Show the    │  │    description"     │  │ • git blame  │
    │    dependency  │  │ • "Which entities   │  │ • git clone  │
    │    chain"      │  │    relate to auth?" │  │              │
    │ • "Find all    │  │ • Hybrid: vector    │  │              │
    │    orphans"    │  │    + graph filter   │  │              │
    └───────────────┘  └───────────────────┘  └──────────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │    QUERY ROUTER        │
                    │                       │
                    │ Deterministic ──► Graph│
                    │ Semantic ──► Vector    │
                    │ Hybrid ──► Both + Fuse │
                    │ Legacy ──► Git Store   │
                    └───────────────────────┘
```

**Layer 1: Graph Database (Memgraph)**

Purpose: Deterministic structural queries. "What does this function call?" "What is the dependency chain from module A to module B?" "Find all entities with in-degree zero (orphans)."

Choice rationale: Memgraph over Neo4j for the local-first use case. Memgraph is an in-memory graph database written in C++ with sub-millisecond traversal latency, making it suitable for real-time IDE integration. Neo4j remains an option for the cloud/enterprise tier where persistence durability matters more than raw speed.

**Layer 2: Vector Database (Qdrant)**

Purpose: Semantic similarity queries. "Find functions that handle authentication." "Which entities are conceptually related to payment processing?" "Search by natural language description."

Choice rationale: Qdrant provides high-performance approximate nearest neighbor (ANN) search with filtering capabilities. Critical for AI context delivery — when an agent asks "show me code related to X," the vector store finds semantically similar entities, and the graph store expands their structural neighborhoods.

**Layer 3: Git Blob Store**

Purpose: Backward compatibility. Files are reconstructed on demand from the entity graph for any tool that expects traditional git operations. This store is derivative — it is regenerated from the graph, not the source of truth.

### 3.4 Graph Schema

```
    NODE TYPES                          EDGE TYPES
    ──────────                          ──────────

    ┌──────────┐                        ┌─────────────────────┐
    │  Module   │───CONTAINS───►        │  CONTAINS           │
    └──────────┘                        │  (Module→Entity)    │
    ┌──────────┐                        ├─────────────────────┤
    │ Function  │───CALLS──────►        │  CALLS              │
    └──────────┘                        │  (Fn→Fn)            │
    ┌──────────┐                        ├─────────────────────┤
    │  Class    │───EXTENDS────►        │  REFERENCES         │
    └──────────┘                        │  (Entity→Entity)    │
    ┌──────────┐                        ├─────────────────────┤
    │  Method   │───IMPLEMENTS─►        │  EXTENDS            │
    └──────────┘                        │  (Class→Class)      │
    ┌──────────┐                        ├─────────────────────┤
    │ Variable  │───HAS_TYPE───►        │  IMPLEMENTS         │
    └──────────┘                        │  (Class→Interface)  │
    ┌──────────┐                        ├─────────────────────┤
    │   Type    │───DATA_FLOWS_TO──►    │  DATA_FLOWS_TO      │
    └──────────┘                        │  (Entity→Entity)    │
    ┌──────────┐                        ├─────────────────────┤
    │ Interface │───TESTS──────►        │  HAS_TYPE           │
    └──────────┘                        │  (Entity→Type)      │
    ┌──────────┐                        ├─────────────────────┤
    │   Enum    │                       │  TESTS              │
    └──────────┘                        │  (Test→Entity)      │
    ┌──────────┐                        ├─────────────────────┤
    │  Schema   │                       │  IMPORTS            │
    └──────────┘                        │  (Module→Module)    │
    ┌──────────┐                        ├─────────────────────┤
    │   API     │                       │  EXPOSES            │
    └──────────┘                        │  (Module→Entity)    │
    ┌──────────┐                        ├─────────────────────┤
    │   Test    │                       │  DEPENDS_ON         │
    └──────────┘                        │  (Entity→Entity)    │
    ┌──────────┐                        └─────────────────────┘
    │  Import   │
    └──────────┘

    EDGE PROPERTIES:
    ─────────────────
    • weight:      float      (call frequency, coupling strength)
    • commit_id:   UUID       (when this edge was created/modified)
    • confidence:  float      (for inferred edges, e.g., data flow)
    • metadata:    JSON       (language-specific annotations)
```

### 3.5 Content Addressing

Following the Unison model, entity identity is determined by content, not location:

```
Identity Algorithm:
─────────────────

1. Parse source code with tree-sitter → CST
2. Extract entity subtree from CST
3. Normalize the AST:
   a. Strip comments and whitespace
   b. Replace local variable names with positional indices
      (α-renaming / de Bruijn indexing)
   c. Normalize string literals to canonical form
   d. Sort unordered constructs (e.g., object keys)
4. Serialize normalized AST to canonical bytes
5. hash = SHA-256(canonical_bytes)

Properties:
─────────────
• Rename function → same hash (name is metadata, not identity)
• Move function to different file → same hash
• Change function body → new hash → new DAG node
• Identical functions in different repos → same hash (deduplication)
```

This enables powerful capabilities:
- **Cross-repository deduplication:** Identical utility functions across repos share a single hash
- **Rename-proof history:** A function's full history persists through any number of renames
- **Move-proof tracking:** Refactoring a function from `utils.ts` to `auth/helpers.ts` is tracked as a metadata change, not a delete+create

---

## 4. The Semantic Compiler

### 4.1 Overview

The Semantic Compiler is SCG's core proprietary engine. It transforms raw source code into content-addressed entity objects stored in the dual-store. It runs locally (for privacy and speed) as a Rust binary, using incremental computation (inspired by the Salsa framework) to achieve sub-100ms recomputation on file save.

```
    SEMANTIC COMPILER PIPELINE
    ══════════════════════════

    ┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────────┐
    │  Source   │     │  Tree-   │     │   Entity     │     │  Semantic    │
    │  Files    │────►│  sitter  │────►│  Extractor   │────►│  Analyzer    │
    │ (.ts,.py) │     │  Parser  │     │              │     │  (Salsa)     │
    └──────────┘     └──────────┘     └──────────────┘     └──────────────┘
                         │                   │                     │
                     CST (Concrete       Entity List           Resolved
                     Syntax Tree)        + Raw AST             Types,
                                         Subtrees              Edges,
                                                               Data Flow
                                                                  │
                                                                  ▼
    ┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────────┐
    │  Graph   │     │ Content  │     │   Vector     │     │   Graph      │
    │  DB      │◄────│ Addresser│◄────│  Embedder    │◄────│  Emitter     │
    │(Memgraph)│     │(SHA-256) │     │ (local model)│     │              │
    └──────────┘     └──────────┘     └──────────────┘     └──────────────┘
        │                                    │
        │                                    ▼
        │                            ┌──────────────┐
        │                            │  Vector DB   │
        │                            │  (Qdrant)    │
        └────────────────────────────┘──────────────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │  Git Bridge   │
                                     │ (file recon.) │
                                     └──────────────┘
```

### 4.2 Stage 1: Tree-sitter Parsing

**Input:** Raw source file (e.g., `auth.ts`)
**Output:** Concrete Syntax Tree (CST)

Tree-sitter provides:
- **Incremental parsing:** On file edit, only the changed portion of the tree is re-parsed (O(log n) for typical edits)
- **Error recovery:** Produces valid partial trees even for syntactically broken code (critical for real-time IDE use)
- **30+ language grammars** maintained by an active open-source community
- **Zero-copy operation:** Parses directly from memory-mapped files

Language support priority for MVP:

| Tier | Languages | Tree-sitter Grammar Maturity |
|---|---|---|
| 1 (Launch) | TypeScript, JavaScript, Python, Go, Rust | Production-grade |
| 2 (Q2) | Java, C#, Ruby, PHP, Swift, Kotlin | Production-grade |
| 3 (Q3) | C, C++, Scala, Elixir, Haskell | Varies |

### 4.3 Stage 2: Entity Extraction

**Input:** CST from tree-sitter
**Output:** List of EntityObject candidates with raw AST subtrees

Each language requires a set of **tree-sitter queries** (S-expression patterns) that identify entity boundaries. Example for TypeScript:

```scheme
;; Extract function declarations
(function_declaration
    name: (identifier) @entity.name
    parameters: (formal_parameters) @entity.params
    return_type: (type_annotation)? @entity.return_type
    body: (statement_block) @entity.body
) @entity.function

;; Extract class declarations
(class_declaration
    name: (type_identifier) @entity.name
    (class_heritage)? @entity.heritage
    body: (class_body) @entity.body
) @entity.class

;; Extract exported API endpoints (framework-specific)
(call_expression
    function: (member_expression
        object: (identifier) @router_name
        property: (property_identifier) @http_method
    )
    arguments: (arguments
        (string) @entity.route
        (arrow_function) @entity.handler
    )
) @entity.api_endpoint
```

The Entity Extractor maintains a registry of query sets per language. Adding a new language requires writing tree-sitter queries — no changes to the core compiler pipeline.

### 4.4 Stage 3: Semantic Analysis (Salsa-Inspired)

**Input:** Entity list with raw AST subtrees
**Output:** Resolved types, edges, and data flow annotations

This is where SCG goes beyond what tools like SCIP or CodeQL provide. The Semantic Analyzer uses an incremental computation framework inspired by Rust's **Salsa** (used by rust-analyzer) to maintain a live, queryable semantic model.

```
    SALSA-INSPIRED INCREMENTAL COMPUTATION
    ═══════════════════════════════════════

    Query Database (Memoized)
    ┌────────────────────────────────────────────────┐
    │                                                │
    │  resolve_type(entity_hash)                     │
    │      │                                         │
    │      ├── lookup_local_scope(entity_hash)       │
    │      │       │                                 │
    │      │       └── parse_entity(entity_hash)  ◄──┤── CACHED
    │      │                                         │
    │      ├── resolve_import(import_path)            │
    │      │       │                                 │
    │      │       └── find_module(module_path)    ◄──┤── CACHED
    │      │                                         │
    │      └── infer_return_type(entity_hash)        │
    │              │                                 │
    │              └── resolve_type(callee_hash)   ◄──┤── RECURSIVE
    │                                                │
    └────────────────────────────────────────────────┘

    On file change:
    1. Invalidate parse_entity(changed_hash)
    2. Salsa propagates invalidation UP the query tree
    3. Only affected queries recompute
    4. Unchanged subtrees remain cached

    Result: Sub-100ms recomputation for typical edits
```

The Semantic Analyzer resolves:

1. **Type Resolution:** Infer and record types for all entities, following imports across module boundaries
2. **Call Graph Construction:** Determine which functions call which, including through dynamic dispatch where statically determinable
3. **Data Flow Analysis:** Track how data moves through the codebase — function parameters to return values, variable assignments, API request/response chains
4. **Edge Emission:** Produce typed edges (CALLS, REFERENCES, EXTENDS, DATA_FLOWS_TO, HAS_TYPE, etc.) for the graph store

### 4.5 Stage 4: Vector Embedding

**Input:** Entity objects with resolved metadata
**Output:** 768-dimensional semantic vectors

Each entity is embedded using a local embedding model (candidate: Nomic Embed Code, or a fine-tuned CodeBERT variant). The embedding input combines:

```
Embedding Input Template:
─────────────────────────
{entity_type} {language} {name}
Signature: {signature}
Docstring: {docstring}
Calls: {list of called entity names}
Called by: {list of calling entity names}
Types: {referenced types}
```

This structured input produces embeddings that capture both semantic meaning and structural context, enabling queries like "find functions related to authentication that interact with the database layer."

### 4.6 Stage 5: Content Addressing and Storage

**Input:** Complete entity objects with vectors
**Output:** Stored in Graph DB + Vector DB

```
Storage Protocol:
─────────────────
1. Compute SHA-256(normalized_ast) → entity_hash
2. Check if entity_hash exists in graph:
   a. EXISTS → No-op (content unchanged, skip storage)
   b. NOT EXISTS →
      i.   Store EntityObject node in Memgraph
      ii.  Store edges (CALLS, REFERENCES, etc.) in Memgraph
      iii. Store vector in Qdrant with entity_hash as ID
      iv.  Link parent_hashes for DAG lineage
3. Update module-level CONTAINS edges
4. Trigger Git Bridge file reconstruction (async)
```

The content-addressing scheme means that unchanged entities are never re-stored, and unchanged edges are never re-written. On a typical file save where one function body changes, only that function's node and its immediate edges are updated. All other entities in the file are untouched.

### 4.7 Performance Targets

| Operation | Target Latency | Technique |
|---|---|---|
| Parse single file (tree-sitter) | < 5ms | Incremental parsing, zero-copy |
| Entity extraction | < 10ms | Pre-compiled tree-sitter queries |
| Semantic analysis (incremental) | < 100ms | Salsa memoized queries |
| Vector embedding (local) | < 50ms | Quantized ONNX model, batch inference |
| Graph write (entity + edges) | < 20ms | Memgraph in-memory, batch Cypher |
| Total pipeline (file save) | < 200ms | Pipeline parallelism |

---

## 5. The Git Bridge

### 5.1 Design Philosophy

Git compatibility is not optional — it is a hard requirement. The Git Bridge provides **bidirectional translation** between the file-based world of Git and the entity-based world of SCG. Developers continue using `git clone`, `git commit`, `git push`, and `git pull`. The semantic graph is maintained transparently.

This approach is validated by **Jujutsu (jj)**, Google's experimental VCS that maintains a Git-compatible backend while implementing a fundamentally different internal model (operation log, automatic rebasing, conflict-as-data). Jujutsu has proven that developers will adopt new VCS internals if the Git interface contract is preserved.

### 5.2 Architecture

```
    GIT BRIDGE: BIDIRECTIONAL TRANSLATION
    ══════════════════════════════════════

    INBOUND (git push / file change → graph update)
    ────────────────────────────────────────────────

    ┌──────────┐     ┌──────────────┐     ┌──────────────┐
    │  git push│     │  File Diff   │     │  Semantic    │
    │  or IDE  │────►│  Detector    │────►│  Compiler    │
    │  save    │     │              │     │  (§4)        │
    └──────────┘     └──────────────┘     └──────────────┘
                          │                      │
                     Changed files          Updated entities
                     identified             + edges stored
                                            in graph

    OUTBOUND (graph state → file reconstruction)
    ─────────────────────────────────────────────

    ┌──────────────┐     ┌──────────────┐     ┌──────────┐
    │  Graph Query  │     │  File        │     │ git clone│
    │  (entities    │────►│  Assembler   │────►│ git pull │
    │   by module)  │     │              │     │ IDE view │
    └──────────────┘     └──────────────┘     └──────────┘
         │                      │
    Entities grouped       Source files
    by file_origin         reconstructed
    + sorted by            with consistent
    byte_range             formatting
```

### 5.3 Inbound Translation (Files → Graph)

When a developer runs `git push` or saves a file in their IDE:

1. **File Diff Detection:** Identify which files changed (using inotify/FSEvents for local, git diff for push)
2. **Incremental Compilation:** Run the Semantic Compiler (Section 4) only on changed files
3. **Entity Diff:** Compare new entity hashes against existing graph state
   - New hash → new entity node (content changed)
   - Same hash → no-op (cosmetic change only, e.g., whitespace)
   - Missing hash → entity deleted (remove node + edges)
4. **Edge Update:** Recompute edges for changed entities and their immediate neighbors
5. **Commit Creation:** Record an SCG commit containing:
   - List of changed entity hashes
   - Parent commit reference
   - Author, timestamp, message
   - Intent metadata (if provided by AI agent)
   - Validation state (test results, if available)

### 5.4 Outbound Translation (Graph → Files)

When a developer runs `git clone`, `git pull`, or opens a file in their IDE:

1. **Module Query:** Retrieve all entities belonging to the requested module/file path
2. **Ordering:** Sort entities by their `byte_range` metadata to reconstruct original file ordering
3. **Assembly:** Concatenate entity source code with appropriate inter-entity whitespace and formatting
4. **Formatting:** Run a language-appropriate formatter (prettier, black, gofmt) to ensure consistent output
5. **Git Object Creation:** Package reconstructed files as Git blob/tree objects for git compatibility

### 5.5 Conflict Resolution

Traditional Git merge conflicts occur at the line level. SCG resolves conflicts at the entity level:

```
    GIT MERGE CONFLICT                   SCG SEMANTIC MERGE
    ──────────────────                   ───────────────────

    <<<<<<< HEAD                         Entity: fn:calculateTotal
    function calculateTotal(items) {
      return items.reduce(               Branch A: hash_abc123
        (sum, item) => sum + item.price  (added discount parameter)
      , 0);
    }                                    Branch B: hash_def456
    =======                              (added tax calculation)
    function calculateTotal(items) {
      let total = 0;                     Merge Strategy:
      for (const item of items) {        1. Detect: both modify same entity
        total += item.price * 1.1;       2. Analyze: changes are to different
      }                                     AST subtrees (params vs. body logic)
      return total;                      3. Auto-merge: combine both changes
    }                                    4. Result: hash_789ghi
    >>>>>>> feature-branch               (discount param + tax calculation)
```

SCG uses the **GumTree algorithm** for AST-level diff and merge:

1. **Phase 1 (Top-Down):** Match identical subtrees using hash comparison (leveraging content addressing)
2. **Phase 2 (Bottom-Up):** Match remaining nodes using structural similarity and position heuristics
3. **Edit Script:** Generate a minimal edit script (insert, delete, update, move) at the AST node level
4. **3-Way Merge:** Apply edit scripts from both branches to the common ancestor
5. **Conflict Detection:** Only flag as conflict when both branches modify the same AST node

This approach achieves **31/31 clean merges** on test cases where Git's text-based merge resolves only **15/31** (Ataraxy Labs benchmark). The 16 cases that Git cannot resolve — reordering function parameters, moving code blocks, renaming variables while modifying logic — are trivially resolved by AST-level operations.

### 5.6 Semantic Diff

SCG provides structural diffs that are dramatically more informative than line-based diffs:

```
    GIT DIFF (line-based)                SCG SEMANTIC DIFF
    ─────────────────────                ─────────────────

    - function getUser(id) {             Entity: fn:getUser
    + function getUser(id, opts) {         MODIFIED: signature
      ...                                   + parameter: opts: GetUserOptions
    - async function getUser(id,           MODIFIED: body
    -   db = defaultDb                       - reference: defaultDb
    - ) {                                    + reference: opts.db ?? defaultDb
    + async function getUser(id, opts) {
    +   const db = opts.db ?? defaultDb;   ADDED EDGE:
      ...                                   fn:getUser ──REFERENCES──► type:GetUserOptions
    }
                                           IMPACT ANALYSIS:
                                             12 callers of fn:getUser may need update
                                             3 callers pass positional args (BREAKING)
                                             9 callers use named args (COMPATIBLE)
```

The semantic diff communicates:
- **What changed** at the structural level (new parameter, changed reference)
- **New relationships** created by the change (new type reference edge)
- **Impact analysis** — which callers are affected and whether the change is breaking

This is built on **Difftastic**'s proven approach of treating structural diffing as a graph problem, extended with SCG's cross-entity relationship tracking.

---

## 6. AI-Native Features

### 6.1 JIT Contextualization

The killer feature. When an AI agent needs context about a code entity, SCG delivers a **pruned, relevant subgraph** instead of dumping entire files.

```
    TRADITIONAL RAG                      SCG JIT CONTEXT
    ───────────────                      ────────────────

    Query: "How does auth work?"         Query: "How does auth work?"

    1. Embed query                       1. Embed query
    2. Vector search → top-K files       2. Vector search → top-K entities
    3. Stuff entire files into           3. BFS graph traversal from each:
       context window                       • depth=1: direct calls, types
       (lots of irrelevant code)            • depth=2: transitive deps
    4. Context window: ~50K tokens          • Prune: remove low-relevance edges
       (much noise, some signal)         4. Context window: ~8K tokens
                                            (high signal, minimal noise)
    Result:
    • 100K+ token context               Result:
    • Significant noise                  • ~10K token context
    • Context rot at scale               • Surgically precise
    • Hallucination-prone                • Scales to any codebase size
                                         • GraphRAG reduces hallucinations 90%
```

**Algorithm: BFS Context Expansion**

```
function jit_context(seed_entities: Entity[], max_depth: int, token_budget: int):
    context = new OrderedSet()
    queue = seed_entities.map(e => (e, depth=0))
    tokens_used = 0

    while queue is not empty AND tokens_used < token_budget:
        (entity, depth) = queue.dequeue()

        if depth > max_depth:
            continue

        context.add(entity)
        tokens_used += estimate_tokens(entity)

        // Expand via graph edges, prioritized by edge type
        neighbors = graph.query("""
            MATCH (e)-[r]->(n) WHERE e.hash = $hash
            RETURN n, r, type(r) as edge_type
            ORDER BY
                CASE type(r)
                    WHEN 'HAS_TYPE' THEN 1     // Types first (most compact)
                    WHEN 'CALLS' THEN 2        // Direct calls
                    WHEN 'REFERENCES' THEN 3   // References
                    WHEN 'DATA_FLOWS_TO' THEN 4
                    ELSE 5
                END
        """, hash=entity.hash)

        for (neighbor, rel, edge_type) in neighbors:
            if neighbor not in context:
                queue.enqueue((neighbor, depth + 1))

    return context.to_prompt_format()
```

This delivers **exactly the code an AI agent needs** — the function being discussed, its type signatures, the functions it calls, the functions that call it, and the data flow chain — without any irrelevant code from the same files.

### 6.2 Living Documentation

SCG generates "virtual documents" on-the-fly from graph state. These are never stored as files — they are computed views over the graph, always perfectly up-to-date.

**Generated Virtual Documents:**

| Document | Content | Graph Query |
|---|---|---|
| `CLAUDE.md` | AI agent instructions, codebase conventions, key patterns | Aggregate entity metadata, naming conventions, architectural boundaries |
| `AGENTS.md` | Agent-specific context per module | Module-level graph summary, entry points, constraints |
| `API_MAP.md` | Complete API surface area | All entities with `entity_type = APIEndpoint` + their types |
| `DEPENDENCY_GRAPH.md` | Visual dependency map | Module-level IMPORTS edges, rendered as ASCII/Mermaid |
| `DEAD_CODE_REPORT.md` | Orphaned entities | `MATCH (n) WHERE NOT (()-[:CALLS]->(n)) AND n.entity_type = 'Function'` |
| `ARCHITECTURE.md` | High-level system architecture | Module clusters, cross-module edge density |

These documents comply with the emerging **AGENTS.md standard** (Linux Foundation) natively, positioning SCG as the infrastructure layer that generates the metadata other tools consume.

### 6.3 Orphan Detection

Dead code detection becomes a trivial graph query:

```cypher
// Find all functions with no incoming CALLS edges and no TESTS edges
// (i.e., never called and never tested — likely dead code)
MATCH (f:Entity {entity_type: 'Function'})
WHERE NOT ()-[:CALLS]->(f)
  AND NOT ()-[:TESTS]->(f)
  AND NOT f.name STARTS WITH 'main'
  AND NOT f.name STARTS WITH 'export'
RETURN f.name, f.file_origin, f.last_modified
ORDER BY f.last_modified ASC
```

More sophisticated queries:

```cypher
// Find dependency chains where removing one entity disconnects a subgraph
// (architectural bottleneck detection)
MATCH path = (a:Entity)-[:CALLS*2..5]->(b:Entity)
WHERE a <> b
WITH b, count(DISTINCT a) as dependents
WHERE dependents > 10
RETURN b.name, b.file_origin, dependents
ORDER BY dependents DESC

// Find circular dependencies
MATCH path = (a:Entity)-[:CALLS*2..10]->(a)
RETURN [n in nodes(path) | n.name] as cycle, length(path) as depth
ORDER BY depth ASC
```

### 6.4 Semantic Diff and Merge

(Covered in detail in Section 5.5 and 5.6. Summary of AI-native enhancements here.)

Beyond the structural merge capabilities described in the Git Bridge section, SCG adds AI-native diff features:

1. **Intent-Aware Diffs:** When an AI agent makes changes, the commit includes a natural language intent description. The diff engine can verify that the structural changes match the stated intent.

2. **Impact Prediction:** Before a merge is committed, SCG traverses the graph to identify all entities affected by the change, their test coverage, and their downstream consumers. This produces a risk score for the merge.

3. **Auto-Generated Merge Commit Messages:** The semantic diff output feeds an LLM prompt that generates human-readable merge descriptions that accurately reflect structural changes, not line-level noise.

### 6.5 Multi-Agent Versioning

As AI development shifts from single-agent to multi-agent workflows, SCG provides native versioning primitives:

```
    SCG COMMIT OBJECT (Multi-Agent Aware)
    ══════════════════════════════════════

    CommitObject {
        // Standard fields
        id:              UUID
        parent_ids:      Vec<UUID>           // DAG parents
        timestamp:       ISO-8601
        author:          string              // Human or agent identifier

        // Entity changes
        added_entities:   Vec<EntityHash>
        modified_entities: Vec<(OldHash, NewHash)>
        removed_entities: Vec<EntityHash>

        // AI-Native Metadata
        intent: {
            description:  string             // NL description of what and why
            task_id:      string             // Link to task/issue/ticket
            confidence:   float              // Agent's self-assessed confidence
        }

        validation: {
            tests_passed:  int
            tests_failed:  int
            tests_added:   int
            coverage_delta: float            // Change in code coverage
            lint_status:   enum {pass, warn, fail}
        }

        impact_analysis: {
            affected_entities:  Vec<EntityHash>    // Transitive impact set
            affected_modules:   Vec<string>
            breaking_changes:   Vec<BreakingChange>
            risk_score:         float              // 0.0 (safe) to 1.0 (high risk)
        }

        // Agent coordination
        agent_context: {
            agent_id:      string            // Which agent made this commit
            session_id:    string            // Agent session identifier
            parent_task:   string            // Orchestrating task
            locked_entities: Vec<EntityHash> // Entities this agent claimed
        }
    }
```

This enables:
- **Agent Conflict Prevention:** Agents lock specific entities before editing, preventing concurrent modification
- **Intent Verification:** Automated checks that structural changes match stated intent
- **Risk-Gated Merges:** High-risk commits (breaking changes, low test coverage) require human review
- **Agent Performance Tracking:** Measure which agents produce commits with highest test-pass rates and lowest risk scores

---

## 7. The MCP Server Entry Point

### 7.1 Strategy

The MCP (Model Context Protocol) server is SCG's **wedge product** — the initial entry point that gets developers using the semantic graph without requiring them to change their version control workflow. With 97 million monthly MCP downloads, this is the highest-leverage distribution channel.

### 7.2 Architecture

```
    MCP SERVER ARCHITECTURE
    ═══════════════════════

    ┌─────────────────────────────────────────────────────────────┐
    │                     IDE / AI Agent                          │
    │  (Cursor, VS Code, Claude Code, Windsurf, any MCP client)  │
    └───────────────────────────┬─────────────────────────────────┘
                                │ MCP Protocol (JSON-RPC over stdio)
                                ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                    SCG MCP SERVER                            │
    │                                                             │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
    │  │   Resources   │  │    Tools      │  │    Prompts       │  │
    │  │              │  │              │  │                  │  │
    │  │ scg://entity │  │ search()     │  │ explain_entity() │  │
    │  │ scg://graph  │  │ navigate()   │  │ suggest_fix()    │  │
    │  │ scg://diff   │  │ refactor()   │  │ review_change()  │  │
    │  │ scg://impact │  │ find_dead()  │  │ generate_tests() │  │
    │  │ scg://docs   │  │ get_context()│  │ explain_impact() │  │
    │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
    │         │                 │                    │             │
    │         └─────────────────┼────────────────────┘             │
    │                           │                                  │
    │                    ┌──────┴──────┐                           │
    │                    │ Query Router │                           │
    │                    └──────┬──────┘                           │
    │                           │                                  │
    │              ┌────────────┼────────────┐                     │
    │              ▼            ▼            ▼                     │
    │         ┌────────┐  ┌────────┐  ┌──────────┐               │
    │         │Graph DB│  │Vec DB  │  │Git Bridge│               │
    │         │Memgraph│  │Qdrant  │  │          │               │
    │         └────────┘  └────────┘  └──────────┘               │
    └─────────────────────────────────────────────────────────────┘
```

### 7.3 MCP Tool Definitions

```typescript
// Core MCP tools exposed by the SCG server

tools: [
    {
        name: "scg_search",
        description: "Semantic search across code entities using natural language",
        parameters: {
            query: string,           // Natural language query
            entity_types?: string[], // Filter by entity type
            scope?: string,          // Module/directory scope
            limit?: number           // Max results (default: 10)
        }
    },
    {
        name: "scg_get_context",
        description: "Get JIT context for an entity — returns the entity plus its relevant graph neighborhood",
        parameters: {
            entity_id: string,       // Entity hash or name
            depth?: number,          // BFS traversal depth (default: 2)
            token_budget?: number,   // Max tokens to return (default: 8000)
            include_tests?: boolean  // Include test entities
        }
    },
    {
        name: "scg_navigate",
        description: "Navigate the code graph — find callers, callees, type hierarchy, data flow",
        parameters: {
            entity_id: string,
            direction: "callers" | "callees" | "types" | "data_flow" | "tests",
            depth?: number
        }
    },
    {
        name: "scg_diff",
        description: "Get semantic diff between two commits or branches",
        parameters: {
            base: string,            // Commit hash or branch name
            head: string,
            include_impact?: boolean // Include impact analysis
        }
    },
    {
        name: "scg_find_dead_code",
        description: "Find orphaned entities with no callers or tests",
        parameters: {
            scope?: string,          // Module scope
            include_exports?: boolean
        }
    },
    {
        name: "scg_impact_analysis",
        description: "Analyze the impact of changing a specific entity",
        parameters: {
            entity_id: string,
            change_type: "modify" | "delete" | "rename"
        }
    },
    {
        name: "scg_generate_docs",
        description: "Generate a living document from the graph",
        parameters: {
            doc_type: "claude_md" | "agents_md" | "api_map" | "dependencies" | "architecture",
            scope?: string
        }
    }
]
```

### 7.4 Distribution Plan

1. **NPM / PyPI / Cargo packages** for easy installation
2. **One-line setup:** `npx @scg/mcp-server init` indexes the current repo and starts the MCP server
3. **IDE extension marketplace:** VS Code, JetBrains, Cursor marketplace listings that auto-configure the MCP server
4. **Docker image** for CI/CD integration
5. **GitHub Action** for automatic graph updates on push

---

## 8. Developer Experience and UX

### 8.1 Design Principles

SCG follows **Linear-inspired** design principles: opinionated defaults, keyboard-first interaction, speed as a feature, and progressive disclosure of complexity.

| Principle | Implementation |
|---|---|
| **Speed is non-negotiable** | Rust core engine, in-memory graph (Memgraph), sub-200ms pipeline, zero-copy file I/O |
| **Git compatibility is mandatory** | Developers never need to learn a new VCS. All Git commands work. SCG augments, it does not replace. |
| **Opinionated simplicity** | Sensible defaults for everything. Zero configuration required for basic use. Power users can customize graph queries, context depth, etc. |
| **Progressive disclosure** | Level 1: MCP server "just works" in IDE. Level 2: CLI tools for graph queries. Level 3: Custom Cypher queries and API access. |
| **Local-first privacy** | All computation runs locally by default. No code leaves the developer's machine. Cloud features are opt-in. |

### 8.2 User Workflows

**Workflow 1: Zero-Config AI Context (Day 1)**
```
$ npx @scg/mcp-server init
  Indexing 1,247 files...
  Extracted 8,432 entities
  Built 23,891 edges
  Graph ready in 4.2s

  MCP server running on stdio
  Add to your IDE's MCP configuration:
  {
    "mcpServers": {
      "scg": { "command": "npx", "args": ["@scg/mcp-server"] }
    }
  }
```
From this point, any MCP-compatible AI tool (Cursor, Claude Code, Windsurf) automatically receives graph-powered context instead of file-level context.

**Workflow 2: Semantic Search (CLI)**
```
$ scg search "functions that handle payment processing"
  fn:processPayment (src/payments/processor.ts:42) — score: 0.94
  fn:validateCard (src/payments/validation.ts:15) — score: 0.87
  fn:createCharge (src/payments/stripe.ts:78) — score: 0.82
  class:PaymentService (src/payments/service.ts:10) — score: 0.79

$ scg navigate fn:processPayment --callers --depth=2
  fn:processPayment
    ◄── fn:handleCheckout (src/api/checkout.ts:55)
        ◄── api:POST/checkout (src/api/routes.ts:120)
    ◄── fn:retryPayment (src/jobs/retry.ts:30)
        ◄── fn:processFailedPayments (src/jobs/scheduled.ts:15)
```

**Workflow 3: Dead Code Report**
```
$ scg find-dead --scope=src/
  ORPHANED ENTITIES (no callers, no tests):
    fn:legacyHash (src/utils/crypto.ts:89) — last modified: 2024-03-15
    fn:formatPhoneNumber (src/utils/format.ts:201) — last modified: 2024-01-08
    class:OldUserAdapter (src/adapters/user.ts:15) — last modified: 2023-11-22
    type:DeprecatedConfig (src/types/config.ts:45) — last modified: 2023-09-30

  4 orphaned entities found. Total: ~120 lines of dead code.
  Run `scg remove-dead --dry-run` to preview cleanup.
```

**Workflow 4: Impact Analysis Before Merge**
```
$ scg impact fn:authenticate --change=modify
  IMPACT ANALYSIS: fn:authenticate
  ─────────────────────────────────
  Direct callers: 5
    fn:loginHandler, fn:apiMiddleware, fn:refreshToken,
    fn:oauthCallback, fn:validateSession

  Transitive impact: 23 entities across 8 modules

  Test coverage: 87% (4/5 direct callers tested)
    UNTESTED: fn:oauthCallback — consider adding tests

  Breaking change risk: MEDIUM
    fn:authenticate signature unchanged
    Return type unchanged
    Internal logic change may affect:
      fn:validateSession (depends on token format)

  Recommendation: Run tests for auth + session modules before merge.
```

### 8.3 IDE Integration

```
    IDE INTEGRATION ARCHITECTURE
    ════════════════════════════

    ┌─────────────────────────────────────────────────┐
    │                   IDE                            │
    │                                                 │
    │  ┌──────────────────────────────────────────┐   │
    │  │  SCG Panel (sidebar)                     │   │
    │  │                                          │   │
    │  │  Entity: fn:authenticate                 │   │
    │  │  Module: src/auth/handler.ts             │   │
    │  │                                          │   │
    │  │  ┌─ Callers (5) ─────────────────────┐   │   │
    │  │  │  fn:loginHandler                  │   │   │
    │  │  │  fn:apiMiddleware                 │   │   │
    │  │  │  fn:refreshToken                  │   │   │
    │  │  │  fn:oauthCallback                 │   │   │
    │  │  │  fn:validateSession               │   │   │
    │  │  └───────────────────────────────────┘   │   │
    │  │                                          │   │
    │  │  ┌─ Types ───────────────────────────┐   │   │
    │  │  │  type:AuthRequest                 │   │   │
    │  │  │  type:AuthResponse                │   │   │
    │  │  │  type:TokenPayload                │   │   │
    │  │  └───────────────────────────────────┘   │   │
    │  │                                          │   │
    │  │  ┌─ Tests (2) ──────────────────────┐    │   │
    │  │  │  test:auth_success_flow          │    │   │
    │  │  │  test:auth_invalid_token         │    │   │
    │  │  └──────────────────────────────────┘    │   │
    │  │                                          │   │
    │  │  Coverage: 87% | Complexity: Medium       │   │
    │  │  Last modified: 2 days ago by @dev        │   │
    │  └──────────────────────────────────────────┘   │
    │                                                 │
    │  ┌─ Code Lens (inline) ─────────────────────┐   │
    │  │  fn authenticate(req: AuthRequest)        │   │
    │  │  ↑ 5 callers | 2 tests | 3 types         │   │
    │  └───────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────┘
```

---

## 9. Enterprise Features

### 9.1 Role-Based Access Control (RBAC)

```
    ENTERPRISE RBAC MODEL
    ═════════════════════

    ┌─────────────────────────────────────────────┐
    │              Organization                    │
    │                                             │
    │  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
    │  │  Admin   │  │ Manager │  │Developer│    │
    │  │         │  │         │  │         │    │
    │  │ • CRUD  │  │ • Read  │  │ • Read  │    │
    │  │   repos │  │   all   │  │   assigned│   │
    │  │ • Manage│  │ • Write │  │ • Write │    │
    │  │   teams │  │   team  │  │   assigned│   │
    │  │ • Audit │  │   repos │  │ • Query │    │
    │  │   logs  │  │ • Merge │  │   graph  │    │
    │  │ • Config│  │   review│  │         │    │
    │  └─────────┘  └─────────┘  └─────────┘    │
    │                                             │
    │  GRAPH-LEVEL PERMISSIONS                    │
    │  ─────────────────────────                  │
    │  • Entity-level read/write ACLs             │
    │  • Module-level access boundaries           │
    │  • Cross-repo query restrictions            │
    │  • Audit trail on all graph mutations       │
    └─────────────────────────────────────────────┘
```

### 9.2 Compliance and Governance

| Requirement | SCG Implementation |
|---|---|
| **Data Residency** | Local-first architecture; cloud tier supports region-specific deployment (EU, US, APAC) |
| **EU AI Act Compliance** | Full provenance chain: every AI-generated entity carries agent_id, intent, validation state |
| **Code Provenance** | Content-addressed DAG provides cryptographic proof of code lineage (every entity hash chains to its parent) |
| **SOC 2 Type II** | Audit logging of all graph mutations, access events, and agent actions |
| **GDPR** | Graph supports fine-grained deletion — remove specific entities and all edges referencing them |
| **SBOM Generation** | Graph natively represents dependency chains; SBOM export is a graph traversal |
| **License Compliance** | Entity-level license tagging; detect license conflicts across the dependency graph |

### 9.3 Code Provenance Chain

```
    CODE PROVENANCE: ENTITY LINEAGE
    ════════════════════════════════

    EntityHash: abc123
    ├── Created by: agent:claude-4 (session: xyz)
    ├── Intent: "Add rate limiting to API endpoint"
    ├── Parent hash: def456
    │   ├── Created by: human:@alice
    │   ├── Parent hash: ghi789
    │   │   └── Created by: human:@bob (initial implementation)
    │   └── Validation: 14/14 tests passed, coverage 92%
    ├── Validation: 16/16 tests passed, coverage 94%
    ├── Review: approved by human:@alice
    └── Deployed: production (2026-03-10T14:30:00Z)

    Every entity in the graph carries its complete creation history,
    enabling full audit trail from deployment back to initial creation.
```

### 9.4 Enterprise Deployment Options

```
    DEPLOYMENT TIERS
    ════════════════

    ┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
    │   LOCAL      │     │   TEAM CLOUD     │     │   ENTERPRISE      │
    │   (Free)     │     │  ($20/seat/mo)   │     │  ($50/seat/mo)    │
    │              │     │                  │     │                   │
    │ • MCP server │     │ • Hosted graph   │     │ • Self-hosted     │
    │ • Local graph│     │ • Cross-repo     │     │ • On-premise      │
    │ • CLI tools  │     │   queries        │     │ • Air-gapped      │
    │ • IDE plugin │     │ • Team sharing   │     │ • SSO/SAML        │
    │              │     │ • Shared docs    │     │ • Custom SLAs     │
    │              │     │ • CI/CD hooks    │     │ • Dedicated support│
    │              │     │                  │     │ • Compliance cert  │
    └─────────────┘     └──────────────────┘     └───────────────────┘
```

---

## 10. Technical Moats and Defensibility

### 10.1 The Open Core Strategy

```
    OPEN SOURCE (Apache 2.0)             PROPRIETARY
    ════════════════════════             ═══════════

    • MCP Server                         • Semantic Compiler (Rust)
    • Git Bridge                         • Intent Engine
    • IDE Plugins (VS Code,              • Cross-Repo Knowledge Graph
      JetBrains, Cursor)                 • Enterprise RBAC + Audit
    • CLI Tools                          • Cloud Sync + Hosting
    • Tree-sitter Query Sets             • Advanced Analytics
    • Graph Schema (public spec)         • Priority Support
    • Basic Graph Queries                • Custom Integrations
```

This follows the proven open-core model:
- **GitLab:** Open-source CE, proprietary EE → $16B market cap
- **Elastic:** Open Elasticsearch, proprietary X-Pack → $10B+ market cap
- **HashiCorp:** Open Terraform, proprietary Terraform Cloud → $5B+ acquisition by IBM

The open-source layer creates developer trust, community contributions (especially tree-sitter query sets for new languages), and ecosystem lock-in. The proprietary layer captures value from teams and enterprises who need cross-repo intelligence, compliance, and managed hosting.

### 10.2 Four Moats

**Moat 1: Zero-Copy Local Indexing (Rust Engine)**
The Semantic Compiler runs as a native Rust binary, parsing and indexing code at near-filesystem speeds with zero-copy I/O. Competitors building in Python, TypeScript, or Java face a 10-100x performance disadvantage for local indexing. Sub-200ms total pipeline latency is achievable only in systems-level languages with careful memory management.

**Moat 2: Proprietary Intent Engine**
The Intent Engine correlates natural language task descriptions with structural code changes, building a learned model of "what developers mean when they say X." This model improves with every commit across all SCG users (with opt-in telemetry), creating a network effect that new entrants cannot replicate.

**Moat 3: Cross-Repository Knowledge Graph**
The most powerful moat. As organizations index multiple repositories, SCG builds a cross-repo knowledge graph that reveals:
- Shared entities across services (common types, shared libraries)
- Cross-service API contracts and data flow
- Organization-wide architectural patterns and anti-patterns

This graph becomes more valuable with every additional repository, creating **data gravity** that makes migration increasingly costly.

**Moat 4: Tribal Knowledge Capture**
Over time, SCG accumulates institutional knowledge that exists nowhere else:
- Which entities are frequently modified together (implicit coupling)
- Which patterns lead to bugs (from test failure correlation)
- Which architectural decisions were made and why (from intent metadata)
- Which code is authoritative vs. deprecated (from usage patterns)

This tribal knowledge moat deepens continuously and is impossible for a competitor to replicate without the same longitudinal data.

### 10.3 Defensibility Matrix

```
    DEFENSIBILITY vs. POTENTIAL COMPETITORS
    ═══════════════════════════════════════

                        │ GitHub  │ OpenAI │ Cursor │ Potpie │ Ataraxy│
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    Semantic Graph      │ Would   │ Would  │ No     │ YES    │ YES    │
    (Entity-level)      │ need to │ need to│ graph  │ (Neo4j)│(custom)│
                        │ rebuild │ build  │        │        │        │
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    Version Control     │ Git     │ Would  │ No     │ No     │ YES    │
    (Entity-level)      │ (file)  │ need to│        │        │(CLI)   │
                        │         │ build  │        │        │        │
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    AI Context          │ Copilot │ ChatGPT│ YES    │ Partial│ No     │
    Delivery            │ (file)  │ (file) │(file)  │        │        │
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    MCP Distribution    │ No      │ No     │ Client │ No     │ No     │
    (Server)            │         │        │ only   │        │        │
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    Rust Performance    │ N/A     │ N/A    │ N/A    │ No     │ Partial│
    (Local indexing)    │         │        │        │(Python)│        │
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    Cross-Repo Graph    │ Possible│Possible│ No     │ No     │ No     │
    (Network effect)    │(costly) │(costly)│        │        │        │
    ────────────────────┼─────────┼────────┼────────┼────────┼────────│
    ACQUISITION         │ HIGH    │ HIGH   │ LOW    │ MEDIUM │ MEDIUM │
    INTEREST            │         │        │        │        │        │
    └───────────────────┴─────────┴────────┴────────┴────────┴────────┘

    KEY INSIGHT: No single competitor has all five capabilities.
    GitHub and OpenAI have distribution but lack the graph.
    Potpie and Ataraxy have partial graphs but lack distribution.
    SCG builds all five from day one.
```

---

## 11. Business Strategy and Acquisition Path

### 11.1 Three-Phase Roadmap

```
    PHASE 1                  PHASE 2                  PHASE 3
    LOCAL MCP WEDGE          SEMANTIC BUILD/CI         MULTI-AGENT PLATFORM
    (Months 1-6)             (Months 7-18)            (Months 18-36)
    ═══════════════          ═══════════════          ═══════════════════

    Goal: Developer           Goal: Team adoption      Goal: Platform
    love + adoption           + revenue                dominance

    ┌─────────────────┐      ┌─────────────────┐      ┌──────────────────┐
    │ • MCP server    │      │ • Cloud graph    │      │ • Agent marketplace│
    │ • Local graph   │      │ • Semantic CI    │      │ • Cross-repo graph│
    │ • CLI tools     │      │ • Team sharing   │      │ • Intent Engine   │
    │ • IDE plugins   │      │ • Semantic merge │      │ • Agent versioning│
    │ • Git Bridge    │      │ • Code review    │      │ • Enterprise suite│
    │                 │      │   integration    │      │ • API platform    │
    └────────┬────────┘      └────────┬────────┘      └────────┬─────────┘
             │                        │                         │
    Metrics:                 Metrics:                 Metrics:
    • 10K developers         • 50K developers         • 500K+ developers
    • GitHub stars           • $2M ARR                • $25M+ ARR
    • MCP downloads          • 500 teams              • 5,000+ orgs
    • Community PRs          • 95% retention          • Platform GMV
```

### 11.2 Phase 1: Local MCP Wedge (Months 1-6)

**Objective:** Become the most-installed MCP server for code intelligence.

**Deliverables:**
- Open-source MCP server with local graph indexing
- Tree-sitter-based Semantic Compiler (Tier 1 languages: TS, JS, Python, Go, Rust)
- In-memory Memgraph for local graph queries
- Local Qdrant for vector search
- Git Bridge for bidirectional translation
- CLI tools: `scg search`, `scg navigate`, `scg find-dead`, `scg impact`
- VS Code extension with SCG panel

**Go-to-Market:**
- Launch on Hacker News, Reddit r/programming, Twitter/X developer community
- Product Hunt launch
- GitHub repo with comprehensive README and demo videos
- MCP marketplace listing (if available)
- Developer blog posts: "Why your AI coding tool is working with one hand tied behind its back"

**Key Metrics:**
- 10,000 active developers (weekly MCP server usage)
- 5,000 GitHub stars
- 50,000 npm/cargo/pip downloads
- 100+ community contributions (tree-sitter queries, bug fixes)

### 11.3 Phase 2: Semantic Build and CI (Months 7-18)

**Objective:** Prove the business model. Convert individual developers to team plans.

**Deliverables:**
- Cloud-hosted graph (multi-repo, team-shared)
- Semantic CI integration: run only tests affected by entity-level changes (not file-level)
- Semantic code review: PR diffs show entity changes + impact analysis
- Team dashboards: code health metrics, dead code trends, coupling analysis
- GitHub/GitLab integration (webhooks, PR comments)
- Semantic merge conflict resolution (GumTree-based)

**Pricing:**
- Free tier: Local MCP server, single-repo graph, CLI tools
- Team plan: $20/seat/month — cloud graph, cross-repo, CI integration, team sharing
- Enterprise: Contact sales — self-hosted, RBAC, compliance, SLA

**Revenue Drivers:**
- **CI savings:** Semantic test selection reduces CI run time by 40-60% (only running tests for affected entities, not entire test suites). At scale, this saves significant cloud compute costs.
- **Merge velocity:** Semantic merge resolution reduces merge conflicts by ~50% (based on Ataraxy Labs benchmarks), directly accelerating team velocity.
- **Code review efficiency:** Impact analysis on PRs reduces review time by surfacing exactly what's affected.

**Key Metrics:**
- $2M ARR
- 500 paying teams
- 95% month-over-month retention
- 50K active developers

### 11.4 Phase 3: Multi-Agent Platform (Months 18-36)

**Objective:** Become the infrastructure layer for AI-native software development.

**Deliverables:**
- Multi-agent versioning (Section 6.5)
- Agent marketplace: third-party agents that consume SCG's graph API
- Intent Engine: NL-to-code-change correlation model
- Cross-organization Knowledge Graph (opt-in, anonymized)
- Advanced analytics: architectural drift detection, technical debt quantification
- Full enterprise suite: SAML/SSO, audit logs, data residency, compliance certifications

**Platform Revenue Model:**
- Enterprise seats: $50/seat/month
- Platform API access: usage-based pricing for third-party agent developers
- Agent marketplace: 20% commission on paid agent transactions
- Managed hosting: premium pricing for large-scale, dedicated deployments

**Key Metrics:**
- $25M+ ARR
- 500K+ active developers
- 5,000+ organizations
- 50+ third-party agents on marketplace

### 11.5 Acquisition Targets

SCG is designed to be a compelling acquisition target for multiple potential acquirers:

| Acquirer | Strategic Value | Estimated Value |
|---|---|---|
| **Microsoft (GitHub)** | Replace GitHub's file-level architecture with semantic graph; leapfrog OpenAI's competitor | $500M-$2B |
| **OpenAI** | Infrastructure layer for their GitHub competitor; SCG provides what they would need to build from scratch | $300M-$1B |
| **Anthropic** | Enhance Claude Code with graph-native context delivery; competitive advantage against OpenAI/GitHub | $200M-$800M |
| **Atlassian** | Modernize Bitbucket with AI-native capabilities; integrate with Jira for intent-to-code tracking | $200M-$500M |
| **Google** | Complement Kythe and internal code graph systems; external developer platform play | $300M-$1B |

The three moats (Rust engine, cross-repo graph data gravity, tribal knowledge capture) ensure that even well-resourced acquirers would find it faster to buy than to build.

### 11.6 Potential Acqui-hire / Integration Targets for SCG

| Company | What They Bring | Integration Strategy |
|---|---|---|
| **Potpie AI** | Neo4j code graph expertise, early customers | Merge their indexer into SCG's Semantic Compiler |
| **Ataraxy Labs** | Entity-level VCS research, sem+weave CLI | Merge their semantic diff/merge into SCG's Git Bridge |
| **Difftastic** | Production-grade structural diff, 30+ languages | License or acquire the diff engine for Git Bridge |

---

## 12. Technical Stack and MVP Scope

### 12.1 Technology Choices

```
    TECHNICAL STACK
    ═══════════════

    LAYER               TECHNOLOGY              RATIONALE
    ─────               ──────────              ─────────

    Core Engine         Rust                    Performance, memory safety,
                                                zero-cost abstractions

    Parsing             tree-sitter (C/Rust)    Incremental, error-tolerant,
                                                30+ languages

    Incremental         Salsa pattern           Sub-100ms recomputation,
    Computation         (custom Rust impl)      memoized query framework

    Graph Database      Memgraph (local)        In-memory, C++, sub-ms queries
                        Neo4j (cloud/enterprise) Mature, scalable, Cypher

    Vector Database     Qdrant (local)          Rust-native, fast ANN search
                        pgvector (cloud)        PostgreSQL integration

    Embedding Model     Nomic Embed Code        Local inference, code-optimized
                        (ONNX quantized)        768-dim, fast on CPU

    MCP Server          TypeScript/Node.js      MCP SDK ecosystem,
                        (thin layer over Rust)  developer familiarity

    Git Bridge          Rust (libgit2 bindings) Direct Git object manipulation,
                                                high performance

    CLI                 Rust (clap)             Fast startup, native binary

    IDE Extensions      TypeScript              VS Code API, JetBrains plugin SDK

    Cloud API           Rust (Axum)             High-performance HTTP framework

    CI/CD Integration   GitHub Actions,         Webhook-based, event-driven
                        GitLab CI
```

### 12.2 MVP Scope (Phase 1, Months 1-6)

**In Scope (Must Ship):**

| Component | Scope | Est. Effort |
|---|---|---|
| Semantic Compiler | Tree-sitter parsing → Entity extraction → Content addressing → Graph storage | 8 weeks |
| Graph Store | Memgraph integration, entity/edge CRUD, basic Cypher queries | 4 weeks |
| Vector Store | Qdrant integration, entity embedding, semantic search | 3 weeks |
| Git Bridge (Inbound) | File change detection → incremental graph update | 4 weeks |
| Git Bridge (Outbound) | Graph → file reconstruction for git compatibility | 3 weeks |
| MCP Server | 7 core tools (search, context, navigate, diff, dead-code, impact, docs) | 4 weeks |
| CLI | `scg init`, `scg search`, `scg navigate`, `scg find-dead`, `scg impact` | 2 weeks |
| VS Code Extension | SCG panel, code lens, MCP auto-configuration | 3 weeks |
| Language Support | TypeScript, JavaScript, Python (Tier 1) | 3 weeks |

**Out of Scope (Phase 2+):**

- Cloud-hosted graph
- Semantic merge conflict resolution
- Multi-agent versioning
- Cross-repo Knowledge Graph
- Enterprise RBAC/compliance
- Go and Rust language support (Tier 1b, weeks after launch)
- CI/CD integration

### 12.3 System Architecture (MVP)

```
    MVP SYSTEM ARCHITECTURE
    ═══════════════════════

    ┌─────────────────────────────────────────────────────┐
    │                    DEVELOPER MACHINE                 │
    │                                                     │
    │  ┌──────────┐     ┌───────────────────────────┐     │
    │  │   IDE    │◄───►│      MCP Server            │     │
    │  │(VS Code) │     │   (TypeScript/Node.js)     │     │
    │  └──────────┘     │                           │     │
    │                   │  ┌─────────────────────┐   │     │
    │  ┌──────────┐     │  │   Rust Core Engine  │   │     │
    │  │   CLI    │◄───►│  │  (FFI via napi-rs)  │   │     │
    │  │ (scg)   │     │  │                     │   │     │
    │  └──────────┘     │  │ • Semantic Compiler │   │     │
    │                   │  │ • Content Addresser │   │     │
    │  ┌──────────┐     │  │ • Graph Emitter    │   │     │
    │  │   Git    │◄───►│  │ • Git Bridge       │   │     │
    │  │(standard)│     │  └─────────────────────┘   │     │
    │  └──────────┘     │           │                │     │
    │                   │     ┌─────┴─────┐          │     │
    │                   │     │           │          │     │
    │                   │  ┌──┴───┐  ┌───┴───┐      │     │
    │                   │  │Graph │  │Vector │      │     │
    │                   │  │Store │  │Store  │      │     │
    │                   │  │(Memgr│  │(Qdrant│      │     │
    │                   │  │ aph) │  │)      │      │     │
    │                   │  └──────┘  └───────┘      │     │
    │                   └───────────────────────────┘     │
    │                                                     │
    │  ┌──────────────────────────────────────────────┐   │
    │  │              File System                      │   │
    │  │  .git/          (standard Git objects)        │   │
    │  │  .scg/          (graph data, vector index)    │   │
    │  │  src/           (source code - untouched)     │   │
    │  └──────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────┘
```

### 12.4 Repository Structure (MVP)

```
scg/
├── Cargo.toml                    # Rust workspace
├── crates/
│   ├── scg-core/                 # Entity model, content addressing
│   │   ├── src/
│   │   │   ├── entity.rs         # EntityObject definition
│   │   │   ├── hash.rs           # SHA-256 content addressing
│   │   │   ├── graph_schema.rs   # Node/edge type definitions
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   ├── scg-compiler/             # Semantic Compiler pipeline
│   │   ├── src/
│   │   │   ├── parser.rs         # Tree-sitter integration
│   │   │   ├── extractor.rs      # Entity extraction
│   │   │   ├── analyzer.rs       # Salsa-inspired semantic analysis
│   │   │   ├── embedder.rs       # Vector embedding (ONNX)
│   │   │   ├── emitter.rs        # Graph + vector store writes
│   │   │   └── lib.rs
│   │   ├── queries/              # Tree-sitter query files
│   │   │   ├── typescript.scm
│   │   │   ├── javascript.scm
│   │   │   └── python.scm
│   │   └── Cargo.toml
│   ├── scg-graph/                # Graph database interface
│   │   ├── src/
│   │   │   ├── memgraph.rs       # Memgraph client
│   │   │   ├── queries.rs        # Cypher query builders
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   ├── scg-vector/               # Vector database interface
│   │   ├── src/
│   │   │   ├── qdrant.rs         # Qdrant client
│   │   │   ├── search.rs         # ANN search + filtering
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   ├── scg-bridge/               # Git Bridge
│   │   ├── src/
│   │   │   ├── inbound.rs        # Files → graph translation
│   │   │   ├── outbound.rs       # Graph → files reconstruction
│   │   │   ├── watcher.rs        # File system watcher
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   └── scg-cli/                  # CLI binary
│       ├── src/
│       │   ├── main.rs
│       │   ├── commands/
│       │   │   ├── init.rs
│       │   │   ├── search.rs
│       │   │   ├── navigate.rs
│       │   │   ├── dead_code.rs
│       │   │   └── impact.rs
│       │   └── lib.rs
│       └── Cargo.toml
├── packages/
│   ├── mcp-server/               # MCP server (TypeScript)
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── tools/
│   │   │   │   ├── search.ts
│   │   │   │   ├── context.ts
│   │   │   │   ├── navigate.ts
│   │   │   │   ├── diff.ts
│   │   │   │   ├── dead_code.ts
│   │   │   │   ├── impact.ts
│   │   │   │   └── docs.ts
│   │   │   └── bridge.ts         # napi-rs FFI to Rust core
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── vscode-extension/         # VS Code extension
│       ├── src/
│       │   ├── extension.ts
│       │   ├── panel.ts
│       │   └── codelens.ts
│       └── package.json
├── docs/
│   ├── architecture.md
│   ├── graph-schema.md
│   └── contributing.md
└── README.md
```

---

## 13. Risk Analysis

### 13.1 Technical Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| **Tree-sitter grammar quality varies by language** | Medium | High | Focus on Tier 1 (TS/JS/Python) where grammars are production-grade. Community contributions for others. Fallback to file-level indexing for unsupported languages. |
| **Semantic analysis complexity underestimated** | High | Medium | Start with lightweight analysis (call graph, basic types). Defer full data flow analysis to Phase 2. Salsa framework keeps incremental overhead manageable. |
| **Memgraph local resource consumption** | Medium | Medium | Profile aggressively. Implement graph compaction (evict old versions). Provide configurable memory limits. Memgraph's in-memory model keeps footprint predictable. |
| **Vector embedding quality insufficient** | Low | Medium | Use established code embedding models (Nomic, CodeBERT). Fine-tune on SCG-specific entity format. Hybrid retrieval (vector + graph) compensates for embedding noise. |
| **Git Bridge reconstruction fidelity** | High | Low | Extensive test suite comparing reconstructed files against originals. Preserve original formatting metadata. Run formatters as final pass. Property-based testing with arbitrary code inputs. |
| **Content addressing collision probability** | Low | Very Low | SHA-256 collision probability is ~10^-38 for any reasonable codebase. Unison has operated this model for years without issues. |
| **Incremental compilation correctness** | High | Medium | Formal property: `compile(full) == apply_incremental(changes, cached)`. Continuous verification via shadow full-recompilation on a fraction of builds. |

### 13.2 Market Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| **GitHub ships semantic features** | High | Medium | GitHub's architecture makes entity-level VCS extremely difficult to retrofit. Their moat is distribution, not technology. SCG's open-core model and local-first approach serve a different segment. |
| **OpenAI acquires a competitor first** | Medium | Medium | Move fast on Phase 1. SCG's open-source wedge creates community lock-in that survives competitive acquisitions. If OpenAI acquires Potpie or Ataraxy, SCG's broader platform vision remains differentiated. |
| **Developer resistance to new tools** | Medium | High | Git Bridge eliminates workflow disruption. Developers don't need to learn anything new — SCG augments existing tools via MCP. The value proposition (better AI context) is immediately tangible. |
| **MCP standard loses momentum** | Low | Low | MCP has 97M monthly downloads and backing from Anthropic. Even if MCP stalls, SCG's architecture supports any API/plugin model. The graph is the moat, not the protocol. |
| **Economic downturn reduces developer tooling budgets** | Medium | Medium | Free tier ensures continued adoption. CI cost savings (40-60% reduction) provide hard ROI that justifies spend even in downturns. |

### 13.3 Organizational Risks

| Risk | Severity | Probability | Mitigation |
|---|---|---|---|
| **Rust talent scarcity** | Medium | High | Core team of 2-3 senior Rust engineers. Supplement with experienced C/C++ engineers who can ramp on Rust. Remote-first hiring expands talent pool. |
| **Scope creep across 3 phases** | High | High | Strict phase gating. Phase 2 does not begin until Phase 1 metrics are met. Product manager role dedicated to scope control. |
| **Open-source community expectations** | Medium | Medium | Clear open/proprietary boundary from day one. Transparent roadmap. Community advisory board for open-source direction. |

---

## 14. Appendix

### 14.1 Complete Graph Schema (Cypher DDL)

```cypher
// Node constraints
CREATE CONSTRAINT ON (e:Entity) ASSERT e.hash IS UNIQUE;
CREATE CONSTRAINT ON (m:Module) ASSERT m.path IS UNIQUE;
CREATE CONSTRAINT ON (c:Commit) ASSERT c.id IS UNIQUE;

// Node labels and properties
// Entity: { hash, entity_type, name, language, file_origin, byte_range_start,
//           byte_range_end, source, signature, docstring, parent_hashes,
//           commit_id, timestamp }
// Module: { path, language, commit_id }
// Commit: { id, parent_ids, author, timestamp, message, intent_description,
//           intent_task_id, intent_confidence, validation_tests_passed,
//           validation_tests_failed, validation_coverage_delta,
//           impact_risk_score, agent_id, session_id }

// Edge types
// (:Module)-[:CONTAINS]->(:Entity)
// (:Entity)-[:CALLS {weight, commit_id}]->(:Entity)
// (:Entity)-[:REFERENCES {commit_id}]->(:Entity)
// (:Class)-[:EXTENDS {commit_id}]->(:Class)
// (:Class)-[:IMPLEMENTS {commit_id}]->(:Interface)
// (:Entity)-[:DATA_FLOWS_TO {confidence, commit_id}]->(:Entity)
// (:Entity)-[:HAS_TYPE {commit_id}]->(:Type)
// (:Test)-[:TESTS {commit_id}]->(:Entity)
// (:Module)-[:IMPORTS {commit_id}]->(:Module)
// (:Module)-[:EXPOSES {commit_id}]->(:Entity)
// (:Entity)-[:DEPENDS_ON {commit_id}]->(:Entity)

// Indexes for common query patterns
CREATE INDEX ON :Entity(entity_type);
CREATE INDEX ON :Entity(name);
CREATE INDEX ON :Entity(file_origin);
CREATE INDEX ON :Entity(commit_id);
CREATE INDEX ON :Module(language);
```

### 14.2 Key Statistics and Benchmarks

| Metric | Value | Source |
|---|---|---|
| Developers using AI tools | 85% | Stack Overflow 2025 Survey |
| Developers spending more time fixing AI code | 66% | GitClear 2025 Report |
| Developers distrusting AI output | 46% | GitHub Octoverse 2025 |
| MCP monthly downloads | 97M | npm registry, March 2026 |
| Context rot threshold | ~100K tokens | Anthropic research, 2025 |
| GraphRAG hallucination reduction | 90% vs traditional RAG | Microsoft Research, 2025 |
| GitHub incident increase | 58% YoY | GitHub Status, 2025-2026 |
| GumTree merge success (entity-level) | 31/31 | Ataraxy Labs benchmark |
| Git merge success (same test set) | 15/31 | Ataraxy Labs benchmark |
| Semantic diff accuracy improvement | 2.3x vs Git diffs | Ataraxy Labs benchmark |
| SCIP size advantage over LSIF | 4x smaller | Sourcegraph benchmarks |
| SCIP speed advantage over LSIF | 10x faster | Sourcegraph benchmarks |
| Salsa incremental recomputation | Sub-100ms | rust-analyzer benchmarks |
| Potpie root-cause analysis speedup | 1 week → 30 minutes | Potpie AI case studies |
| Cursor valuation | $29B (March 2026) | Public reports |
| Tree-sitter supported languages | 30+ | tree-sitter GitHub |
| SHA-256 collision probability | ~10^-38 | Cryptographic analysis |

### 14.3 Glossary

| Term | Definition |
|---|---|
| **Entity** | A discrete semantic unit of code: function, class, type, API endpoint, schema, test |
| **Entity Object** | The complete representation of an entity: AST, hash, metadata, embedding, lineage |
| **Content Addressing** | Using SHA-256(normalized_AST) as the unique identifier for an entity |
| **DAG** | Directed Acyclic Graph — the versioning structure for entity lineage |
| **Dual-Store** | Graph DB (deterministic queries) + Vector DB (semantic queries) |
| **Semantic Compiler** | The pipeline that transforms source files into entity objects |
| **Git Bridge** | Bidirectional translation between file-based Git and entity-based SCG |
| **JIT Contextualization** | BFS graph traversal to deliver pruned, relevant context to AI agents |
| **Intent Engine** | NL-to-code-change correlation model (proprietary, Phase 3) |
| **Living Documents** | Virtual files generated on-the-fly from graph state (never stored) |
| **Orphan Detection** | Graph query for entities with zero incoming edges (dead code) |
| **MCP** | Model Context Protocol — standard for AI tool integration |
| **Tree-sitter** | Incremental parsing framework supporting 30+ languages |
| **Salsa** | Query-based incremental computation framework (from rust-analyzer) |
| **GumTree** | AST-level diff algorithm for structural comparison |
| **Cypher** | Query language for graph databases (Neo4j, Memgraph) |
| **BFS** | Breadth-First Search — graph traversal algorithm used for context expansion |
| **CST** | Concrete Syntax Tree — full parse tree including whitespace and comments |
| **AST** | Abstract Syntax Tree — simplified parse tree focused on semantic structure |
| **SCIP** | Sourcegraph Code Intelligence Protocol — compact code index format |
| **ANN** | Approximate Nearest Neighbor — vector similarity search algorithm |

### 14.4 References

1. **Unison Language** — Content-addressed code model. https://www.unison-lang.org/
2. **Jujutsu (jj)** — Git-compatible experimental VCS by Google. https://github.com/martinvonz/jj
3. **GumTree** — AST diff algorithm. Falleri et al., "Fine-grained and Accurate Source Code Differencing" (ASE 2014)
4. **Difftastic** — Structural diff tool. https://difftastic.wilfred.me.uk/
5. **Salsa** — Incremental computation framework. https://github.com/salsa-rs/salsa
6. **Tree-sitter** — Incremental parsing. https://tree-sitter.github.io/
7. **SCIP** — Sourcegraph Code Intelligence Protocol. https://sourcegraph.com/blog/announcing-scip
8. **Kythe** — Google's language-agnostic code graph. https://kythe.io/
9. **CodeQL** — GitHub's code analysis engine. https://codeql.github.com/
10. **Memgraph** — In-memory graph database. https://memgraph.com/
11. **Qdrant** — Vector similarity search engine. https://qdrant.tech/
12. **MCP (Model Context Protocol)** — Anthropic. https://modelcontextprotocol.io/
13. **AGENTS.md** — Linux Foundation standard for AI agent metadata
14. **Potpie AI** — Code knowledge graphs. https://potpie.ai/
15. **Ataraxy Labs** — Semantic version control research

---

## 15. VCS-Bench: The Built-In Benchmarking Engine

### 15.1 Why Benchmarking Is a Core Feature, Not an Afterthought

Engineering directors don't buy tools because they have cool architecture — they buy tools that **prove ROI on their actual codebase**. Generic LLM benchmarks (HumanEval, SWE-bench) only test if an AI can write a standalone function. They say nothing about how well an AI navigates a team's specific 500K-line monorepo.

SCG ships with **VCS-Bench** — a built-in benchmarking engine that measures AI effectiveness on the customer's real codebase, providing live proof that the semantic graph outperforms file-based approaches.

**Strategic value:** VCS-Bench creates a "try before you buy" motion. Teams plug in their repo, see the numbers, and sell the tool to their own management.

### 15.2 The Three Dimensions of Measurement

VCS-Bench measures across three axes: **Context Efficiency**, **Logical Accuracy**, and **Economic Impact**.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VCS-BENCH MEASUREMENT FRAMEWORK                   │
│                                                                       │
│  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────────┐  │
│  │ CONTEXT           │  │ LOGICAL            │  │ ECONOMIC          │  │
│  │ EFFICIENCY        │  │ ACCURACY           │  │ IMPACT            │  │
│  │                   │  │                    │  │                   │  │
│  │ • Token-to-Logic  │  │ • First-Pass Pass  │  │ • Cost per Task   │  │
│  │   Ratio           │  │   Rate (unit tests)│  │ • Token Waste $   │  │
│  │ • Dependency      │  │ • Dependency       │  │ • Time-to-Context │  │
│  │   Coverage %      │  │   Coverage         │  │ • Babysitting     │  │
│  │ • Context Warm-up │  │ • Zero Broken      │  │   Time Saved      │  │
│  │   Latency         │  │   Contracts        │  │ • Monthly Savings │  │
│  └──────────────────┘  └───────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

#### Core Metrics

| Metric | Definition | Formula | Why It Matters |
|---|---|---|---|
| **Token-to-Logic Ratio** | What % of injected tokens were actually relevant | `Relevant Lines / Total Tokens Injected` | Measures context noise. File-based RAG scores ~2%. SCG targets >85%. |
| **Dependency Coverage** | % of upstream/downstream call sites correctly identified | `Identified Dependencies / Total Dependencies` | 100% = zero broken contracts after refactor. File RAG misses edge cases. |
| **First-Pass Pass Rate** | % of AI-generated PRs that pass unit tests on attempt #1 | `Passing PRs / Total PRs` | Directly correlates to developer "babysitting" time. |
| **Context Warm-up Latency** | Time from "task start" to "full context loaded" | `Time(context_ready) - Time(task_start)` | SCG: graph traversal in ms. File RAG: file scanning in seconds/minutes. |
| **Cost per Task** | LLM API cost to complete a specific coding task | `Total Tokens × Cost/Token` | The CFO metric. SCG eliminates 90%+ token waste. |
| **Hallucination Rate** | % of AI suggestions referencing non-existent code/APIs | `Hallucinated References / Total References` | GraphRAG reduces hallucinations by ~90% vs traditional RAG. |

### 15.3 The Stress Test Scenarios

VCS-Bench includes standardized scenarios specifically designed to expose where file-based RAG fails.

#### Scenario A: "Deep Ripple" Refactor

**Task:** Change a core TypeScript interface or Pydantic model used across 15+ services in a monorepo.

```
SETUP:
  - Target: `PaymentMethod` interface used by 17 downstream consumers
  - Change: Add a required `currency: CurrencyCode` field
  - Success criteria: All 17 consumers updated, all tests pass

FILE-BASED RAG (Baseline):
  - Grep/vector search finds 14/17 consumers (82%)
  - Misses 3: one in a test helper, one in a migration script, one in a
    serialization layer outside the main /src directory
  - Tokens consumed: ~85,000 (reading entire files to find references)
  - First-pass test result: FAIL (3 broken imports)

SCG (Graph Traversal):
  - Cypher query: MATCH (n)-[:IMPLEMENTS|:REFERENCES]->(i:Interface {name: 'PaymentMethod'})
    RETURN n
  - Finds 17/17 consumers (100%) — deterministic, not probabilistic
  - Tokens consumed: ~1,200 (only entity signatures + call context)
  - First-pass test result: PASS
```

**Expected headline:** *"SCG identified 100% of affected call sites using 70x fewer tokens."*

#### Scenario B: "Orphaned Logic" Cleanup

**Task:** Identify all dead code in the `/services/billing` directory.

```
FILE-BASED RAG (Baseline):
  - AI reads every file in the directory (~40 files, ~8,000 lines)
  - Attempts to reason about which functions are called
  - Hallucinates that 3 functions are "probably used" by external services
  - Time: 45 seconds of LLM processing
  - Tokens: ~32,000
  - Accuracy: Found 6/10 orphans (missed 4, false-positive on 3)

SCG (Graph Query):
  - Cypher: MATCH (f:Function)-[:DEFINED_IN]->(m:Module)
    WHERE m.path STARTS WITH '/services/billing'
    AND NOT ()-[:CALLS]->(f)
    AND NOT f.is_entry_point
    RETURN f.name, f.file, f.line_number
  - Time: 12ms
  - Tokens: 0 (pure graph query, no LLM needed)
  - Accuracy: 10/10 orphans identified (deterministic)
```

**Expected headline:** *"SCG found 4x more dead code in 0.04% of the time — without using any LLM tokens."*

#### Scenario C: "Blind Refactor" (The Killer Demo)

**Task:** A random, deeply-nested utility function is deleted from a repo the AI has never seen. Ask the AI to "Fix the repo."

```
SETUP:
  - Target repo: cal.com, Supabase, or similar well-known OSS project
  - Deleted function: A utility 3 levels deep in the import chain
  - 9 files transitively depend on it

FILE-BASED RAG:
  - AI sees import errors in 2-3 files (the direct importers)
  - Fixes those, but misses 6 transitive dependents
  - Multiple rounds of "fix → test → fail → fix" required
  - Total rounds to green: 4-6

SCG:
  - Graph immediately returns the full dependency subgraph of the deleted node
  - AI receives all 9 affected files with exact call sites
  - Total rounds to green: 1
```

**Expected headline:** *"SCG resolved a transitive dependency break in one pass. File-based tools needed 5 rounds."*

#### Scenario D: "Cross-Repo Impact Analysis"

**Task:** A shared npm package's API changes. Identify all consuming services that will break.

```
FILE-BASED RAG:
  - Cannot cross repository boundaries at all
  - Developer must manually check each consuming repo
  - Often discovers breaks only in production

SCG (Cross-Repo Knowledge Graph):
  - Query: MATCH (f:Function)-[:CALLS]->(api:Function {package: '@company/shared-types'})
    WHERE api.signature_hash != api.previous_signature_hash
    RETURN f, f.repository, f.file
  - Returns every consumer across every connected repository
  - Time: <100ms
```

### 15.4 The "Shadow Agent" — Automated Continuous Benchmarking

Once VCS-Bench is integrated, it runs automatically in the background.

```
┌─────────────────────────────────────────────────────────────┐
│                    SHADOW AGENT PIPELINE                      │
│                                                               │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
│  │ Recently  │───►│ Roll Back│───►│ Run Both │───►│ Compare│ │
│  │ Merged PR │    │ Code     │    │ RAG + SCG│    │ Results│ │
│  └──────────┘    │ State    │    │ Agents   │    │        │ │
│                   └──────────┘    └──────────┘    └───┬────┘ │
│                                                       │      │
│                                              ┌────────▼────┐ │
│                                              │  Dashboard   │ │
│                                              │  Update      │ │
│                                              └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**How it works:**
1. Periodically takes a recently merged PR or resolved Jira ticket
2. Rolls back the code state to before the change
3. Asks both a standard RAG agent and the SCG Graph Agent to solve the same task
4. Records: tokens used, time, accuracy, test pass rate, cost
5. Updates the live dashboard with rolling 30-day comparisons

**The Dashboard Display:**

```
┌─────────────────────────────────────────────────────────────┐
│              AI READINESS SCORE: YOUR CODEBASE               │
│                                                               │
│  Overall Score: ████████████████████░░░░  82/100              │
│                                                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ TOKENS SAVED     │  │ COST SAVED       │  │ TIME SAVED    │ │
│  │ This Month       │  │ This Month       │  │ This Month    │ │
│  │                  │  │                  │  │               │ │
│  │  14.2M → 890K   │  │   $2,847 →       │  │  47 hrs →     │ │
│  │  (93.7% ↓)      │  │   $178 (93.7% ↓) │  │  3.2 hrs      │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│                                                               │
│  Graph Coverage: 97.3% of entities indexed                    │
│  Dead Code Found: 234 orphaned functions (12,847 lines)       │
│  Merge Conflict Resolution: 94% auto-resolved (vs 48% Git)   │
│                                                               │
│  [View Detailed Report]  [Export for Management]  [Run Now]   │
└─────────────────────────────────────────────────────────────┘
```

### 15.5 The "Cost of Hallucination" Calculator

The CFO-facing metric that makes budget conversations easy:

```
Token Waste = (Total Tokens × Cost/Token) × (1 - Accuracy Rate)

Example for a 50-person engineering team:
  - Monthly AI token usage (file-based): 280M tokens × $0.003/1K = $840/mo
  - Relevant tokens (estimated 5%): 14M tokens × $0.003/1K = $42/mo
  - Monthly waste: $798/mo ($9,576/year)
  - With SCG (92% token efficiency): $73/mo
  - Annual savings: $9,204/year for 50 engineers

  At 500 engineers: $92,040/year in pure token savings
  + Developer time savings from fewer "babysitting" rounds
  + Reduced bug rate from better context accuracy
```

### 15.6 Benchmark Repository Selection

VCS-Bench ships with pre-configured benchmarks on popular open-source repos:

| Repository | Size | Languages | Why It's a Good Test |
|---|---|---|---|
| **cal.com** | ~500K lines | TypeScript | Complex monorepo with deep cross-package deps |
| **Supabase** | ~800K lines | TypeScript, Go, Elixir | Multi-language, microservices, shared types |
| **Next.js** | ~300K lines | TypeScript | Large framework with internal module system |
| **Django** | ~400K lines | Python | Deep class hierarchies, ORM relationships |
| **Kubernetes** | ~3M lines | Go | Massive codebase, complex interfaces |

Teams can also run VCS-Bench on their **private repositories** for the most relevant comparison.

---

## 16. The GitHub-to-Graph Migration Pipeline

### 16.1 The Zero-Risk Migration Principle

Nobody will rewrite their repositories to adopt a new platform. The migration tool must be:
- **One-click**: Provide a GitHub URL + PAT, everything else is automatic
- **Non-destructive**: The GitHub repo remains fully functional throughout
- **Incremental**: Start with HEAD, backfill history in the background
- **Bidirectional**: Changes on GitHub sync to graph; changes on graph sync to GitHub

**The key insight:** Migration is not "leave GitHub." It's "plug SCG into your existing GitHub repo." The graph becomes a **parallel intelligence layer** that enhances the repo without replacing it.

### 16.2 Migration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  GITHUB-TO-GRAPH MIGRATION PIPELINE               │
│                                                                    │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐        │
│  │ GitHub    │    │ Shallow      │    │ Semantic          │        │
│  │ Repo URL  │───►│ Clone (HEAD) │───►│ Compiler          │        │
│  │ + PAT     │    │              │    │ (Tree-sitter +    │        │
│  └──────────┘    └──────────────┘    │  Language Queries) │        │
│                                       └────────┬─────────┘        │
│                                                │                   │
│                           ┌────────────────────┼──────────────┐   │
│                           │                    │              │   │
│                           ▼                    ▼              ▼   │
│                    ┌─────────────┐    ┌──────────────┐ ┌───────┐ │
│                    │ Graph DB     │    │ Vector DB     │ │ Git   │ │
│                    │ (Entities +  │    │ (Embeddings)  │ │ Blobs │ │
│                    │  Edges)      │    │               │ │       │ │
│                    └──────┬──────┘    └──────────────┘ └───────┘ │
│                           │                                       │
│                    ┌──────▼──────────────────────────────────┐    │
│                    │         BIDIRECTIONAL SYNC               │    │
│                    │                                          │    │
│                    │  GitHub → Graph: Webhook on push         │    │
│                    │  Graph → GitHub: Auto git commit          │    │
│                    └──────────────────────────────────────────┘    │
│                                                                    │
│  BACKGROUND:                                                       │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │ History Backfill: Walk git log, parse each commit's diff, │     │
│  │ build entity version history in graph (async, low-priority)│     │
│  └──────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

### 16.3 The Migration Pipeline — Step by Step

#### Step 1: Ingestion

```python
# User provides:
repo_url = "https://github.com/company/monorepo"
access_token = "ghp_..."

# System performs:
# 1. Shallow clone (HEAD only — fast, minimal bandwidth)
# 2. Language detection (identify .ts, .py, .go, .rs, etc.)
# 3. Load appropriate Tree-sitter grammars
```

#### Step 2: Initial Graph Build

```
For each file in HEAD:
  1. Tree-sitter generates CST (Concrete Syntax Tree)
  2. Language-specific extractor walks CST:
     - Extracts: functions, classes, interfaces, types, imports
     - Creates Entity Objects with content hashes
  3. Relationship analyzer maps:
     - Function calls ([:CALLS] edges)
     - Import dependencies ([:IMPORTS] edges)
     - Type relationships ([:IMPLEMENTS], [:EXTENDS] edges)
     - Containment ([:DEFINED_IN] edges to file/module nodes)
  4. Write to Graph DB + generate embeddings for Vector DB

Parallelism: Files are processed concurrently across CPU cores.
Expected speed: ~50,000 lines/second on modern hardware.
A 500K-line repo: ~10 seconds for initial graph build.
```

#### Step 3: Bidirectional Sync Activation

**GitHub → Graph (Write Path):**
1. Register a GitHub webhook for `push` events
2. On push: extract modified files from the diff
3. Re-parse only modified files through Semantic Compiler
4. Compute new entity hashes, compare with existing
5. Apply graph mutations (add/update/remove nodes and edges)
6. Update vector embeddings for changed entities

**Graph → GitHub (Read Path):**
1. When AI agent mutates graph (changes an entity node)
2. Query `[:DEFINED_IN]` edge to find the physical file
3. Reconstruct file: query all entities in that file, order by source position
4. Concatenate entity text bodies → complete file content
5. Create standard Git commit (author: "SCG AI Agent")
6. Push to GitHub via API

#### Step 4: Background History Backfill

```
# Async, low-priority process:
for commit in reverse(git_log):
    diff = git_diff(commit.parent, commit)
    for file in diff.modified_files:
        old_entities = parse(file.old_version)
        new_entities = parse(file.new_version)
        entity_diff = compute_entity_diff(old, new)

        # Build entity version history:
        # (Function:v1) -[:EVOLVED_TO]-> (Function:v2)
        # with metadata: commit_hash, author, timestamp, message
```

This enables **semantic blame**: "Who last modified the authentication flow?" instead of "Who changed line 47?"

### 16.4 Migration Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│                  MIGRATION STATUS: company/monorepo          │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │  HEAD Parse:  ████████████████████████████  100%     │     │
│  │  History:     ████████████░░░░░░░░░░░░░░░  42%      │     │
│  │  Embeddings:  ██████████████████████████░░  92%      │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  Entities Indexed:  24,847 functions | 3,291 classes          │
│  Relationships:     142,903 edges mapped                      │
│  Languages:         TypeScript (68%), Python (22%), Go (10%)  │
│  Sync Status:       ✅ Bidirectional sync active               │
│  Last GitHub Push:  2 minutes ago → Graph updated in 340ms    │
│                                                               │
│  IMMEDIATE INSIGHTS:                                          │
│  ⚠️  234 orphaned functions detected (12,847 lines)           │
│  ⚠️  17 circular dependencies found                           │
│  ⚠️  3 interfaces with 50+ implementations (refactor targets) │
│  ✅  98.7% of cross-file references resolved                  │
│                                                               │
│  [View Full Graph]  [Run VCS-Bench]  [Configure Sync]        │
└─────────────────────────────────────────────────────────────┘
```

### 16.5 Migration Performance Targets

| Repository Size | Initial Parse | Graph Build | Sync Latency (per push) |
|---|---|---|---|
| 10K lines | <1 second | <2 seconds | <100ms |
| 100K lines | ~2 seconds | ~5 seconds | <200ms |
| 500K lines | ~10 seconds | ~25 seconds | <500ms |
| 1M lines | ~20 seconds | ~50 seconds | <1 second |
| 5M+ lines | ~2 minutes | ~5 minutes | <2 seconds |

*Targets assume modern hardware (8+ cores, 32GB+ RAM). Parallelization scales linearly with cores.*

### 16.6 Enterprise Migration Features

For enterprise customers with private/on-prem requirements:

- **Air-gapped migration:** Run the entire pipeline locally, no data leaves the network
- **Selective migration:** Choose specific directories, services, or languages to index first
- **Team-by-team rollout:** Different teams can adopt at different speeds
- **Rollback:** Disable SCG sync at any time — the GitHub repo is always the canonical source until the team explicitly switches
- **Compliance export:** Generate audit reports showing exactly what was indexed, when, and by whom
- **Multi-repo federation:** Connect multiple repos into a single cross-repo Knowledge Graph

### 16.7 The "Land and Expand" Motion

The migration pipeline is the core of the go-to-market strategy:

```
  LAND                           EXPAND
  ─────                          ──────
  1. Developer discovers SCG     4. Team sees VCS-Bench dashboard
  2. Plugs in personal repo      5. Engineering director approves
  3. Sees instant insights          team-wide adoption
     (orphan code, graph viz)    6. Enterprise features unlock
                                 7. Cross-repo Knowledge Graph
                                    becomes organizational memory
                                 8. Full platform migration
```

**The critical insight from Gemini's strategy:** You never ask anyone to "leave GitHub." You say: *"Plug our engine into your existing repo. Your AI agents get 10x faster instantly. Your developers change nothing."* Once they're hooked on the speed and accuracy — and the dashboard proves the ROI — they naturally migrate workflows to SCG.

---

*This document represents the complete architectural blueprint for the Semantic Code Graph platform. It synthesizes market research, technical research, AI industry trends, developer experience insights, and product strategy into a unified, actionable plan.*

*The path is clear: build the semantic graph, ship the MCP wedge, earn developer trust through open source, and capture platform value as multi-agent AI development becomes the default mode of software engineering.*

---

**Document Hash:** `SCG-ARCH-v1.1.0-2026-03-10`
**Next Review:** April 10, 2026
