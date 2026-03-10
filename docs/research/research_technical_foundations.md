# Technical Foundations for an AI-Native Semantic Code Platform

## Research Report: From Files to Semantic Code Graphs

---

## Table of Contents

1. [AST-Based Version Control and Diff Algorithms](#1-ast-based-version-control-and-diff-algorithms)
2. [Code as a Graph Database](#2-code-as-a-graph-database)
3. [Semantic Code Intelligence](#3-semantic-code-intelligence)
4. [Real-Time Code Compilation to Graph](#4-real-time-code-compilation-to-graph)
5. [The "Semantic Compiler" Architecture](#5-the-semantic-compiler-architecture)
6. [Key Technical Challenges and Known Solutions](#6-key-technical-challenges-and-known-solutions)
7. [Architecture Patterns from Existing Tools](#7-architecture-patterns-from-existing-tools)
8. [Recommended Technical Stack](#8-recommended-technical-stack)

---

## 1. AST-Based Version Control and Diff Algorithms

### 1.1 The Problem with Text-Based Diffing

Traditional version control (Git) operates on text lines. This creates fundamental issues for code:
- Whitespace-only changes produce noisy diffs
- Renamed variables touching many lines appear as massive changes
- Moved code blocks show as deletions + insertions rather than moves
- Reformatting is indistinguishable from logic changes
- Merge conflicts arise from textual proximity, not semantic conflicts

### 1.2 GumTree: The Foundation Algorithm

GumTree is the most widely-used AST differencing algorithm, cited in hundreds of research papers. It computes an **edit script** (a sequence of {insert, remove, update, move} operations) that transforms one AST into another.

**Algorithm design (two-phase):**

1. **Top-down phase:** Greedily matches whole isomorphic subtrees between two ASTs using a hash-based comparison. This efficiently handles unchanged portions of code.
2. **Bottom-up phase:** For unmatched nodes, computes Jaccard similarity between subtrees. If similarity exceeds a threshold, nodes are matched. This handles modified code where the overall structure is preserved but details changed.

**Known limitations:**
- Generates inaccurate mappings for 20-29% of file revisions in empirical studies
- Lacks multi-mapping support (one node maps to exactly one node)
- Can match semantically incompatible AST nodes
- No refactoring awareness (e.g., extract-method is not recognized as a single operation)
- No commit-level diff support (operates file-by-file)

**Recent improvements:** RefactoringMiner-aware AST diffing tools like RMiner incorporate refactoring detection to produce more accurate, higher-level edit scripts.

### 1.3 Modern Semantic Diff Tools

**Difftastic** (Rust, MIT license):
- Treats structural diffing as a graph problem, using Dijkstra's algorithm to find the minimal edit
- Parses via tree-sitter, supporting 30+ languages
- Ignores syntactically insignificant whitespace
- Detects reformatting vs. actual changes
- Integrates with Git as a custom diff driver
- Limitation: lossy for merging (discards whitespace tracking needed for merge output)

**Diffsitter:**
- Also tree-sitter based, focused on AST-level diffs
- Lighter weight than Difftastic
- Limited to languages with tree-sitter grammars

**SemanticDiff:**
- VS Code extension and GitHub integration
- Language-aware diffing with visualization
- Commercial product with free tier

**Sem (Semantic Version Control CLI):**
- Entity-level diffs on top of Git (functions, classes, not lines)
- Supports 17 languages via tree-sitter
- Provides `sem diff`, `sem blame`, `sem graph`, and `sem impact` commands
- Represents code changes at the entity level: "function `processPayment` was modified" rather than "lines 42-67 changed"

### 1.4 Structural Merging

Text-based 3-way merge (Git's default) produces spurious conflicts when independent changes happen near each other in the file. Structural merge operates on ASTs instead.

**Approaches:**
- **Top-down structured merge:** Prunes trivially mergeable subtrees first, then handles conflicts at deeper levels
- **Bottom-up structured merge:** Starts from leaf nodes and propagates upward
- **Hybrid (recent research):** Combines both passes with linear time complexity and no backtracking
- **Semistructured merge:** Uses language-specific syntactic separators as a middle ground between full structured merge and text merge

**Semantic conflict detection** remains an open research problem. Even when structural merge succeeds (no textual conflict), the result may have semantic conflicts (e.g., two branches independently add calls to a function that now has different behavior). Tools like SAM use auto-generated unit tests as partial specifications to detect these.

### 1.5 Content-Addressed Code: The Unison Model

Unison represents the most radical departure from file-based version control:

- **Code is identified by hash, not by name.** Each definition is stored under a 512-bit SHA3 hash of its AST (not its text representation).
- **The AST is the primary representation.** Text is just a rendering for human editing. Code is parsed once and stored as AST in a database.
- **Names are metadata, not identity.** Renaming a function is a metadata-only operation; the hash doesn't change because the structure hasn't changed.
- **Append-only codebase database.** The Unison Codebase Manager (UCM) manages branches, merges, and synchronization natively, independent of Git.
- **No build step needed.** Since code is stored pre-parsed, there are no build failures from syntax errors in dependencies.

This model eliminates entire categories of version control problems: rename conflicts disappear, dependency hell is structurally impossible, and distributed code sharing becomes trivial.

---

## 2. Code as a Graph Database

### 2.1 Why Graphs for Code

Code is inherently a graph structure:
- **Call graphs:** Function A calls Function B
- **Type hierarchies:** Class A extends Class B
- **Data flow:** Variable X flows from statement S1 to statement S2
- **Control flow:** After block B1, execution goes to B2 or B3
- **Dependency graphs:** Module A imports Module B
- **Containment:** Function F is defined inside Class C

Flat files obscure these relationships. A graph database makes them first-class, queryable entities.

### 2.2 CodeQL: Code as a Relational Database

GitHub's CodeQL is the most mature production system for treating code as queryable data.

**How it works:**
1. An **extractor** runs during the build process and captures a snapshot of the codebase
2. The snapshot is stored as a **CodeQL database** containing: AST nodes, data flow graphs, control flow graphs, type information, and symbol tables
3. A declarative query language (**QL**) enables pattern matching over these structures
4. Queries express vulnerability patterns, coding standards, or architectural constraints

**Database structure:**
- Full hierarchical representation of the AST
- Data flow graph (tracks how values propagate through the program)
- Control flow graph (tracks execution paths)
- Type hierarchy and symbol resolution

**Query example (SQL injection detection):**
```ql
from DataFlow::PathNode source, DataFlow::PathNode sink
where SqlInjection::flowPath(source, sink)
select sink, source, sink, "SQL injection from $@.", source, "user input"
```

**Supported languages:** C/C++, C#, Go, Java, Kotlin, JavaScript, Python, Ruby, TypeScript, Swift.

**Key insight for our platform:** CodeQL proves that a relational/graph representation of code can scale to large codebases and support sophisticated semantic queries. However, CodeQL databases are **static snapshots** -- they must be rebuilt from scratch when code changes, making them unsuitable for real-time use.

### 2.3 Kythe: Language-Agnostic Code Graph

Google's Kythe is the system behind Google's internal code search and cross-referencing across billions of lines of code.

**Architecture:**
1. **Instrumented build system:** Compilers produce indexing information alongside compilation
2. **Language-agnostic graph structure:** Nodes represent definitions, references, types; edges represent relationships (defines, references, extends, calls)
3. **Queryable service layer:** Tools query the graph for cross-references, call hierarchies, type information

**Key design decisions:**
- Language-agnostic data format means one tool ecosystem serves all languages
- Graph is built incrementally during compilation, not in a separate analysis pass
- Supports Google-scale codebases (billions of lines)

### 2.4 Neo4j-Based Code Graphs

Several projects store code structures in Neo4j graph databases:

**CodeGraph Analyzer:**
- Creates a "digital twin" of a codebase in Neo4j
- Nodes: classes, interfaces, methods, fields, modules
- Edges: inheritance, invocation, declaration, import, containment
- Supports multiple languages
- Enables Cypher queries like: "Find all methods that transitively call `processPayment`"

**javacode-to-neo4j:**
- Extracts program dependency graphs from Java source code
- Stores entities and static dependencies (inheritance, invocation, declaration)
- Enables graph traversal of program business logic

**Codebase Knowledge Graph (Neo4j blog):**
- ETL pipeline: extract codebase models, transform to RDF triples, load into Neo4j
- Represents semantic models of programming language constructs
- Links code structure with project structure and documentation

### 2.5 Program Dependence Graphs (PDGs)

PDGs combine control dependency and data dependency in a single directed graph:
- **Nodes:** Program statements
- **Control dependency edges:** Statement B is control-dependent on statement A if A determines whether B executes
- **Data dependency edges:** Statement B is data-dependent on statement A if A defines a variable that B uses

PDGs are foundational for:
- Program slicing (extracting the subset of code that affects a given variable)
- Parallelization (identifying independent code regions)
- Optimization (dead code elimination, code motion)
- Security analysis (taint tracking)

---

## 3. Semantic Code Intelligence

### 3.1 Tree-Sitter: The Parsing Foundation

Tree-sitter is the de facto standard for real-time code parsing in modern editors (Neovim, Helix, Zed, Atom).

**Key capabilities:**
- **Incremental parsing:** When code changes, only the affected AST subtree is re-parsed. Typically completes in sub-milliseconds.
- **Error recovery:** Produces a valid (partial) AST even for syntactically invalid code -- critical for editor use where code is constantly in an incomplete state.
- **40+ language grammars** available
- **Concrete syntax tree (CST):** Preserves all tokens including whitespace and comments, unlike abstract syntax trees
- **GLR-based parsing** handles ambiguous grammars
- **WebAssembly support:** Parsers can run in browsers

**Architecture:**
- Grammars defined in JavaScript
- Parser generator written in Rust
- Generated parsers are C code (or WASM)
- Bindings for Rust, Node.js, Python, Go, and more

**Limitation for semantic analysis:** Tree-sitter produces a **syntactic** tree. It does not perform name resolution, type checking, or semantic analysis. For those, you need a full language server or compiler frontend.

### 3.2 Language Server Protocol (LSP)

LSP defines a standard protocol between editors and language-specific analysis servers.

**Semantic capabilities:**
- Go-to-definition, find-references
- Hover information (types, documentation)
- Code completion with type-aware suggestions
- Rename refactoring
- Semantic tokens (token classification beyond syntax highlighting)
- Call hierarchy, type hierarchy
- Diagnostics (errors, warnings)

**Architecture pattern:**
1. Editor sends document changes to language server
2. Language server maintains an internal semantic model of the code
3. On each request, the server resolves AST entities at positions and responds with semantic information

**Key insight:** LSP itself does not define a semantic data model -- it defines a protocol for querying one. The actual semantic model lives inside each language server implementation. Building a unified Semantic Code Graph requires going beyond LSP to define a language-agnostic semantic model.

### 3.3 SCIP: Sourcegraph's Code Intelligence Protocol

SCIP (SCIP Code Intelligence Protocol) is Sourcegraph's answer to the question of how to index and store semantic code information at scale.

**Advantages over LSIF (its predecessor):**
- 4x smaller when gzip-compressed
- 10x faster to generate (demonstrated with scip-typescript vs lsif-node)
- Protobuf-based schema provides static types and rich editor completion
- Inspired by SemanticDB from the Scala ecosystem

**What SCIP captures:**
- Symbol definitions and references
- Cross-file and cross-repository navigation
- Type information
- Documentation strings

**Existing indexers:** TypeScript/JavaScript, Java/Scala/Kotlin, with more in development.

### 3.4 Code Embeddings and Vector Search

**code2vec** (Technion, 2019):
- Decomposes code into paths through the AST
- Learns fixed-length vector representations of code snippets
- Demonstrated 75% improvement over prior methods for method name prediction
- Semantically similar code (different implementations of the same algorithm) produces nearby vectors

**CodeBERT / GraphCodeBERT** (Microsoft Research):
- Pre-trained models that understand both code and natural language
- GraphCodeBERT additionally incorporates data flow information
- Used for code search, code summarization, code translation

**Practical code search architectures (Sourcegraph Cody):**
- Multi-retrieval approach: keyword search + vector embeddings + dependency graph traversal
- Ranking model selects most relevant context from multiple retrieval methods
- RAG architecture feeds retrieved code into LLM for generation

**Zoekt** (Sourcegraph):
- Trigram-based code search engine for fast literal searches
- Sub-second queries across billions of lines
- Complements semantic search with exact matching

---

## 4. Real-Time Code Compilation to Graph

### 4.1 The Salsa Framework: Query-Based Incremental Computation

Salsa (used by rust-analyzer and the Rust compiler) is the most sophisticated framework for incremental semantic analysis.

**Core concepts:**
- **Queries:** Named computations that take inputs and produce outputs (e.g., "parse file X", "resolve type of expression E")
- **Dependency graph:** As queries execute, Salsa records which other queries they invoked, building a DAG
- **Memoization:** Query results are cached. On subsequent invocations, Salsa checks if any inputs changed.
- **Early cutoff:** Even if an input changed, if the query's output is unchanged, dependent queries are not re-executed. Example: adding whitespace changes the source text (input) but not the AST (output of parsing), so type-checking is skipped.

**Performance characteristics:**
- Typical IDE interactions (keystroke, completion request) trigger recomputation of only the directly affected queries
- Most of the semantic model remains cached
- Sub-100ms response times for complex queries on large codebases

### 4.2 Rust-Analyzer Architecture (Reference Implementation)

Rust-analyzer is the best-documented example of a real-time semantic analysis engine.

**Layer stack:**
1. **Syntax layer** (`syntax` crate): Lossless syntax tree (CST), value type, no global context needed. Built with a custom incremental parser.
2. **HIR (High-level Intermediate Representation):** A fully resolved, typed semantic model. Wraps an ECS-style internal API in an OO-flavored facade. Handles the delicate mapping from syntax to semantics.
3. **IDE layer:** Builds on HIR to provide IDE features (completion, go-to-definition, diagnostics, refactoring). Pure functions: `(Analysis, Position) -> Result`.

**Key architectural decisions:**
- **Cancellation:** Long-running analysis can be cancelled when new edits arrive. The system is designed so that cancellation is safe at any point.
- **Lazy computation:** Semantic information is computed on-demand, not eagerly. Only the parts of the codebase touched by the current query are analyzed.
- **Snapshot semantics:** Each query operates on a consistent snapshot of the codebase, even if edits are happening concurrently.

### 4.3 Three Architectures for a Responsive IDE

A blog post from the rust-analyzer team identifies three architectural approaches:

1. **Batch compiler:** Analyze everything from scratch on each change. Simple but slow. Only viable for small projects.
2. **Incremental compiler (Salsa-style):** Cache intermediate results and invalidate only what changed. Complex to implement but provides excellent performance.
3. **Reactive/streaming:** Model the analysis as a dataflow graph where changes propagate automatically. Most elegant but hardest to debug.

Rust-analyzer uses approach #2 (Salsa-based incremental computation), which represents the current state-of-the-art for production IDE backends.

---

## 5. The "Semantic Compiler" Architecture

Based on the research above, here is a proposed architecture for a **Semantic Compiler** that converts source code into a Semantic Code Graph in real-time.

### 5.1 Pipeline Overview

```
Source Code (text)
    |
    v
[Tree-sitter Parser] -- incremental, sub-ms updates
    |
    v
Concrete Syntax Tree (CST)
    |
    v
[AST Transformer] -- normalize to language-agnostic AST nodes
    |
    v
Abstract Syntax Tree (AST)
    |
    v
[Semantic Analyzer] -- Salsa-based incremental queries
    |  - Name resolution
    |  - Type inference
    |  - Data flow analysis
    |  - Control flow analysis
    v
Semantic Model (HIR)
    |
    v
[Graph Emitter] -- converts semantic model to graph operations
    |
    v
Semantic Code Graph (stored in graph database)
    |
    v
[Content Addresser] -- Unison-style hashing of graph substructures
    |
    v
Versioned, Content-Addressed Semantic Graph
```

### 5.2 Graph Schema Design

**Node types:**
- `Module` -- a compilation unit / file
- `Function` -- function/method definition
- `Class` / `Struct` / `Interface` -- type definitions
- `Variable` -- local variables, parameters, fields
- `Expression` -- individual expressions with type information
- `Statement` -- control flow statements
- `Type` -- resolved type information
- `Import` -- dependency declarations

**Edge types:**
- `CONTAINS` -- structural containment (Module contains Function)
- `CALLS` -- function invocation
- `REFERENCES` -- variable/symbol usage
- `EXTENDS` / `IMPLEMENTS` -- type hierarchy
- `DEPENDS_ON` -- module-level dependency
- `DATA_FLOWS_TO` -- data dependency
- `CONTROLS` -- control dependency
- `HAS_TYPE` -- type annotation/inference
- `OVERRIDES` -- method overriding

**Node properties:**
- `hash` -- content-addressed hash of the subtree (Unison-style)
- `source_range` -- mapping back to source text positions
- `metadata` -- documentation, annotations, visibility

### 5.3 Incremental Graph Updates

When code changes:
1. Tree-sitter re-parses only the affected subtree (sub-ms)
2. Salsa invalidates and recomputes only affected semantic queries
3. The Graph Emitter computes a **graph diff** (added/removed/modified nodes and edges)
4. The graph database applies the diff transactionally
5. Content-addressed hashes are recomputed bottom-up only for affected subtrees

This ensures that a keystroke in one function does not trigger re-analysis of the entire codebase.

### 5.4 Content Addressing for Version Control

Following Unison's model:
- Each graph node gets a hash based on its semantic content (not its text representation or position)
- Renaming a variable changes only the name metadata, not the hash
- Adding whitespace/comments changes nothing in the graph
- Two implementations of the same algorithm with different variable names can be detected as equivalent

**Version control operations become graph operations:**
- `diff` = compute the set of added/removed/modified graph nodes between two versions
- `merge` = union of graph changes with conflict detection on overlapping node modifications
- `blame` = trace each graph node back to the commit that introduced it
- `bisect` = binary search over graph snapshots

---

## 6. Key Technical Challenges and Known Solutions

### 6.1 Language Heterogeneity

**Challenge:** Each programming language has different AST structures, type systems, and semantic rules.

**Known solutions:**
- Tree-sitter provides unified parsing across 40+ languages
- SCIP/Kythe define language-agnostic indexing formats
- A common semantic graph schema (like the one in 5.2) can accommodate language-specific features via node/edge subtypes
- Start with a subset of languages (TypeScript, Python, Go) and expand

### 6.2 Scaling Graph Storage

**Challenge:** Large codebases (millions of functions, billions of relationships) produce enormous graphs.

**Known solutions:**
- Kythe handles Google's monorepo (billions of lines) using sharded graph storage
- CodeQL uses specialized columnar storage optimized for recursive queries
- Neo4j supports horizontal scaling with Neo4j Fabric
- Content-addressed storage enables deduplication (identical library code stored once)
- Incremental updates (only changed subgraphs are rewritten)

### 6.3 Real-Time Performance

**Challenge:** Graph updates must happen within the IDE interaction budget (~100ms for completion, ~16ms for syntax highlighting).

**Known solutions:**
- Tree-sitter achieves sub-ms incremental parsing
- Salsa achieves sub-100ms semantic recomputation via memoization and early cutoff
- Graph writes can be batched and applied asynchronously
- Two-tier architecture: fast local graph (in-memory) + eventual consistency with persistent graph store

### 6.4 Semantic Accuracy

**Challenge:** Semantic analysis requires type inference, name resolution, and flow analysis, which are language-specific and computationally expensive.

**Known solutions:**
- Leverage existing language servers (LSP) for semantic information rather than rebuilding compilers
- Use SCIP indexers where available for batch semantic extraction
- Accept approximate semantics for real-time use (full accuracy on save/commit)
- Hybrid approach: tree-sitter for syntax (fast) + language server for semantics (slower, cached)

### 6.5 Merge Conflicts in Graphs

**Challenge:** Graph-based merging is more complex than text-based merging.

**Known solutions:**
- Semistructured merge as a pragmatic middle ground
- Entity-level merging (Sem tool's approach) where conflicts are per-function, not per-line
- Semantic conflict detection via test generation (SAM approach)
- Content-addressed nodes simplify "did this change?" checks

### 6.6 Backward Compatibility with Git/Files

**Challenge:** The ecosystem runs on files and Git. A graph-based system must interoperate.

**Known solutions:**
- Unison maintains a text rendering of its AST database for human editing
- Sem operates as a layer on top of Git, not a replacement
- Bidirectional sync: graph <-> files, with the graph as source of truth
- Git integration as an export/import mechanism, not the primary store

---

## 7. Architecture Patterns from Existing Tools

### 7.1 Pattern: Layered Analysis Pipeline

**Used by:** rust-analyzer, IntelliJ, Eclipse JDT

```
Text -> CST -> AST -> HIR -> MIR -> Analysis Results
```

Each layer provides progressively more semantic information. Incremental computation is applied at every layer boundary. This is the proven architecture for IDE-quality semantic analysis.

### 7.2 Pattern: Build-Time Indexing

**Used by:** CodeQL, Kythe, SCIP

The compiler/build system produces a semantic index as a side-effect of compilation. This index is stored separately and queried by tools. Advantages: leverages the compiler's own semantic analysis (guaranteed accuracy). Disadvantages: not real-time (requires a build step).

### 7.3 Pattern: Content-Addressed Storage

**Used by:** Unison, Git (for objects), IPFS

Every piece of data is identified by a hash of its content. This enables deduplication, integrity verification, and elegant version control. Unison applies this specifically to AST nodes, proving it works for code.

### 7.4 Pattern: Multi-Retrieval Code Intelligence

**Used by:** Sourcegraph Cody

Combine multiple retrieval methods for code understanding:
1. Trigram search (Zoekt) for exact text matches
2. Vector embeddings for semantic similarity
3. Graph traversal for structural relationships
4. Dependency analysis for module-level context

No single retrieval method suffices; the combination provides comprehensive code intelligence.

### 7.5 Pattern: Query-Based Incremental Computation

**Used by:** Salsa, rust-analyzer, Adapton

Model all analysis as pure functions (queries) with automatic dependency tracking and memoization. This is the key to making real-time semantic analysis feasible. The framework handles invalidation, caching, and re-execution transparently.

---

## 8. Recommended Technical Stack

Based on this research, the recommended components for building an AI-native Semantic Code Platform:

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Parsing** | Tree-sitter | 40+ languages, incremental, sub-ms, error-tolerant |
| **Incremental computation** | Salsa (Rust) or custom query engine | Proven in rust-analyzer, handles complex dependency graphs |
| **Semantic indexing** | SCIP protocol | Language-agnostic, compact, Protobuf-typed, active development |
| **Graph storage** | Neo4j or custom graph store | Mature, supports Cypher queries, horizontal scaling |
| **Content addressing** | SHA3-512 hashing (Unison model) | Enables structural version control, deduplication |
| **Diff algorithm** | GumTree (enhanced) + entity-level diffing | Best-studied algorithm, with improvements from recent research |
| **Code embeddings** | CodeBERT/GraphCodeBERT | Supports both code search and semantic similarity |
| **Search** | Zoekt (trigram) + vector store | Fast exact search + semantic search |
| **Version control** | Custom graph-native VCS on top of Git | Git for ecosystem compatibility, graph ops for semantic merging |
| **API layer** | LSP-compatible protocol | IDE integration without requiring new editor plugins |

### Critical Path for MVP

1. **Tree-sitter parsing pipeline** -- get reliable, incremental CSTs for target languages
2. **Graph schema and storage** -- define the semantic graph schema and stand up a graph DB
3. **Incremental graph emitter** -- convert tree-sitter CSTs to graph nodes/edges with change detection
4. **Content-addressed versioning** -- hash graph substructures for semantic diffing
5. **LSP bridge** -- use existing language servers to enrich the graph with type/reference information
6. **Query API** -- enable semantic queries over the graph (find callers, trace data flow, impact analysis)

---

## Sources and References

### AST Diffing
- [GumTree AST Diff (SpoonLabs)](https://github.com/SpoonLabs/gumtree-spoon-ast-diff)
- [Pointers on AST Differencing (Monperrus)](https://www.monperrus.net/martin/tree-differencing)
- [RefDiff: Refactoring-aware AST Differencing](https://arxiv.org/html/2403.05939)
- [Difftastic - Structural diff tool](https://github.com/Wilfred/difftastic)
- [Diffsitter - Tree-sitter based AST diff](https://github.com/afnanenayet/diffsitter)
- [Sem - Semantic Version Control CLI](https://github.com/Ataraxy-Labs/sem)

### Graph Databases for Code
- [CodeQL (GitHub)](https://codeql.github.com/)
- [Kythe (Google)](https://www.kythe.io/)
- [Codebase Knowledge Graph (Neo4j)](https://neo4j.com/blog/developer/codebase-knowledge-graph/)
- [CodeGraph Analyzer](https://github.com/ChrisRoyse/CodeGraph)

### Semantic Code Intelligence
- [Tree-sitter](https://tree-sitter.github.io/)
- [SCIP Code Intelligence Protocol (Sourcegraph)](https://github.com/sourcegraph/scip)
- [code2vec (Technion)](https://arxiv.org/abs/1803.09473)
- [Sourcegraph Code Search](https://sourcegraph.com/code-search)
- [Zoekt Trigram Search](https://github.com/sourcegraph/zoekt)

### Incremental Compilation and Analysis
- [Salsa Framework](https://github.com/salsa-rs/salsa)
- [Rust-analyzer Architecture](https://rust-analyzer.github.io/book/contributing/architecture.html)
- [Three Architectures for a Responsive IDE](https://rust-analyzer.github.io//blog/2020/07/20/three-architectures-for-responsive-ide.html)
- [Incremental Compilation in Rust](https://rustc-dev-guide.rust-lang.org/queries/incremental-compilation.html)
- [Durable Incrementality (rust-analyzer blog)](https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html)

### Content-Addressed Code
- [Unison Programming Language](https://www.unison-lang.org/)
- [Unison: The Big Idea](https://www.unison-lang.org/docs/the-big-idea/)
- [Trying Unison: Code as Hashes (SoftwareMill)](https://softwaremill.com/trying-out-unison-part-1-code-as-hashes/)

### Structural Merging
- [Semistructured Merge with Syntactic Separators](https://arxiv.org/html/2407.18888v1)
- [Three-Way Structured Merge Methodology](https://www.sciencedirect.com/science/article/abs/pii/S138376212300190X)
- [Semantic Conflict Detection (SAM)](https://www.sciencedirect.com/science/article/pii/S0164121224001158)

### Microsoft Code Intelligence
- [Visual Studio IntelliCode](https://visualstudio.microsoft.com/services/intellicode/)
- [Microsoft Code Intelligence Research](https://www.microsoft.com/en-us/research/project/code-intelligence/)
- [LSP for AI Coding Tools](https://amirteymoori.com/lsp-language-server-protocol-ai-coding-tools/)
