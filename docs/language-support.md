# Language Support

Kin preserves every admitted file in exact repository authority regardless of
language. A separate graph-native enrichment stage classifies supported content
and extracts as much semantic structure as the language's adapter provides.
This page states exactly what each language gets from that enrichment. No tier
is implied beyond what the extraction actually emits.

## How classification works

Graph-native semantic enrichment routes each admitted file into one of four
tiers:

| Tier | What the graph stores |
| --- | --- |
| **Full semantic** | Entities (functions, classes, methods, types…), relations (calls, containment, inheritance…), test detection, doc/comment summaries |
| **Shallow syntax** | Coarse top-level declarations + imports + a syntax fingerprint, with no call graph, no nested entities, no tests, and no docs |
| **Structured artifact** | Dedicated extractors for manifests and configs (Cargo.toml, package.json, go.mod, pom.xml, Dockerfile, CI configs, SQL migrations…) |
| **Opaque artifact** | Content hash + MIME hint. Never dropped, never parsed |

Whole-repo ingest and incremental edits (reconcile/watch) route the same way.
Both resolve every extension the adapter registry claims, so a file lands in
the same tier whichever path admitted it, and a test asserts that the two
cannot drift apart.

## Full semantic support

| Language | Entities | Relations | Tests | Docs | LSP enrichment |
| --- | --- | --- | --- | --- | --- |
| TypeScript | ✓ | calls, contains, extends, implements, references | ✓ (jest) | ✓ | ✓ typescript-language-server |
| JavaScript | ✓ | calls, contains, extends, references | ✓ | ✓ | ✓ typescript-language-server |
| Python | ✓ | calls, contains, extends, references | ✓ (pytest) | ✓ | ✓ pyright / pylsp |
| Go | ✓ | calls, contains, extends, implements, references, sends-message, spawns | ✓ | ✓ | ✓ gopls |
| Java | ✓ | calls, contains, extends, implements, references | ✓ (junit) | ✓ | ✓ jdtls |
| Rust | ✓ | calls, contains, implements, references | ✓ (cargo) | ✓ | ✓ rust-analyzer |
| C++ | ✓ | calls, contains, extends, imports, references, uses-macro | ✓ | ✓ | ✓ clangd |
| C | ✓ | calls, imports, references, uses-macro | ✗ | ✓ | ✓ clangd |
| Kotlin | ✓ | calls, contains, extends, implements, references | ✓ | ✓ | ✗ |
| C# | ✓ | calls, contains, extends, references | ✗ | ✓ | ✗ |
| Ruby | ✓ | calls, contains, extends, references | ✗ | ✓ | ✗ |
| Swift | ✓ | calls, contains, implements, references | ✓ (xctest) | ✓ | ✗ |
| PHP | ✓ | calls, contains, extends, implements, references | ✓ (phpunit) | ✓ | ✗ |
| HCL / Terraform | ✓ | imports, references | ✗ | ✓ | ✗ |

## Shallow syntax support

The shallow tier exists in the pipeline but currently routes no extensions.
Every language with a shallow grammar also has a full entity-extraction
adapter, so those files take the full semantic path instead.

Extensions with neither a full adapter nor a wired grammar are stored as
opaque artifacts: Scala, Lua, R, Zig, Elixir, Erlang, Haskell, OCaml, Perl.
Treat these as unsupported for semantic extraction today.

## LSP enrichment

When the corresponding language server binary is installed, Kin adds
type-resolved relations on top of the parser output (call hierarchy,
overrides, uses-type, references, each tagged with LSP origin and a
confidence weight): Rust, Python, TypeScript, JavaScript, Go, Java, C, C++.
Enrichment is skipped silently when the server binary is absent.

## Everything else

Any file without an adapter is stored as an opaque artifact: content-addressed
and versioned, visible to file-level operations, invisible to semantic
queries. Markdown, JSON, YAML, and other structured-text formats currently
fall in this tier unless a structured-artifact extractor matches them.
