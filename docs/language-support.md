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

Incremental edits (reconcile/watch) resolve adapters by file extension and can
reach further than whole-repo ingest for a few languages, noted below.

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

## Full adapters not yet routed by whole-repo ingest

Swift, PHP, and HCL/Terraform have complete adapters (with relations, and for
Swift/PHP test + doc extraction) that currently apply only on incremental
edits. Whole-repo ingest classifies Swift and PHP as shallow syntax and
HCL/Terraform as opaque. Until ingest routing is unified, treat their
effective support as the lower tier.

## Shallow syntax support

Grammar-backed shallow extraction (declarations + imports + fingerprint, no
call graph) covers C, C++, C#, Ruby, PHP, and Swift. It applies when a file
reaches the shallow tier.

The following extensions are currently **classified as shallow but have no
grammar wired**, so they degrade to opaque in practice: Scala, Lua, R, Zig,
Elixir, Erlang, Haskell, OCaml, Perl. Treat these as unsupported for semantic
extraction today.

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
