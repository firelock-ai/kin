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
| Go | ✓ | calls, contains, extends, implements, references, sends-message, spawns | ✓ | ✓ | not wired (gopls adapter exists) |
| Java | ✓ | calls, contains, extends, implements, references | ✓ (junit) | ✓ | not wired (jdtls adapter exists) |
| Rust | ✓ | calls, contains, implements, references | ✓ (cargo) | ✓ | ✓ rust-analyzer |
| C++ | ✓ | calls, contains, extends, imports, references, uses-macro | ✓ | ✓ | not wired (clangd adapter exists) |
| C | ✓ | calls, imports, references, uses-macro | ✗ | ✓ | not wired (clangd adapter exists) |
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
type-resolved relations on top of the parser output (call hierarchy, overrides,
uses-type, references), each tagged with LSP origin and a confidence weight that
classifies it as `type_resolved` rather than as a name match.

Two facts have to hold together before any of those edges can exist: the daemon
has to wire an adapter for the language, and a server binary has to be installed
on the host. The daemon wires **Rust, Python, TypeScript and JavaScript**, which
is what `kin_core::reference_coverage::ENRICHABLE_LANGUAGES` names and what a
test in `kin_daemon` holds it to. Every other language carries no reference,
override or uses-type edge by construction, whatever is installed. kin-lsp does
carry adapters for Go, Java, C and C++, and the table above says so, but those
adapters are not reached from the runtime today.

This matters because cross-file resolution without a language server falls back
to matching bare names, which produces edges that name a plausible destination
rather than a proven one.

Install the servers with:

```
npm install -g pyright                                   # Python
npm install -g typescript-language-server typescript     # TypeScript and JavaScript
rustup component add rust-analyzer                       # Rust
```

`kin setup` and `kin doctor --fix` will offer to run these for you. Neither
installs without consent: interactively they ask once per command with the
download disclosed, and non-interactively they change nothing unless
`--install-language-servers` is passed.

A missing server used to be skipped silently. `kin doctor` now reports it as an
actionable gap naming the language, what the gap costs, and the exact command
that closes it. Import and call edges are still resolved from source with no
language server involved, so the loss is bounded to the edge classes that need a
resolved program.

The daemon discovers servers once at startup. A server installed while a daemon
is already running is picked up without a restart only if that daemon found at
least one server when it started; on a host that had none, the enrichment
channel is never opened, so run `kin daemon stop` and let the next command start
a fresh one.

## Everything else

Any file without an adapter is stored as an opaque artifact: content-addressed
and versioned, visible to file-level operations, invisible to semantic
queries. Markdown, JSON, YAML, and other structured-text formats currently
fall in this tier unless a structured-artifact extractor matches them.
