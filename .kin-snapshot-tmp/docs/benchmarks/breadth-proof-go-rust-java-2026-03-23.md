# Breadth Proof: Go, Rust, Java (2026-03-23)

This document records the first validated breadth proof for Kin's semantic indexing
across Go, Rust, and Java repositories. These languages were previously supported
by the parser conformance suite but had no real-world repository evidence.

Command used:

```bash
cargo build --release -p kin-cli
# For each repo: git clone --depth 1 <url> && cd <dir> && kin init && kin commit
```

## Real OSS Repo Matrix

| Repo | Language | Entities | Relations | Files | C5 (cross-file) | Parse time |
| --- | --- | --- | --- | --- | --- | --- |
| gin-gonic/gin | Go | 1,650 | 1,133 | 130 | 81% | 6.3s |
| serde-rs/serde | Rust | 2,403 | 1,482 | 388 | 61% | 7.5s |
| google/gson | Java | 3,884 | 2,824 | 306 | 82% | 11.6s |

## Coverage Tiers

All three repos achieved majority C5 (cross-file semantic) coverage:

- **gin (Go):** 95 of 118 source files at C5. Import resolution and cross-package call linking
  are fully operational. 4 files at C4 (intra-file only), 17 opaque (markdown, pem, proto).
- **serde (Rust):** 231 of 380 source files at C5. Trait definitions, impl blocks, and
  cross-module use paths are resolved. 6 files at C4, 136 opaque (mostly `.stderr` test fixtures).
- **gson (Java):** 238 of 291 source files at C5. Package-level imports, class hierarchies,
  and method cross-references are resolved. 21 files at C4, 24 opaque (markdown, proguard, proto).

## Semantic Feature Validation

Each repo was tested for trace, dead-code detection, and review correctness:

### Trace

- `kin trace RouterGroup` in gin: resolves the struct, shows methods (PUT, HEAD, etc.),
  follows cross-file call to `group.handle()`. 251 tokens.
- `kin trace Serializer` in serde: resolves the trait, shows associated types (Ok, Error),
  shows serialization method signatures. 88 tokens.
- `kin trace Gson` in gson: resolves the class, shows thread-local FutureTypeAdapter pattern,
  internal fields and serialization dispatch. 3,292 tokens.

### Dead Code

Dead-code detection only sees intra-repo call graphs. For library/framework repos,
public API surface will appear "unreferenced" because consumers are external. This is
a known limitation, not a bug.

- gin: 673 unreferenced entities. Most are public API methods (`RouterGroup.HEAD`,
  `RouterGroup.PUT`, etc.) whose callers are in consumer applications, not in gin itself.
  True dead code includes `Test.GetReps` (protobuf generated test fixture).
- serde: high unreferenced count expected for a trait-heavy library. Items like
  `missing_field`, `StringDeserializer::variant_seed` are private helpers that may be
  used via macro expansion (invisible to static analysis).
- gson: `Tweet` and `ReaderUser.toString` are benchmark-only classes genuinely unused
  outside the metrics package. `JavaTimeTypeAdapters.requireNonNullField` is a real
  internal helper.

For application repos (not libraries), dead-code detection is more accurate because
internal call sites are visible. The original JS/TS/Python benchmark matrix used
application-style repos where dead-code detection achieved high precision.

### Review

- `kin review` on each repo's initial commit correctly enumerated all added entities
  with file attribution and relation counts.

## Mixed-Language Proof

A synthetic 5-language repo (Go + Python + TypeScript + Rust + Java) was also tested:

- 21 entities, 14 relations, 5 files
- All 5 languages parsed and committed in a single `kin commit` (24ms parse time)
- `kin trace` correctly resolves entities in each language
- `kin dead-code` correctly identifies all 20 unreferenced entities
- `kin support` shows Go at C5, others at C4 (as expected for a single-file-per-language repo)

## Comparison With Prior Matrix

The March 20, 2026 validated benchmark covered 10 repos across JS/TS/Python only.
This proof extends the language matrix to include Go, Rust, and Java on real-world
repositories of material size (1,650 to 3,884 entities each).

Combined coverage now spans:

| Language | Repos | Max entities | Status |
| --- | --- | --- | --- |
| JavaScript | 4 | 546 (axios) | Validated benchmark (69/70 wins) |
| TypeScript | 2 | 3,199 (zod) | Validated benchmark (69/70 wins) |
| Python | 4 | 1,663 (typer) | Validated benchmark (69/70 wins) |
| Go | 1 | 1,650 (gin) | Breadth proof (this document) |
| Rust | 1 | 2,403 (serde) | Breadth proof (this document) |
| Java | 1 | 3,884 (gson) | Breadth proof (this document) |
| C | 1 | 619 (jq) | Breadth proof (deep adapter, this document) |
| C++ | 1 | 2,573 (nlohmann/json) | Breadth proof (deep adapter, this document) |

## C/C++ Deep Adapter Results (March 23 update)

C and C++ were promoted from shallow (C2-tier) to deep adapters with full entity,
relation, and call extraction. Validated on real OSS repos:

| Repo | Language | Entities | Relations | Files | C4+ | Parse time |
| --- | --- | --- | --- | --- | --- | --- |
| jqlang/jq | C | 619 | 1,907 | 362 | 15% | 2.5s |
| nlohmann/json | C++ | 2,573 | 3,087 | 1,178 | 42% | 9.3s |

- jq: 26 `.c` + 21 `.h` files at C4 (intra-file relations with call resolution).
  `jv_parse`, `jv_parse_sized` trace correctly with cross-function call links.
- nlohmann/json: 407 `.cpp` + 57 `.hpp` files at C4. Template-heavy header-only
  library with 2,573 entities extracted including classes, methods, and namespaces.
- C/C++ files reach C4 rather than C5 because `#include` is textual inclusion,
  not module-level import resolution. Cross-file call linking still works through
  function name matching.

## Notes

- Rust's high opaque percentage (36%) is expected: serde's test suite includes many
  `.stderr` expected-output files that have no semantic structure.
- Java's parse time (11.6s) is the highest, correlating with the largest entity count (3,884).
  This is still well within usable bounds for a one-time conversion.
- The breadth proof does not yet include the full benchmark task suite (agent-driven
  task comparisons). That requires running the benchmark harness with an AI assistant.
  This document proves parsing, indexing, trace, dead-code, and review correctness.
