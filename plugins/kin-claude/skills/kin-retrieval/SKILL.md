---
name: kin-retrieval
description: Read a codebase through Kin's semantic graph instead of grep and whole-file reads. Use when finding where something lives, what a symbol does, who calls it, or which code implements a described behavior, and when a repo has been admitted to Kin (a .kin/ directory exists).
---

# Reading a repository through the Kin graph

Kin parses a repository into entities, relationships, changes, and provenance, and answers
questions from that graph. Where grep matches strings and a file read spends context on
lines you did not need, these tools return the declaration, its neighborhood, and the
graph state that produced the answer.

Reach for the graph first. Fall back to grep only for things the graph does not model:
prose in comments, generated files, and text inside languages Kin does not parse.

## Pick the tool by what you know

You know the name. Use `semantic_search`. It matches parsed declarations by name, kind,
and language, so it returns functions, classes, structs, traits, enums, interfaces, types,
and constants rather than every line that mentions the word. Each hit carries its file
path, line range, signature, and a stable entity id. Despite the name it does not rank by
vector similarity, so treat it as the fast exact-ish lookup.

You only know the behavior. Use `semantic_locate`. It ranks code against a
natural-language query using the vector index, which is the retrieval that powers
`kin locate`. Set `granularity` to `entity` for declarations or `file` for files. It needs
the running daemon and an embedded graph, and it reports its coverage in the response.

You have an entity and need to understand it. Use `get_context_pack`. It bundles the
target with its caller and import neighborhood into one prompt-sized payload, which
replaces a chain of separate reads. `get_entity_source` returns just the implementation
body when the pack is more than you need.

You need callers. Use `find_references` for everything that imports, calls, or references
a symbol. Use `graph_neighborhood` when you want the dependency structure around an
entity, with `direction` of `out` for what it depends on, `in` for what depends on it, and
`both` for the merged view.

You need the path a value travels. Use `trace_data_flow`. It walks the call and data-flow
chain from a focal entity and returns it as an ordered list of steps.

You need history. Use `kin_provenance_query` for who changed an entity, how many times,
what the latest change was, and which approvals are recorded.

You need to know what the repository contains. Use `kin_artifact_list` and
`kin_artifact_read`. These cover every tracked object, including lockfiles, configuration,
binary assets, and files in languages Kin does not parse, addressed by artifact id rather
than by path.

## Read the envelope before you trust the answer

Every response carries a `_kin` envelope. It names the runtime that answered
(`repo-daemon` for the live graph, `offline-in-process` for the fallback store), the graph
generation and reconciliation state, embedding coverage, and any degraded flags. There is
no configuration under which a semantic answer is quietly backfilled from raw file search.

An empty result is not automatically an absence. Empty retrieval responses carry a
`negative` object whose `safe_to_conclude_absent` field says whether the absence can be
trusted. Semantic tools report `semantic_authoritative` only under complete embedding
coverage with no degraded signals, and `coverage_partial` or `coverage_unknown` otherwise.
Structural tools report `structural_authoritative` only when the graph is initialized and
loaded. Any other verdict means ask again once the graph is ready, not that the thing does
not exist.

If `semantic_locate` reports thin coverage, embeddings are still building. Run `kin embed`
in the repository, or use `semantic_search` and the structural tools in the meantime, which
do not depend on the vector index.

## A working order

Start with one `semantic_search` or `semantic_locate` to find the entity. Pull
`get_context_pack` on the best hit. Add `find_references` if you need the call sites, or
`impact_analysis` if you are about to change something shared. That is usually two or three
calls, and it is enough. Stop and answer rather than sweeping the tree.
