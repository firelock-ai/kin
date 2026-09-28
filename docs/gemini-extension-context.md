# Kin: read the repository from the graph

Kin parses a repository into entities, relationships, changes, and provenance, and answers
from that graph. Work on targeted semantic entities. Missing parsed coverage is a graph
gap to report or repair at conversion, never a reason to read or search whole files.

## Pick the tool by what you know

- **You know the symbol name.** `semantic_search` matches parsed declarations by name,
  kind, and language, and returns each hit's path, line range, signature, and entity id.
  It is a metadata matcher, not a vector ranker.
- **You only know the behavior.** `semantic_locate` ranks code against a natural-language
  query using the vector index. It needs the running daemon and an embedded graph, and it
  reports its own coverage.
- **You need to understand an entity.** `get_context_pack` bundles it with its caller and
  import neighborhood. `get_entity_source` returns just the body.
- **You need callers.** `find_references` returns everything that imports, calls, or
  references a symbol. `graph_neighborhood` walks the dependency structure, with
  `direction` of `out`, `in`, or `both`. Follow `next_cursor` with the same query
  and filters to receive all reference pages. A partial page cannot prove absence;
  reconstruct fragmented semantic records before using them. A stale cursor needs a
  fresh query, and completing pages does not clear the answer's semantic caveats.

- **You need the path a value travels.** `trace_data_flow` returns the ordered call and
  data-flow chain from a focal entity.
- **You are changing shared code.** `impact_analysis` walks the relation graph to the
  downstream entities the change can reach.
- **You need history.** `kin_provenance_query` reports an entity's changes, its latest
  change, and recorded approvals.
- **The graph has no matching entity.** Check the coverage in the response. Report missing
  conversion coverage instead of substituting a whole artifact or file-module body.

## Trust the envelope, not the emptiness

Every response carries a `_kin` envelope naming the runtime that answered, the graph
generation, embedding coverage, and any degraded flags. A semantic answer is never quietly
backfilled from raw file search.

An empty result carries a `negative` object whose `safe_to_conclude_absent` field says
whether the absence can be trusted. Semantic tools report `semantic_authoritative` only
under complete embedding coverage with no degraded signals. Structural tools report
`structural_authoritative` only with the graph initialized and loaded. Any other verdict
means ask again when the graph is ready, not that the thing is missing.

## If the tools have no graph

The server answers from `.kin/` in the working directory. If there is none, run `kin init .`
in the repository, or set `KIN_MCP_AUTO_INIT=1` and let the server do it. Then run
`kin embed` to build the vector index `semantic_locate` needs. The structural tools work as
soon as admission finishes. `kin graph status` reports coverage at any time.

## A working order

Find the entity with `semantic_search` or `semantic_locate`. Choose `get_entity_source`
for its body or `get_context_pack` for its bounded neighborhood; do not fetch both when
one already answered the question. Use `find_references` or `impact_analysis` when the
change is shared. Reuse the returned body and source base; do not sweep the repository.

## Make a guarded entity edit

Read `get_entity_source` and retain its complete `source_base` unchanged. For a
localized change in a large entity, use `kin_mutate` (or routed `mutate`) with
`verb: "patch"`, `target: source.id`, and
`payload: {EntitySourcePatch: {source_base: source.source_base, edits:
[{old_text: "unique exact text", new_text: "replacement"}]}}` plus a description.
Omit `body` and `destination`. Every anchor must occur exactly once in the
original entity body; all anchors address that original body and must not
overlap. Use one operation per entity. A stale base or a missing/ambiguous anchor
refuses the transaction without partially applying it.

For a tiny entity or broad rewrite, a guarded full-body `update` can be smaller:
use `payload: {EntitySourceBase: source.source_base}` and the complete new `body`.
Neither form may silently discard the source guard or fall back to raw-file
semantic edits. [Guarded source edits](mcp-source-bases.md) gives the full contract.
