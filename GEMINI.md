# Kin: read the repository from the graph

Kin parses a repository into entities, relationships, changes, and provenance, and answers
from that graph. Prefer these tools over grep and whole-file reads. Fall back to raw search
only for what the graph does not model, such as prose in comments and unparsed file types.

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
  `direction` of `out`, `in`, or `both`.
- **You need the path a value travels.** `trace_data_flow` returns the ordered call and
  data-flow chain from a focal entity.
- **You are changing shared code.** `impact_analysis` walks the relation graph to the
  downstream entities the change can reach.
- **You need history.** `kin_provenance_query` reports an entity's changes, its latest
  change, and recorded approvals.
- **You need repository contents.** `kin_artifact_list` and `kin_artifact_read` cover every
  tracked object by artifact id, including lockfiles, configuration, and binary assets.

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

One `semantic_search` or `semantic_locate` to find the entity, one `get_context_pack` on
the best hit, then `find_references` or `impact_analysis` if the change is shared. Two or
three calls is usually enough. Stop and answer rather than sweeping the tree.
