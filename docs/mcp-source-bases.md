# Guarded entity source edits

`get_entity_source` returns `source_base` when it can bind the complete body to a
verified source span and one local workspace authority sample. Preserve that
object unchanged with the text you read. An absent or `null` value means no supported writable base
was established; it is not permission to invent one. Historical and hosted-only
reads do not mint a local edit base. A current read of an entity whose span carries
no recorded source digest answers `source_base_unavailable` beside the body: Kin
cannot guard a change to that entity until it is re-derived. An older repository
may need `kin upgrade`. Reread afterward and proceed only if Kin issues a
`source_base`; if the repository is already current or no base is issued, stop
and report the unresolved source verification gap.

Every whole-entity replacement carries a source base. An `update` with no payload,
or an explicit `Entity` payload with a body, is refused as `source_base_required`
before anything is begun or applied, and one fresh `get_entity_source` read and a
resend with the guarded form is the fix.

Build a guarded operation from the source response, then send it through the
normal transaction tools or `kin_mutate`:

```js
const operation = {
  verb: "update",
  target: source.id,
  payload: { EntitySourceBase: source.source_base },
  body: replacementText, // Complete replacement entity source.
  description: "Explain the intended change"
};
```

For a localized edit, `patch` avoids resending the complete entity. Use the same
source base and literal text copied from the exact source read:

```js
const operation = {
  verb: "patch",
  target: source.id,
  payload: {
    EntitySourcePatch: {
      source_base: source.source_base,
      edits: [{ old_text: "return cached;", new_text: "return cached ?? fallback;" }]
    }
  },
  description: "Use the fallback when the cache is empty"
};
```

Do not send `body` or `destination` with a patch. Every `old_text` must be
nonempty and occur exactly once within the original entity body. Anchors are
literal UTF-8 text, not regexes, line numbers, or file searches. All edits address
the same original body, never earlier replacements; overlapping, missing,
ambiguous, empty and no-op edits are refused. `new_text` may be empty. Stage at
most one operation per entity; put several anchors in its `edits` array. Different
entities in one transaction share the original authority sample and commit
atomically. A stale source base refuses the entire transaction and retains the
staged patch just as it retains a guarded full body.

Choose the smallest correct form: an anchored patch generally helps a localized
edit in a large body; a guarded full-body update can be smaller for a tiny entity
or a broad rewrite. Both retain the same source-base protection. Neither form
permits entity identity changes, unsupported syntax, or implicit declaration
insertion/removal. An older runtime may reject `EntitySourcePatch`; do not drop
the guard or fall back to a raw-file semantic edit.

`EntitySourceBase` takes the complete object, never a string. Its closed schema
is `kin.entity.source_base.v1`, published
as `entitySourceBase` by `@kin/boundary-contracts` and embedded in MCP tool discovery.
Unknown fields and versions are refused. Older runtimes reject the unknown typed
payload; clients must not retry it as an unguarded edit.

V1 binds repository and workspace identity, workspace generation, selected-head
identity, workspace tree, entity and artifact IDs, source blob hash, exact byte
range and body hash. The head and body hashes use Kin's BLAKE3 blob digest. These
are optimistic concurrency expectations, not authorization credentials. V1
conservatively refuses any workspace advance, including unrelated source changes.
It does not silently rebase an old body onto the newest entity.

The exact daemon writer checks this expectation under its coordination and
authority mutation locks, before creating the publication fence. A conflict returns
JSON with schema `kin.entity.source_base_conflict.v1`, code `source_base_conflict`,
`applied: false`, the transaction ID and `staged_operations_retained: true`.
Acknowledged staged work survives restart. Compare the current source with your
retained draft, then submit resolved work in a new transaction. A keyed mutation
also needs a new request ID for changed work. Explicitly abort the old transaction
when it is no longer useful. A storage failure that prevents retention cannot
claim `staged_operations_retained: true`. In every case one fresh `get_entity_source`
read, compared with your draft, and a resend with the base it returns is the fix.

Receipt recovery precedes freshness checks: retrying a transaction that already
published returns its original receipt and never reapplies its old body over a
newer publication. Request deduplication and caller-read freshness remain separate
guarantees.

The existing exact body-edit constraints still apply, including supported syntax,
entity identity preservation and no implicit declaration insertion/removal. This
contract does not implement editor draft storage or make invalid text publishable.

## Repository bases

Work addressed to a source unit rather than to an existing entity, a unit-addressed
`EntityCreate` or a `UnitImports`, carries a `repository_base` instead of a source base.
It is the workspace instant you last observed:

```js
const repositoryBase = {
  schema: "kin.repository.base.v1",
  context: {
    repository_id, workspace_id, workspace_generation,
    workspace_head_hash, workspace_tree_hash
  }
};
```

`context` has exactly the shape of a source base's `context`. `session` returns one when it
opens, `status` returns the current one for HEAD, and every successful commit returns the next
one beside its `created_entities`. Send it unchanged. Like a source base it is an optimistic
concurrency expectation, not an authorization credential. Unit work is planned against the
workspace tree, so the check compares the repository, workspace, head and tree the base names
with the current ones; an empty repository's first creation is still stale-checked. A
workspace generation that advanced over the same head and tree, such as a toolchain run that
published nothing, is not a conflict.

A stale repository base refuses the whole transaction with JSON schema
`kin.repository.base_conflict.v1`, code `repository_base_conflict`, `applied: false`, the
transaction ID, `current_repository_base` (the base authority holds now) and `next_step`.

A transaction may mix entity edits guarded by source bases with unit work guarded by a
repository base, and every base in it must be current. The current repository base does not
refresh an entity's source base, so when the transaction carried any operation with a
`source_base`, the refusal lists them in `source_reads_required`, each as its operation index and
`entity_id`. Re-read each listed entity with `source` (`get_entity_source`), rebuild that
operation from the read with the fresh `source_base` it returns, and resend every operation
with `current_repository_base`. When nothing is listed, the unit-addressed operations need only
`current_repository_base`, and the resend is one step with no extra read. It is safe because unit
work names its unit and declarations by identity: a name taken since is refused again at the
retry, and every declaration already in the unit keeps its exact bytes.

`kin_mutate` without a `request_id` aborts the refused transaction and answers
`staged_operations_retained: false` and `transaction_aborted: true`, since the caller still holds
the operations it sent. A transaction staged with `kin_transaction_stage` keeps its operations
(`staged_operations_retained: true`) until you abort it.
