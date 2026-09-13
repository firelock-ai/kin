# Guarded entity source edits

`get_entity_source` returns `source_base` when it can bind the complete body to a
verified source span and one local workspace authority sample. Preserve that
object unchanged with the text you read. An absent or `null` value means no supported writable base
was established; it is not permission to invent one. Historical and hosted-only
reads do not mint a local edit base.

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
claim `staged_operations_retained: true`.

Receipt recovery precedes freshness checks: retrying a transaction that already
published returns its original receipt and never reapplies its old body over a
newer publication. Request deduplication and caller-read freshness remain separate
guarantees.

The existing exact body-edit constraints still apply, including supported syntax,
entity identity preservation and no implicit declaration insertion/removal. This
contract does not implement editor draft storage, make invalid text publishable,
or change unguarded mutation behavior.
