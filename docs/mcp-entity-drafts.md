# Durable entity drafts

An authenticated local daemon owns drafts independently of MCP session leases.
Saving preserves exact UTF-8, including empty text, invalid syntax, CRLF and NUL.
Draft storage is editing state; it never substitutes for graph source authority.

The full MCP tool profile serves six explicit tools. An editor can call the same
`/mcp/tools/call` route with its local bearer. Check `kin_draft_capabilities` before
promising Save: it probes actual directory synchronization without creating a
store. This initial implementation supports durable writes on Unix. Other
platforms return `draft_durability_unsupported` before create/save/Apply writes;
read/list remain available. Windows durable writes are a remaining product gate.

## MCP metadata and draft payloads

Standard MCP responses attach the universal version-2 metadata object under the
reserved top-level `_kin` key. `kin_draft_read` therefore returns draft fields
plus `_kin`; create/save/Apply return an outer response whose nested `draft`
contains only domain fields. Direct daemon responses may omit `_kin`.

Use `validateMcpContract('entityDraft', response)` for a read and
`validateMcpContract('entityDraftCapabilities', response)` for capabilities from
`@kin/boundary-contracts`. On `ok: true`, the result exposes `payload` and
`envelope` separately. Validate nested draft records with the ordinary
`validateContract('entityDraft', response.draft)`. The ordinary validator remains
closed and intentionally refuses `_kin` on a domain record.

The MCP validator separates only the reserved top-level key. Every other field
reaches the closed domain schema, so unknown ownership/freshness constraints and
nested `_kin` keys still refuse. Metadata, when present, requires
`envelope_version: 2`, a recognized runtime, and a `degraded` object. Known fields
are type-checked. Additional metadata stays intact for forward-compatible
disclosure; unsupported envelope versions/runtimes refuse. Shape validation is
not certification of authority, and unknown metadata never grants freshness,
write permission or successful Apply.

Compare saved draft identities, revisions, bodies and receipts using the domain
payload. Runtime graph observations in `_kin` can legitimately change after a
restart and are not immutable draft content. Keep the original metadata for
diagnostics. An absent envelope is reported as `null`; the domain validator does
not fill in missing observations.

## Save and reopen

1. Read complete current-head `get_entity_source` and retain `body` plus the
   exact versioned `source_base`. Historical and bounded reads do not provide a
   current editing expectation.
2. Call `kin_draft_create` with client-generated stable `draft_id` UUID,
   `original_source_base`, `original_body`, and arbitrary draft `body`. Retry an
   uncertain creation with the identical UUID and arguments.
3. Call `kin_draft_save` with `draft_id`, `expected_revision`, and exact `body`.
   Every successful change appends an immutable revision. The original source
   body and source-base identity stay separate and unchanged.
4. `kin_draft_read` accepts `draft_id` and optional explicit `revision`.
   `kin_draft_list` accepts optional `entity_id`, `after` UUID cursor and `limit`
   (default 50, maximum 200). Both work after session expiry or target deletion.

A saved response has schema `kin.entity.draft.saved.v1`, `draft` and
`already_saved`. Retry identity is the complete create/save request. An exact
retry returns its original revision even after later saves; it does not move the
latest draft backward. A changed request against an occupied revision refuses
with `draft_revision_conflict`. Keep caller text and read the latest revision.

`revision` advances for text and Apply metadata. `content_revision` names the
revision that most recently saved body bytes. It does not advance merely because
an Apply attempt or receipt was saved. CAS uses `revision`.

## Explicit Apply

`kin_draft_apply` accepts `draft_id`, `expected_revision`, and a registered
`session_id` with write/commit capability. For a new attempt the daemon durably
appends the requested metadata revision, exact attempted content revision, session UUID, generated permanent
request ID and complete closed mutation arguments **before dispatch**. The
operation carries the original `EntitySourceBase` into the exact writer, which
checks it under its publication lock. Apply uses `kin_mutate_durable_v1`; no
alternate writer or freshness bypass exists.

An identical original Apply invocation is resolved from its immutable requested
revision and session before any newer pending attempt. Earlier success replay
keeps a newer pending attempt intact. Otherwise, if an attempt is pending, Apply
only resumes that original request. It does not
substitute the submitted session, latest body, or a new source base. Save remains
available and carries the immutable pending attempt into the new revision.
Unpublished retries require fresh registration of the original session UUID;
receipt recovery for already published work does not require a live lease.

The daemon records the authoritative original receipt durably before returning
`kin.entity.draft.applied.v1`. It includes `applied_draft_revision`,
`requested_revision`, `current_text_applied`, `receipt_saved`, original `receipt`, and latest `draft`.
An older attempt recovered after newer Save has `current_text_applied: false`.
A recovered original receipt never implies the current repository still contains
those bytes, nor does it reapply them over intervening commits.

Apply errors use `kin.entity.draft.apply_pending.v1`. Keep the pending request.
A mutation error can include publication recovery evidence, so generic errors
make no blanket claim that nothing was published. If publication succeeded but
draft receipt persistence failed, `draft_apply_receipt_not_saved` explicitly
reports `repository_source_applied: true`, `receipt_saved: false` and the receipt.
Retry the exact pending attempt. The draft is never deleted or reset.

A stale source-base refusal preserves text and history. Resolve it by reading the
current source and creating a new draft with the explicitly chosen merged text.
There is no silent rebase. Invalid syntax also remains saved while Apply refuses.

## Storage boundaries

Draft identity is repository + workspace + entity + `local-bearer-v1`; rotating
bearer bytes and transient editing sessions do not change ownership. Payloads
cannot select another owner. Startup-pinned repository namespace validation
rejects a replaced repository. Full-record checksums bind schema, identity,
revision, original base/body, draft body, pending arguments and receipts. They
are corruption checks, not signatures against a local filesystem owner.

Each revision is an exclusively created, unique temporary file, fsynced and
published with a non-replacing hard link, followed by actual directory fsync.
Parent-directory synchronization covers first creation and retries after a
failed creation. Acknowledgement never uses a no-op directory sync. Prior
revisions are never overwritten or evicted.

Unknown recovery evidence is preserved. Writes refuse until it is inspected;
read/list can recover acknowledged records when the unknown evidence is an
ordinary file, and list exposes its names. Only an exact, valid duplicate of an
already published revision is cleaned automatically. Symlinks and nonregular
entries refuse. Corrupt latest records do not silently fall back; explicitly
read a known earlier revision to recover its text.

Default storage ceilings are 8 MiB per original/current body, 512 MiB total,
4,096 draft IDs and 65,536 revisions. These are storage bounds, not transport
promises: the daemon JSON request ceiling is 4 MiB and the keyed mutation's
canonical arguments ceiling is 1 MiB. A large draft may be saved but refuse
Apply. Quota, write and sync failures retain previously acknowledged bytes and
never return a saved acknowledgement. The capabilities payload reports limits.


Admission settings are configurable positive integers. `KIN_DRAFT_MAX_BODY_BYTES`
has a 16 MiB maximum; `KIN_DRAFT_MAX_STORAGE_BYTES` a 16 GiB maximum;
`KIN_DRAFT_MAX_DRAFTS` a 65,536 maximum; `KIN_DRAFT_MAX_REVISIONS` a 1,000,000
maximum. Restart the daemon with a raised bounded setting and retry the same
request to recover from quota refusal. Invalid settings disable new Save/Apply
and make capabilities report `draft_admission_config_invalid`; read/list still
recover existing drafts. Raising limits does not enlarge transport ceilings.
