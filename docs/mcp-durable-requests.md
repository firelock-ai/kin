# Durable `kin_mutate` requests

Pass a nonblank opaque UTF-8 `request_id` of at most 256 bytes to an authenticated,
supporting local daemon. Kin reserves one transaction before beginning the mutation.
After a lost response, retry the complete call with the same `session_id` and key.
Preserve both IDs across MCP restarts. Calls without a key retain their existing
behavior and the public tool's `idempotent_hint` remains false.

Keys are scoped to the actual repository, the local bearer owner namespace and
the canonical registered session UUID. Token rotation preserves that namespace.
This is not tenant isolation between people sharing the daemon's bearer token.
The body session must match `X-Kin-Session`, regardless of coordination mode.
An expired session may retrieve a previously published receipt, but cannot resume
unpublished work without a live authorized registration. Runtime registrations
may be absent after a daemon restart. In that case pending work first refuses;
the authenticated owner can register the original caller-allocated session UUID
through `kin_session_start` (forwarded to authenticated `POST /session`) before
retrying the same bound request. Receipt retrieval
requires no re-registration and never refreshes an expired lease.

Identical means all JSON arguments match after normalizing the session UUID and
defaulting absent `scope` to `repository`. Object-key order is irrelevant. Array
order, source bytes, summary, scope, and request ID are bound.
A changed request under the same key returns `request_id_payload_mismatch` without
publishing. Corrected work uses a new key. A bound transaction cannot be staged,
committed, validated or aborted through the lower-level transaction tools.
The keyed schema accepts only `session_id`, `request_id`, `operations`, `scope`,
and `summary`. Keyed v1 accepts only the default `scope: "repository"`, which
means the workspace already bound to this daemon. It does not select another
workspace or enforce a narrower scope. Unknown top-level fields, unknown operation
fields and fields that
a typed payload would discard are refused before reservation. In particular,
`expected_base` is refused: request deduplication is not caller-read freshness.
The exact writer retains its existing daemon-authority freshness checks.

Keyed success has explicit schema `kin.mutate.receipt.v1`. It carries the original
transaction, change, operation count, modified files, repository operation ID,
generation, transaction hash, and authoritative `roots_before` and `roots_after`.
These roots describe the original publication, even after newer work. The schema
uses those authority roots in place of the legacy response's live-graph
`new_root_hash`; it does not relabel a current graph hash as an original result.
The versioned keyed envelope carries durable publication facts; legacy transient
coordination, collision/conflict, semantic-readiness and staged-versus-carried
presentation fields are outside this envelope. `modified_files` names every path
in the original committed change, including carried pending work.
Only the delivery field `already_applied` changes on replay. Offline operation,
auth-disabled daemons and old daemons refuse this guarantee; the MCP delegate sends
the internal versioned name `kin_mutate_durable_v1` and never falls back to a new
begin/commit sequence for a keyed call.

Request records live in private `.kin/mutate_requests/` files. Successful records
keep their binding and a fixed-shape publication proof permanently, including after
transaction
eviction and session reaping. Corruption requires explicit recovery and preserves
the evidence. Restore verified records; deleting keys is not a safe quota remedy.

The private record schema is `kin.mutate.request.v2`. A domain-separated SHA-256
digest covers every binding field except the digest itself, including the
transaction UUID, pending payload, operation count and completed publication
proof. Every record read validates it before using any binding or receipt. This
detects disk corruption; a local owner able to rewrite the record can also
recompute its checksum. It is not an additional authentication mechanism.
Checksum-free private v1 records from earlier development builds are retained
and explicitly refused as recovery-required. They are not silently upgraded:
their transaction identity cannot be verified from their argument hash. Restore
verified v2 records before retrying affected keys. The public keyed request and
`kin.mutate.receipt.v1` response schemas are unchanged by this private format.

Admission settings are positive integer environment variables read for new keys:

| Setting | Default | Supported range |
| --- | ---: | ---: |
| `KIN_MUTATE_MAX_REQUESTS` | 65,536 | 1–1,000,000 |
| `KIN_MUTATE_MAX_STORAGE_BYTES` | 536,870,912 | 1–17,179,869,184 |

An unfinished request reserves 2 MiB of quota, its maximum persisted record size,
so completion can always replace that reservation. Successful publication proofs
use their actual bytes. The complete response, including a potentially large
changed-file list, is reconstructed from the original authoritative change; it
never makes the permanent request record exceed its storage bound. Canonical
request arguments are limited to 1 MiB and the normal
transaction operation-count limit. A quota refusal names the current allocation
and settings to raise. Raising a limit admits new work without removing old keys;
existing keys remain recoverable even after limits are lowered or configuration
is invalid. No automatic successful-key eviction or reuse occurs.

Persistence flushes the record, atomic rename and containing directory before
execution. Directory flushing follows the daemon's existing platform support.
An uncertain transport or storage outcome is resolved by retrying the same key;
it does not authorize a replacement transaction. Recovery checks repository
authority before trusting a cached success or attempting any new publication.

If authority publishes but daemon finalization fails, the first response is an
explicit `kin.mutate.recovery.v1` tool error with `published: true`, the original
receipt, and a reopen-required remedy. It does not claim live graph or projection
readiness. Existing workspace freshness guards refuse new exact writes while the
daemon is stale. Receipt-only retries never install an old generation; reopening
loads current authority before new work. This receipt schema reports publication,
not readiness of derived views.
