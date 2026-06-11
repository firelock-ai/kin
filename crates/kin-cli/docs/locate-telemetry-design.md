# Opt-in local-first locate telemetry — design (5.11/R12)

Status: **design, awaiting consent-model sign-off** before collection lands. Default
**OFF**. Local-first: nothing leaves the machine. This is the foundation of the
telemetry "flywheel" (local spool → opt-in eval/dogfood → future opt-in upload);
only the local spool + schema are in scope here.

## Principles (non-negotiable)

1. **Off by default.** A default `kin locate` invocation writes zero telemetry and is
   byte-identical to today. (Protects the freeze byte-identity verdict.)
2. **Local-first.** Events spool to an append-only file under `.kin/`. No network, no
   daemon, no background upload. Any future upload is a separate, explicitly-opt-in step.
3. **Explicit, informed consent.** Telemetry turns on only via a deliberate opt-in, and
   the first time it engages the user sees a one-time disclosure: what is collected,
   where it is stored, and how to disable/purge.
4. **Inspectable + purgeable.** Plain JSONL the user can read; a documented schema; a
   simple way to delete it.
5. **No fake product state** (per repo rule): real events through the real path; nothing
   synthesized to look complete.

## Consent / opt-in UX (designed first)

Resolution order (first decisive wins), default OFF:

1. `KIN_LOCATE_TELEMETRY` env: `1`/`true` → on, `0`/`false` → force off (CI/ephemeral,
   matches the codebase's env opt-in convention, e.g. `KIN_CONTEXTBENCH_TEST_HINTS`).
2. `.kin/config.toml` `[telemetry] locate_enabled = true/false` (durable, intentional
   per-repo opt-in — the primary consent record).
3. Otherwise: **OFF**.

On the first write of a session (consent on, spool file freshly opened), emit a one-time
disclosure to **stderr** (never stdout — keeps result piping clean):

```
ℹ kin locate telemetry is ON (you opted in). Recording queries + results + funnel
  traces to .kin/telemetry/ — local only, never uploaded. Disable: set
  [telemetry] locate_enabled = false (or KIN_LOCATE_TELEMETRY=0). Purge: delete .kin/telemetry/.
```

## Schema (documented, versioned)

One JSON object per line (JSONL), append-only. `schema_version` gates evolution.

```jsonc
{
  "schema_version": 1,
  "kind": "locate_query",         // event type
  "ts_unix_ms": 1733850000000,    // caller-supplied timestamp (no wall-clock in core)
  "query": "where is the json parser",
  "max_files": 6,
  "scoring_track": "BroadBlend",  // when known
  "results": [                     // ranked, as returned
    {"path": "src/x.rs", "rank": 0, "score": 1.23, "signals": ["entity_resolve","source_text"],
     "top_entity": "entity:abc"}   // when entity identity is available
  ],
  "funnel": [                      // why candidates were dropped (reuses pruned_files)
    {"path": "src/y.rs", "score": 0.04, "reason": "below_support_floor"}
  ]
}
```

A second event type carries outcome feedback (phase 2 — see Open decision 2):

```jsonc
{ "schema_version": 1, "kind": "locate_outcome", "ts_unix_ms": ...,
  "query_ref": "<hash or id of the locate_query>", "path": "src/x.rs",
  "outcome": "accepted" | "rejected" }
```

## Spool

- Path: `.kin/telemetry/locate-YYYY-MM-DD.jsonl` (date from the caller-supplied ts).
- Append-only; best-effort: a spool I/O error is logged at `debug` and **never** fails or
  alters the locate result.
- `.kin/telemetry/` added to the repo `.gitignore` guidance (telemetry is local, not
  committed).

## Hook points (kin-cli only)

- New module `crates/kin-cli/src/telemetry.rs` (or `commands/locate_telemetry.rs`):
  consent check, schema types, JSONL spool writer — all unit-testable with a temp dir.
- A single call at locate result assembly (after the final ranking, where
  `LocateResult` + pruned/funnel data exist) that, **only when consent is on**, builds and
  spools a `locate_query` event. Behind the consent gate, so OFF = no-op = byte-identical.

## Scope / deferrals (honest)

- **In scope:** consent model, schema v1, local JSONL spool, the `locate_query` hook, unit
  tests, this doc.
- **Deferred (needs product/lead direction):** interactive accept/reject capture
  (`locate_outcome`) — needs a feedback channel (a `kin locate feedback` subcommand or an
  agent-emitted signal); query redaction/PII policy; retention/rotation beyond per-day
  files; any upload/aggregation (the rest of the "flywheel").

## Open decisions for team-lead (gate before collection lands)

1. **Consent model:** env + config (recommended) vs env-only vs config-only.
2. **accept/reject now or phase 2:** recommend phase 1 = query+results+funnel only, with
   the schema reserving `locate_outcome` for a follow-up; vs build a feedback channel now.
3. **Spool location:** `.kin/telemetry/` (recommended) vs `.kin/logs/` vs other.
