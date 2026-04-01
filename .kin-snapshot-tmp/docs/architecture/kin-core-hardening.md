# Kin Core Hardening

This document is the blunt assessment of Kin itself as a substrate.

The question is not:

- "Is Kin interesting?"
- "Is Kin visionary?"
- "Can Kin beat Git on some benchmarks?"

Those are already yes.

The real question is:

> Is Kin hard enough, correct enough, and trustworthy enough to become the primary reality for a Kin-first runtime?

Right now, the answer is:

- **the concept is real**
- **the substrate is strong**
- **the core is not fully hardened yet**

That means the next phase is not invention alone. It is reliability.

## What Already Feels Solid

These are no longer speculative.

### 1. Graph + blob substrate

Kin already has the right base architecture:

- semantic graph
- content-addressed blobs
- graph-backed entities and relations
- projection instead of files-as-truth

This is the right foundation.

### 2. Real indexing and retrieval

Kin is not just storing data. It is already useful:

- semantic indexing
- multi-language parsing
- cross-file linking
- semantic search
- context building
- trace flows

This is the part that proves Kin is not a toy.

### 3. Native mode is real

Native mode is no longer just a concept. It exists.

- control-root layout
- source-root separation
- `kin with`
- `kin shell`
- `kin open`
- benchmarkable native flows

It is still rough in places, but it is real.

### 4. Benchmarking and telemetry

The benchmark harness is now a real engineering tool, not just a demo script.

- cached conversion
- warm-cache workflow runs
- step traces
- subagent visibility
- shim logs
- cost attribution

This matters because Kin can now be optimized from evidence instead of vibes.

## What Still Needs Hardening

These are the areas that determine whether the substrate becomes trustworthy enough for a Kin-first runtime.

### 1. Commit-path correctness

This is the most sacred surface in the entire system.

If commit is wrong, everything above it is compromised:

- history
- identity continuity
- review
- impact
- provenance
- work item anchoring

Commit has improved a lot, but it still needs to become boringly correct in all of these cases:

- unchanged entities
- modified entities
- renamed entities
- deleted entities
- relation replacement
- parse failures
- partial file failures

The standard here should be brutal:

> No ghost entities. No stale relations. No identity drift. No silent corruption.

### 2. Transactionality and crash safety

Kin still needs stronger guarantees that graph mutation and semantic-change recording move together.

The system should not be allowed to land in states like:

- graph updated, change record missing
- relations updated, deltas incomplete
- partial mutation after failure

The bar should be:

> A semantic commit is atomic, or it did not happen.

### 3. Identity stability

Semantic identity is the whole point of Kin.

If IDs drift, everything weakens:

- history continuity
- blame
- work links
- proof links
- session/intent targeting

Entity identity and logical relation identity need to remain stable enough that higher layers can trust them without revalidating the world.

### 4. Retrieval quality

The next major bottleneck is not feature count. It is retrieval efficiency.

What hurts Kin today:

- broad search fan-out
- over-large `--show-body` responses
- too many turns to get one answer

What helps:

- exact-name lookup
- one-shot commands like `kin trace`
- better result ranking
- better nearby/transitive selection

The product needs:

> fewer commands, higher signal, smaller output, better first hit

### 5. Native-mode invariants

Native mode has to become predictable and strict.

That means:

- the right process sees the right surface
- shells, assistants, editors, and dumb tools get intentionally different realities
- shims and restrictions behave consistently
- control-root semantics do not leak
- execution workspaces do not drift from the graph

Native mode cannot remain "mostly works if you know what to avoid."

### 6. Session lifecycle

The current session model is real but still wants to feel more unified.

The product loop should become:

1. create or resume session
2. materialize execution surface
3. work
4. reconcile
5. clean up

That should feel like one coherent thing, not several loosely related commands.

### 7. Performance

There are now two kinds of performance that matter:

#### A. Conversion performance

- initial `kin init`
- first `kin commit`
- graph creation
- indexing throughput

#### B. Workflow performance

- search latency
- trace/context latency
- shell/native-mode responsiveness
- projection/materialization cost
- session startup

Conversion is now separated from benchmarked workflow, which is correct. Both still matter.

## What Is Good Enough vs Not Good Enough

### Good enough today

Kin is already good enough to:

- benchmark seriously
- improve using telemetry
- support compatibility-mode workflows
- start proving native-mode value
- justify a Kin-first runtime direction

### Not good enough yet

Kin is not yet good enough to:

- treat every core invariant as solved
- stop worrying about commit-path semantics
- assume native mode is production-hardened
- assume the graph never drifts under edge cases

## What Must Be True Before A Kin-First Runtime Depends On It

Before a `kin-pilot`-style runtime becomes the main strategic surface, the substrate should satisfy these rules:

### Rule 1

Semantic commit is trustworthy.

### Rule 2

Native mode is operationally coherent.

### Rule 3

Trace/context/search are efficient enough that they beat file-first exploration often enough to change default behavior.

### Rule 4

Projection and reconcile are strong enough that shells/editors/tools can treat materialized workspaces as reliable execution views.

### Rule 5

Telemetry is strong enough to explain regressions precisely, not vaguely.

## Near-Term Hardening Priorities

If the goal is to make Kin itself stronger while the fork direction is forming, these are the most valuable priorities:

1. commit-path integrity and atomicity
2. retrieval quality and one-shot semantic commands
3. native session lifecycle and reconcile cleanup
4. native-mode invariants around process-specific projection
5. projection/materialization performance

## Strategic Conclusion

Kin does not need another identity crisis.

It already has the right concept.

The mission now is:

> make the substrate so trustworthy that a Kin-first runtime can assume the graph is reality, not just metadata

That is the hardening bar.
