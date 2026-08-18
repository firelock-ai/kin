# Kin Write-Authority Model

This document defines the write-authority model for the Kin ecosystem: how changes are proposed, validated, and persisted, and where the ultimate source of truth resides during the transition from file-first to graph-first workflows.

## The Destination: Graph-Authoritative Veto

The intended end-state of the Kin ecosystem is **graph-authoritative** with hard enforcement. In this model, the semantic graph is the primary system of record, and the filesystem is a projection. 

At this stage, the graph exercises a **veto** at the write boundary:
- **Write Interception**: Filesystem operations are intercepted at the projection boundary and evaluated before they reach graph truth. The `/vfs/write-notify` and `/vfs/file-changed` routes that once carried this are gone: they were pre-v6 and the daemon answers 404 for both. What acknowledges a write today is the watcher backstop plus an explicit admission, `POST /commands/admit` for an exact-tree admission and `POST /commands/commit` for the seam `kin commit` uses. A mount admits through the latter, so a write through a mounted projection reaches graph truth and `kin log` carries it.
- **Hard Intents and Contracts**: Before any overlay is applied to the graph or projected back to the filesystem, the proposed changes are evaluated against hard intents and semantic contracts (e.g., breaking type signatures, violating downstream dependencies, or conflicting with another agent's reserved intent scope).
- **Governance Enforcement**: If a change violates an established intent, fails semantic review, or introduces a conflict, the write is rejected at the VFS layer.

This ensures that the repository remains strictly compliant with semantic governance policies, shifting validation from post-commit CI loops to stage-time (or even write-time) checks.

## The Transitional State: A Permissive Write Path with Forensic Reconcile

Because completely blocking standard development tools (like Git, traditional IDEs, or `sed`) creates immediate adoption friction, Kin currently operates in a **transitional state**:

- **Permissive write path**: Standard tools still write to files directly, and Kin does not reject those writes at the VFS layer today. Graph authority is established by reconcile rather than at the moment of the write, so during this transition the window between a file edit and graph truth is real, and closing it is what hard enforcement does.
- **Forensic Reconcile**: The Kin daemon asynchronously ingests these filesystem changes, rebuilding the semantic graph and detecting conflicts or contract violations *after* the fact.
- **Advisory Governance**: Rather than blocking the write, the system generates downstream warnings, traffic collisions, or semantic review failures based on the updated graph state. 

### Why This Matters

This transitional posture is an intentional design choice for brownfield migration. It allows humans and agents to adopt Kin's semantic retrieval, memory, and coordination primitives (like intents and traces) without risking being immediately locked out by strict enforcement. 

However, **this is migration debt**. The governance and audit pitch is a definitive, cryptographically verifiable record of who approved what, proving that no contracts were bypassed. That record ultimately requires the hard enforcement of the destination state. Documenting this transition keeps our governance narrative honest. Today we provide forensic visibility and advisory warnings. Tomorrow we provide structural enforcement.
