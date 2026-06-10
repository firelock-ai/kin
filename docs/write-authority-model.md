# Kin Write-Authority Model

This document defines the write-authority model for the Kin ecosystem: how changes are proposed, validated, and persisted, and where the ultimate source of truth resides during the transition from file-first to graph-first workflows.

## The Destination: Graph-Authoritative Veto

The intended end-state of the Kin ecosystem is **graph-authoritative** with hard enforcement. In this model, the semantic graph is the primary system of record, and the filesystem is a projection. 

At this stage, the graph exercises a **veto** at the write boundary:
- **Write-Notify Interception**: Filesystem operations are intercepted at `/vfs/write-notify`.
- **Hard Intents and Contracts**: Before any overlay is applied to the graph or projected back to the filesystem, the proposed changes are evaluated against hard intents and semantic contracts (e.g., breaking type signatures, violating downstream dependencies, or conflicting with another agent's reserved intent scope).
- **Governance Enforcement**: If a change violates an established intent, fails semantic review, or introduces a conflict, the write is rejected at the VFS layer.

This ensures that the repository remains strictly compliant with semantic governance policies, shifting validation from post-commit CI loops to stage-time (or even write-time) checks.

## The Transitional State: Filesystem-Authoritative with Forensic Reconcile

Because completely blocking standard development tools (like Git, traditional IDEs, or `sed`) creates immediate adoption friction, Kin currently operates in a **transitional state**:

- **Filesystem-Authoritative**: The raw filesystem remains the permissive source of truth for incoming changes. Tools and agents can write to files directly without immediate VFS rejection.
- **Forensic Reconcile**: The Kin daemon asynchronously ingests these filesystem changes, rebuilding the semantic graph and detecting conflicts or contract violations *after* the fact.
- **Advisory Governance**: Rather than blocking the write, the system generates downstream warnings, traffic collisions, or semantic review failures based on the updated graph state. 

### Why This Matters

This transitional posture is an intentional design choice for brownfield migration. It allows humans and agents to adopt Kin's semantic retrieval, memory, and coordination primitives (like intents and traces) without risking being immediately locked out by strict enforcement. 

However, **this is migration debt**. The governance and audit pitch—providing a definitive, cryptographically verifiable record of who approved what, and proving that no contracts were bypassed—ultimately requires the hard enforcement of the destination state. Documenting this transition keeps our governance narrative honest: today we provide forensic visibility and advisory warnings; tomorrow we provide structural enforcement.
