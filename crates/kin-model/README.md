# kin-model

`kin-model` contains the canonical shared types for Kin's semantic repository
substrate.

It defines the graph objects that the public Kin stack uses across the local
engine, CLI, daemon, MCP server, projection layer, and supporting crates:

- entities, artifacts, relations, revisions, and retrieval keys
- sessions, intents, locks, traffic reports, and coordination events
- review, work, provenance, verification, and temporal records
- projection, reconciliation, preset, and policy types

This crate is intentionally small and dependency-light. It is the schema and
domain boundary for the open local substrate, not the hosted KinLab control
plane.
