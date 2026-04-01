# Kin Review Extraction Plan

## Goal

Keep semantic review logic reusable without paying separate-repo overhead while the substrate is still changing quickly.

## Current Shape

`kin-review` now lives inside the `kin` workspace so CLI, daemon, and MCP review semantics stay aligned by default.

## Extraction Trigger

Split this crate back out only when the review boundary has:

- stable contracts
- real external consumers beyond `kin`
- an independent release cadence
