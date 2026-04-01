# Kin Remote Architecture

## Goal

Give Kin native remote semantics that work for semantic changes, review state, and proofs.

## Why Separate It

Remote hosting has a different lifecycle than:

- local graph storage in `kin-db`
- local repo and CLI behavior in `kin`
- hosted UI in `kinlab`

## Initial Boundary

The first cut should stay deterministic and transport-agnostic:

- remote capabilities
- push planning
- pull planning
- divergence handling
- publish gates

## Intended Consumers

- `kin`
- `kinlab`
- future hosted sync workers
