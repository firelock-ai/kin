# Kin Search Architecture

`kin-search` should sit between raw graph storage and user-facing search experiences.

## Inputs

- lexical matches from file, symbol, and note indexes
- semantic candidates from vector search
- graph proximity signals from dependency and ownership edges
- proof and provenance signals from review, verification, and activity

## Outputs

- ranked results
- ranking explanations
- policy-friendly evidence summaries

## Initial Boundary

The initial crate only provides deterministic ranking primitives. It should remain easy to embed from:

- `kin`
- `kinlab`
- `kin-code`
- future hosted search services
