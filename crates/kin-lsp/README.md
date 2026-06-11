# kin-lsp

`kin-lsp` enriches Kin's semantic graph with information from standard language
servers.

Tree-sitter parsing gives Kin syntax-level structure. `kin-lsp` adds
type-resolved relations that require language-server knowledge, such as call
hierarchy edges, type hierarchy edges, and type-definition links. The resulting
relations are consumed by the public Kin local stack through `kin` and `kin-db`.

The crate is Apache-2.0 and belongs to the open local substrate. It does not
contain the hosted KinLab control plane.
