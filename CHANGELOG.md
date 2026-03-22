# Changelog

All notable changes to Kin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- npm: `kin-mcp` stays side-effect-free and no longer tries to auto-initialize `.kin/` on MCP startup
- README: brownfield adoption guidance now explicitly documents `kin init`, `kin git import`, and `kin commit`

## [0.1.0-alpha.2] - 2026-03-21

### Added

- CLI: `kin clone` -- clone a repository (native Kin or Git compat fallback)
- CLI: `kin pull` -- pull changes from a remote (native Kin or Git compat fallback)
- CLI: `kin checkout` -- restore a file from any point in the semantic history
- CLI: `kin push` now executes Git push for git-export remotes (previously only prepared the export)
- npm: `kin-mcp` wrapper package for assistant-native MCP setup via `npx`

### Fixed

- CHANGELOG crate count: 17 → 19
- README clone URLs: pointed to correct `firelock-ai` organization
- Assistant setup guidance now includes the npm-based MCP shortcut

## [0.1.0] - 2026-03-13

### Added

- Semantic graph engine backed by KinDB for entity/relationship storage
- Tree-sitter parsing for TypeScript, Python, Go, Java, Rust, JavaScript, and C
- Content-addressable blob store for source text
- CLI: `kin init`, `kin commit`, `kin status`, `kin trace`, `kin context`, `kin diff`, `kin review`
- MCP server for AI agent context delivery (`kin-mcp`)
- Git import/export interop via `kin-git`
- Session workspaces with file reconciliation
- Benchmark harness for measuring context quality and token savings (`kin bench`)
- Compat and native execution modes for assistant integration
- Semantic fingerprinting for identity tracking across renames and refactors
- Token-budgeted context packs via graph traversal
- Daemon mode for background file watching (`kin-daemon`)
- 19-crate workspace architecture

[unreleased]: https://github.com/firelock-ai/kin/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0-alpha.2
[0.1.0]: https://github.com/firelock-ai/kin/releases/tag/v0.1.0
