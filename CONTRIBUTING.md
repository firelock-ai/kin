# Contributing to Kin

Thank you for your interest in contributing to Kin. This document covers everything you need to get started.

## Building from Source

### Prerequisites

- **Rust 1.75+** (2021 edition) -- install via [rustup](https://rustup.rs/)
- **C/C++ compiler** -- required for native dependencies in the workspace
  - macOS: `xcode-select --install`
  - Ubuntu/Debian: `apt install build-essential`
  - Fedora: `dnf install gcc gcc-c++`

### Build

```bash
git clone https://github.com/firelock-ai/kin.git
cd kin
cargo build
```

The workspace contains 18 crates. A full build compiles all of them plus an integration test crate.

### Run Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p kin-parser

# Run integration tests only
cargo test -p integration
```

### Lint

```bash
# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

## Developer Certificate of Origin (DCO)

All contributions to Kin require a [Developer Certificate of Origin](https://developercertificate.org/) sign-off. This certifies that you have the right to submit your contribution under the project's license.

Add a `Signed-off-by` line to every commit message:

```
Add Python decorator support to kin-parser

Signed-off-by: Your Name <your.email@example.com>
```

You can do this automatically with `git commit -s`.

**Why DCO?** Kin is licensed under BSL 1.1 (converting to Apache-2.0). The DCO creates a clear chain of title for all contributions, which protects both you and the project. Without it, neither Firelock nor any future steward of the project can guarantee the legal provenance of the code.

## Making Changes

### Branch Strategy

1. Fork the repository and create a branch from `main`.
2. Name branches descriptively: `fix/parser-error-recovery`, `feat/python-decorator-support`, `docs/mcp-setup`.
3. Keep changes focused. One logical change per PR.

### Pull Request Process

1. Ensure all commits are signed off (`git commit -s`). PRs without DCO sign-off will not be merged.
2. Ensure `cargo test` passes locally before opening a PR.
3. Ensure `cargo clippy` produces no warnings.
4. Ensure `cargo fmt` has been applied.
5. Write a clear PR description explaining **what** changed and **why**.
6. Link related issues with `Closes #123` or `Fixes #123`.
7. A maintainer will review your PR. Expect feedback -- this is a complex codebase and we want to get the abstractions right.

### Commit Messages

Write clear, imperative-mood commit messages:

```
Add Python decorator support to kin-parser

The parser now extracts decorators as metadata on function/class entities
rather than treating them as standalone trivia nodes.

Closes #42
```

## Code Style

- Follow standard Rust conventions. Run `cargo fmt` before committing.
- Use `clippy` as your lint guide -- treat warnings as errors.
- Prefer explicit types over complex inference chains in public APIs.
- Error handling: use `thiserror` for library errors, `anyhow` in CLI/integration code.
- Add `#[cfg(test)]` unit tests in the same file as the code they test.
- Integration tests go in the `tests/integration` crate.

### Crate Boundaries

Each crate has a specific responsibility. Before adding code, make sure it belongs in the crate you're modifying:

- **kin-model**: Types only. No logic, no I/O.
- **kin-db**: Embedded graph engine, snapshot persistence, and query acceleration.
- **kin-blobs**: All blob store I/O. Other crates reference content by hash.
- **kin-parser**: Tree-sitter parsing. Language-specific logic goes in language adapters within this crate.
- **kin-cli**: CLI routing and display. Business logic belongs in the underlying crates.

## Reporting Issues

### Bug Reports

Use the [bug report template](https://github.com/firelock-ai/kin/issues/new?template=bug_report.yml). Include:

- Kin version (`kin --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (run with `RUST_LOG=debug` for verbose output)

### Feature Requests

Use the [feature request template](https://github.com/firelock-ai/kin/issues/new?template=feature_request.yml). Describe the problem you're trying to solve, not just the solution you want.

## Good First Issues

Look for issues labeled [`good first issue`](https://github.com/firelock-ai/kin/labels/good%20first%20issue). These are scoped to a single crate and include enough context to get started without deep knowledge of the full system.

## Questions?

Open a [discussion](https://github.com/firelock-ai/kin/discussions) or ask in the issue tracker. We're happy to help you find the right place to contribute.
