# Contributing to Kin

Thanks for your interest in Kin. This guide covers local development, the
conventions this repository actually follows, and how to get changes reviewed.

## Development Setup

Kin is a Rust workspace. CI builds on **stable** Rust, so a current stable
toolchain via [rustup](https://rustup.rs/) is all you need:

```sh
rustup toolchain install stable
```

Build and test the workspace:

```sh
cargo build
cargo test
```

Before opening a pull request, make sure the standard checks pass:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI treats clippy warnings as errors (`-D warnings`), so a clean clippy run
locally avoids surprises.

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/).
Recent history shows the expected shape — a `type(scope): summary` subject:

```
fix(locate): make scoring pipeline deterministic with explicit tie-breaks
feat(mcp): unify tool responses under a versioned response envelope
docs(planning): canonical roadmap status update
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, and
`chore`. Scopes match the area you touched (`cli`, `daemon`, `mcp`, `locate`,
`search`, `release`, and so on). Write the summary in the imperative mood and
keep it focused on what changed and why.

## Branch Naming and Commit Hygiene

Public Git history is part of the product, so keep it clean and reviewable:

- **Keep branch names topical, not tracker-coded.** Prefer short, descriptive
  names like `fix/locate-tie-breaks` or `docs/contributing-hygiene`. Avoid
  embedding internal issue or tracker IDs in a branch name — a squash merge
  copies the branch name into the public commit subject, so anything in the
  branch name lands in history verbatim.
- **Write durable subjects and bodies.** Commit messages should describe the
  technical change and why it was made. Keep internal tracker IDs, session
  identifiers, and automated authorship trailers out of public commit
  metadata; link that context from the pull request instead.
- **Don't bypass the hooks.** Repository hooks normalize commit metadata for
  consistency — don't skip them with `--no-verify`.

## Pull Requests

- **Keep PRs scoped.** Stage only the files your change actually needs.
  Unrelated cleanups belong in their own PR — this keeps review focused and
  history bisectable.
- Fill out the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).
- Make sure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
- If your change is user-facing, add an entry to the `[Unreleased]` section of
  [CHANGELOG.md](CHANGELOG.md) in the Keep a Changelog format already used there.

## Reporting Issues

File issues on [firelock-ai/kin](https://github.com/firelock-ai/kin/issues)
using the provided templates:

- **Bug reports** — use the bug report template.
- **Feature requests** — use the feature request template.

For security vulnerabilities, do **not** open a public issue. Follow the
private reporting process in [SECURITY.md](SECURITY.md).

## Repository Boundaries

Kin is one repository within a larger ecosystem (`kin-db`, `kin-vfs`,
`kinlab`, and others). Graph storage and retrieval internals live in `kin-db`;
the filesystem projection lives in `kin-vfs`. If your change targets one of
those concerns, open it against the repository that owns the code.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license that covers this repository.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
