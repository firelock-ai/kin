# Contributing to kin-blobs

Thanks for your interest in kin-blobs. This guide covers local development, the
conventions this repository follows, and how to get changes reviewed.

## Development Setup

kin-blobs is a Rust crate. CI builds on **stable** Rust, so a current stable
toolchain via [rustup](https://rustup.rs/) is all you need:

```sh
rustup toolchain install stable
```

Build and test:

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

## DCO Sign-Off

This project uses the [Developer Certificate of Origin
(DCO)](https://developercertificate.org/). Every commit you push on a pull
request must carry a `Signed-off-by` trailer:

```
Signed-off-by: Your Name <you@example.com>
```

Add it by passing `-s` to `git commit`:

```sh
git commit -s -m "fix(store): improve error message on hash mismatch"
```

If you forgot to sign off earlier commits on your branch:

```sh
git commit -s --amend              # amend only the last commit
git rebase --signoff HEAD~N        # add sign-off to the last N commits
```

By signing off you certify that you wrote the code (or have the right to
submit it) and that it may be distributed under the Apache License 2.0 that
governs this repository. Bot-authored commits (Dependabot, GitHub Actions)
are exempt.

## AI-Assisted Contributions

Kin is built with significant AI assistance, and we welcome AI-assisted
contributions from the community. A few requirements:

- **You are responsible for AI-generated code you submit.** Review every
  line before opening a PR. If the model hallucinated an API call, an
  unsound unsafe block, or a security hole, that is your bug to catch.
- **AI-generated code is your contribution.** By signing off your commits
  you assert that you have reviewed the generated code and are submitting it
  under your own name, not as a third-party work. Firelock asserts copyright
  over AI-generated code it produces; you assert copyright over what you
  produce and submit here.
- **No raw model output in commit messages or comments.** Clean up generated
  prose before it lands in public history. Write durable, human-authored
  commit messages that describe the technical change.

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/).
A `type(scope): summary` subject is the expected shape:

```
fix(store): make write durable across crashes with fsync-on-rename
feat(store): add list_hashes streaming iterator
docs(readme): expand usage example
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, and
`chore`. Write the summary in the imperative mood and keep it focused on what
changed and why.

## Branch Naming and Commit Hygiene

Public Git history is part of the product, so keep it clean and reviewable:

- **Keep branch names topical, not tracker-coded.** Prefer short, descriptive
  names like `fix/write-durability` or `feat/streaming-list`. Avoid embedding
  internal issue or tracker IDs in a branch name — a squash merge copies the
  branch name into the public commit subject, so anything in the branch name
  lands in history verbatim.
- **Write durable subjects and bodies.** Commit messages should describe the
  technical change and why it was made. Keep internal tracker IDs, session
  identifiers, and automated authorship trailers out of public commit metadata.
- **Don't bypass the hooks.** Repository hooks normalize commit metadata for
  consistency — don't skip them with `--no-verify`.

## Pull Requests

- **Keep PRs scoped.** Stage only the files your change actually needs.
  Unrelated cleanups belong in their own PR.
- Make sure `cargo fmt`, `cargo clippy`, and `cargo test` all pass before
  requesting review.

## Reporting Issues

File issues on [firelock-ai/kin-blobs](https://github.com/firelock-ai/kin-blobs/issues).

For security vulnerabilities, do **not** open a public issue. Follow the
private reporting process in [SECURITY.md](SECURITY.md).

Triage SLA: security issues are acknowledged within 48 hours; general issues
within 7 days.

## Repository Boundaries

kin-blobs is the content-addressable storage primitive in the Kin local
substrate. It has no knowledge of the semantic graph or higher-level types.
Changes to graph storage, search, or the type schema belong in `kin-db` or
`kin-model`. Changes to the CLI, daemon, or MCP behavior belong in `kin`.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license that covers this repository.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
