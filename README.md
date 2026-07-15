# Kin

> **AI writes code. Kin proves it safe to ship.**
>
> The **system of record for AI-written software**.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/badge/release-latest-6E56CF.svg)](https://github.com/firelock-ai/kin/releases/latest)
[![kinlab.ai](https://img.shields.io/badge/hosted-kinlab.ai-111111.svg)](https://kinlab.ai)

AI agents can write a change faster than a team can establish what it touches,
whether it reverses an earlier fix, and how far its blast radius reaches. Git
records files and line history. Kin records the software itself as a graph of
entities, relations, changes, and provenance, then gives humans and agents one
semantic authority to query and review.

Kin is a public alpha. It is usable today as a local CLI, daemon, MCP server,
review surface, and graph-backed filesystem projection. It is pre-1.0, so expect
rough edges and breaking changes. See the [latest stable release](https://github.com/firelock-ai/kin/releases/latest)
and the [current limitations](#platform-and-maturity) before adopting it in a
critical workflow.

## The stack

Kin is one system with a few clear public surfaces:

| Surface | What it does |
| --- | --- |
| **[kin](https://github.com/firelock-ai/kin)** | Semantic system of record: CLI, daemon, graph lifecycle, MCP, review, provenance, and Git coexistence. |
| **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** | Projects graph-owned files through normal filesystem calls so existing tools can keep using files. |
| **[kin-editor](https://github.com/firelock-ai/kin-editor)** | VS Code access to the entity explorer, semantic search, trace, review, and rename surfaces. |
| **[Kin MCP](docs/mcp-tools.md)** | Typed graph tools for AI agents, bundled into `kin` and launched with `kin mcp start`. |
| **[KinLab](https://kinlab.ai)** | Hosted collaboration and control plane. Public repository connection is not a first-run flow yet. |

Supporting repositories provide graph storage, retrieval, embeddings, blobs,
language enrichment, and reproducible proof. They are implementation layers,
not separate products a new user needs to assemble.

## Five-minute graph-backed path

### 1. Install and configure Kin

On macOS or Linux:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
exec "$SHELL" -l
kin setup --intent agent
```

The installer resolves the [latest stable release](https://github.com/firelock-ai/kin/releases/latest),
verifies its published SHA-256 checksum, installs the managed binaries under
`~/.kin`, and launches setup. Running the explicit `agent` intent configures the
built-in MCP server for detected supported clients. Use `--intent local` for CLI
and filesystem use without MCP configuration, or `--intent editor` for the VS
Code path.

For manual installation, each archive and its `.sha256` file is published under
`https://github.com/firelock-ai/kin/releases/latest/download/`. The moving asset
names are `kin-macos-aarch64`, `kin-macos-x86_64`, `kin-linux-aarch64`,
`kin-linux-x86_64`, and `kin-windows-x86_64`; use the Unix `.tar.gz` or Windows
`.zip` suffix shown on the latest release page.

Homebrew and npm entry points resolve the same public release channel:

```sh
brew install firelock-ai/kin/kin
# or
npm install -g @kinlab/kin@latest
```

On Windows, run `irm https://get.kinlab.dev/install.ps1 | iex` in PowerShell.
Native Windows has a smaller capability envelope; read
[Platform and maturity](#platform-and-maturity) below.

### 2. Build graph truth for an existing repository

```sh
cd /path/to/your/repository
kin init .
kin status
kin overview
```

In an existing Git repository, `kin init` imports recent history by default and
indexes the checked-out tree into `.kin/`. `kin status` starts or reuses the
repository daemon and reports graph and embedding state. The graph is the answer
authority for Kin queries; a missing or unavailable graph is reported instead of
being hidden behind raw file search. Initial indexing time scales with repository
size; the command sequence itself is the short path, not a fixed performance
promise for every codebase.

### 3. Ask the graph a real question

```sh
kin locate "where are webhook retries handled"
kin refs ExactEntityName
kin trace ExactEntityName
```

Replace `ExactEntityName` with a symbol returned by `locate`. `locate` finds the
entities relevant to an intent, `refs` shows graph-owned callers/importers and
references, and `trace` returns the focal entity plus nearby semantic context.
Once embeddings are complete, your configured AI agent can use the vector-backed
`semantic_locate` tool; `get_context_pack`, `find_references`, and
`trace_data_flow` expose the graph neighborhood directly.

`kin init` builds the graph without waiting for embeddings. At that point locate
uses graph and lexical signals and reports that vector coverage is incomplete.
Run `kin embed` to add local vector similarity, then confirm coverage with
`kin status --json`.

## Review an AI-written change

Run `kin init` on the branch you want to review so the relevant Git history is in
the graph, then pass explicit commit SHAs to the report-only shadow gate:

```sh
kin review shadow "$(git rev-parse main)..$(git rev-parse HEAD)"
```

The result is `PASS`, `NEEDS ATTENTION`, or `WOULD BLOCK`, with graph-derived
blast radius, repair context, and audit evidence. The command does not block a
merge or mutate graph state. It produces evidence for a human or CI policy to
act on.

## How Kin relates to Git

Kin coexists with Git. It does not rewrite Git history, branches, or remotes.

- `kin init --git-history off|recent|full` controls bootstrap history import;
  `recent` is the default for an existing Git repository.
- `kin migrate` is the explicit deep-history migration path.
- Git remains the interoperability and transport boundary while Kin owns the
  semantic graph used by Kin commands.
- `kin eject` removes `.kin/` graph state and leaves working files and `.git`
  untouched.
- `kin eject --revert-files` is a separate, destructive option that restores
  the pre-init file snapshot after explicit confirmation. It still never
  modifies `.git`.

This lets a team evaluate Kin inside an existing repository without giving up
its Git remote, history, editor, compiler, or build system.

## Platform and maturity

The core runtime and the filesystem projection have different support
boundaries:

| Platform | Core Kin runtime | `kin-vfs` projection |
| --- | --- | --- |
| macOS, Apple Silicon and Intel | Native graph, vector, daemon, setup, MCP, and review surfaces ship in the release archive. | Shipped and exercised on both architectures. It uses `DYLD_INSERT_LIBRARIES`; SIP-protected or hardened programs may reject injection. |
| Linux x86_64 and arm64 | `kin` and `kin-daemon` are static musl builds intended to run on glibc and musl distributions. | The public VFS executable and shim are GNU/glibc builds, not musl builds. Current artifacts require glibc 2.39; Alpine/musl and older-glibc distributions are not supported projection hosts. The arm64 release proof runs on Ubuntu 24.04. |
| Native Windows x86_64 | Supported for graph, lexical retrieval, daemon, setup, MCP, and review without vectors. | Not shipped. Use WSL2 with a Linux distribution that meets the glibc boundary for projection. |

Bounded arm64 testing found the core graph and lexical path usable at 512 MB,
but full embedding downloads a roughly 522 MB model and currently needs 2 GB as
the safe operating floor; 1 GB is an unsafe edge and 512 MB can terminate during
embedding. These are observed alpha constraints, not universal sizing promises.

A successful `kin --version` proves only that the core binary runs. It does not
prove VFS compatibility or a live graph-backed projection. On a supported Unix
host, use `kin setup status`, `kin-vfs status --workspace .`, and a real
`kin-vfs exec --workspace . -- <command>` launch. The VFS launcher includes an
interposition canary and reports when the operating system strips the shim.
The [kin-vfs README](https://github.com/firelock-ai/kin-vfs#current-platform-and-package-boundaries)
contains the full boundary.

Release assets are checksum-published and the release workflow runs anonymous
installation, daemon/MCP, embedding, and real graph-backed VFS projection checks
across its supported runner matrix. The workflow itself is public:
[Install Proof](https://github.com/firelock-ai/kin/actions/workflows/install-proof.yml).
A green release proves those exact artifacts and environments; it is not a claim
that every distribution, tool, or repository shape is already covered.

## Proof posture

The published preregistered Multi-SWE-Bench Go proof package reports
bit-identical replay on 26 of 26 tasks versus 3 of 26 for its lexical baseline,
with symbol and line retrieval improvements and file retrieval at a statistical
tie. The package is pinned to an older build, not the moving latest release, and
does not establish a broad speed, token-savings, or category-win claim.

Read the methodology, task set, build identity, and artifacts in the
[public proof package](https://firelock.ai/labs/kin-proof). Treat claims outside
that measured scope as hypotheses until they have their own reproducible proof.

## Learn and contribute

- [Quickstart and advanced configuration](docs/quickstart.md)
- [MCP tool reference](docs/mcp-tools.md)
- [Graph-first thesis](docs/thesis.md)
- [GitHub Discussions](https://github.com/firelock-ai/kin/discussions)
- [Bug reports and feature requests](https://github.com/firelock-ai/kin/issues/new/choose)
- [Contributing guide](CONTRIBUTING.md)
- [Private security reporting](SECURITY.md)

## License

[Apache-2.0](LICENSE).
