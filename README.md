<div align="center">

<a href="https://kinlab.ai"><picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/firelock-ai/kin/main/brand/kin-lockup-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/firelock-ai/kin/main/brand/kin-lockup-light.svg">
  <img src="https://raw.githubusercontent.com/firelock-ai/kin/main/brand/kin-lockup-light.svg" alt="Kin" width="300">
</picture></a>

<h3>Software that remembers itself.</h3>

<p><em>Exact context, not more.</em></p>

<p>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
<a href="https://github.com/firelock-ai/kin/releases/latest"><img src="https://img.shields.io/github/v/release/firelock-ai/kin?color=6E56CF&label=release" alt="Latest release"></a>
<a href="https://kinlab.ai"><img src="https://img.shields.io/badge/hosted-kinlab.ai-111111.svg" alt="Hosted at kinlab.ai"></a>
</p>

</div>

Kin is the system of record for AI-written software. AI agents can write a
change faster than a team can establish what it touches, whether it reverses
an earlier fix, and how far its blast radius reaches. Git records files and
line history. Kin records the software itself as a graph of entities,
relations, changes, and provenance, then gives humans and agents one semantic
authority to query and review.

Kin is a public alpha. It is usable today as a local CLI, daemon, MCP server,
review surface, and graph-backed filesystem projection. It is pre-1.0, so expect
rough edges and breaking changes. See the [latest stable release](https://github.com/firelock-ai/kin/releases/latest)
and the [current limitations](#platform-and-maturity) before adopting it in a
critical workflow.

## See it on a real repository

A one-line signature change in ripgrep looks harmless in the diff. Asking the
graph before any build runs:

<div align="center">
<img src="docs/assets/kin-impact-ripgrep.png" alt="A git diff adding a parameter to resolve_binary, then kin impact listing 13 impacted entities within 3 hops, grouped by hop distance" width="920">
</div>

The three direct callers stopped compiling the moment that parameter changed.
`kin impact` named them from graph truth, with the two and three hop blast
radius behind them, before any compiler ran.

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

## Open source and the Kin ecosystem

The core of Kin is open source under Apache-2.0: [kin](https://github.com/firelock-ai/kin),
[kin-db](https://github.com/firelock-ai/kin-db), [kin-vfs](https://github.com/firelock-ai/kin-vfs),
and [kin-editor](https://github.com/firelock-ai/kin-editor), plus the supporting
libraries kin-model, kin-blobs, kin-search, kin-vector, kin-infer, kin-lsp, and
kin-actions.

[KinLab](https://kinlab.ai) is a proprietary product built on this open core: the
hosted collaboration and control-plane layer described above.

The same boundary applies to how benchmark work is shared. The [benchmark
specification and a standalone, dependency-free bundle verifier](https://github.com/firelock-ai/kin-bench-spec)
are public, so a claim can be checked without access to the system that produced
it. The runner and proof infrastructure that produce sealed evidence bundles (the
orchestration, the pinned-release proof gate, and the hosted measurement
environment) remain private for now. The spec and verifier open first; the runner
can open later.

## Shortest graph-backed path

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

### 2. Admit an existing repository as graph truth

```sh
cd /path/to/your/repository
kin init .
```

In a clean Git repository, `kin init` atomically admits complete reachable
history, refs, raw objects, the exact workspace tree, and admission policy into
repository-v6 graph authority. It never substitutes an exact-HEAD snapshot or
raw-filesystem semantic rebuild. Remote-bearing repositories currently fail
closed until exact Kin remote mapping is available.

Repository admission does not run semantic enrichment. Query surfaces consume
graph-owned enrichment when it exists and report its absence instead of hiding
the gap behind raw file search.

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

After graph-native semantic enrichment exists, run `kin embed` to add local
vector similarity and confirm coverage with `kin status --json`.

## Review an AI-written change

**AI writes code. Kin proves the change.**

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

Kin is designed to replace Git as the repository authority. During brownfield
adoption, Git remains an explicit import/export interoperability boundary; it
never answers Kin runtime queries or repairs missing graph truth.

- `kin init` imports complete reachable Git history and exact parent edges.
  Kin deliberately has no partial-history or snapshot-only initialization mode.
- After import, Kin's graph owns repository identity, tree state, history, refs,
  and semantic relations. Filesystem and Git views are projections.
- `kin git export --output ../repo.git` writes a new bare Git projection from
  one graph-owned authority generation. It does not consult working files or an
  ambient `.git/` object store, and it refuses an existing or in-repository
  destination. Objects, refs, and directories are flushed before the
  no-replace destination publication is acknowledged. Capability-anchored
  publication is currently available on Unix hosts; other hosts refuse before
  creating the export.
- `kin eject` first proves that the graph-owned workspace, source blobs, and
  working projection agree exactly. It builds and verifies a complete ordinary
  Git replacement, stops graph projection, revalidates authority, then swaps
  authority in a durable order: the replacement `.git/` is installed first,
  then the locked `.kin/` namespace is detached with a no-replace rename. The
  replacement `.git/` comes from Kin authority; the previous repository-local
  `.git` entry and the detached `.kin/` are retained in a private, recoverable
  sibling archive.
  Credential-free remote and branch-tracking settings sealed during import are
  restored without copying ambient Git configuration.
  Kin intentionally retains that archive until the operator has independently
  backed up and removes it. Capability-anchored eject is currently available on
  Unix hosts; Windows fails before namespace mutation until an equally durable
  retained-handle transaction is available.

This lets a team migrate an existing repository without giving up its editor,
compiler, build system, or Git interoperability while Kin becomes authoritative.

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

The published preregistered Multi-SWE-Bench Go proof package is pinned to an
older build, not the moving latest release, and does not establish a broad
speed, token-savings, or category-win claim. Comparative results are withheld
here pending independent verification.

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
