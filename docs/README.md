# Kin documentation

Start with the [Quickstart](quickstart.md). It installs Kin, admits a
repository, and walks the everyday loop end to end. Once Kin is running, the
[CLI reference](cli-reference.md) is the page you keep open.

## Read in this order

1. **[Quickstart](quickstart.md)** installs Kin, runs guided setup, admits your
   first repository, and covers commit, history, semantic search, and MCP.
2. **[CLI reference](cli-reference.md)** documents every command the `kin`
   binary exposes, with its real arguments, flags, and defaults.
3. **[MCP tools](mcp-tools.md)** is the same thing for agents. It lists every
   tool the bundled MCP server serves and what each one answers.
4. **[Session runtime](session-runtime.md)** explains how `kin exec`,
   `kin shell`, `kin with`, and `kin open` run ordinary tools against
   materialized graph truth, and what happens when one of them fails.
5. **[`kin agent`](cli-reference.md#kin-agent)** is Kin's own agent and the path
   we recommend for agent work. It drives any OpenAI-compatible endpoint, local
   or hosted, answers only from the graph, and records every run as a transcript
   plus a Kin trace.

## Reference

- **[Environment variables](env-vars.md)** is the generated list of supported
  `KIN_*` variables, their defaults, and which ones change results rather than
  performance.
- **[Hosted daemon start requirements](hosted-daemon-start.md)** explains the
  `hosted_start_requirements` block `kin-daemon --compat-json` prints, which is
  how a deployment reads what an image needs instead of tracking it by hand.
- **[Language support](language-support.md)** states what semantic enrichment
  each language actually gets. No tier is implied beyond what extraction emits.
- **[Store size](store-size.md)** explains what drives the size of `.kin/` and
  records what has been measured.
- **[Windows](windows-wsl2.md)** covers what works natively and why WSL2 is the
  recommended path.

## How Kin works

- **[Architectural thesis](thesis.md)** is the argument for a graph-first
  repository substrate over a file-first, diff-first one.
- **[Write-authority model](write-authority-model.md)** describes where the
  source of truth sits during the move from file-first to graph-first, and
  where the graph gets a veto.

## Security

- **[Threat model](security/threat-model.md)** covers the daemon's control API
  and the filesystem projection.
- **[Release signing and update trust](security/signing-and-update-trust.md)**
  traces what a downloaded release proves and how install verifies it.
- **[Code scanning triage](security/code-scanning-triage.md)** explains why the
  CodeQL check goes red on large pull requests without anything being wrong with
  them, gives the one command that tells you, and records the standing
  disposition of every rule that fires here.

## For contributors

- **[Release tag bot](release-bot.md)** documents the automation that turns
  reviewed `main` drift into a tagged, published release.
- **[`ecosystem-manifest.json`](ecosystem-manifest.json)** is the canonical
  description of the Kin repositories and how they fit together.
