# Assistant CLI Compatibility with Kin

This note captures the current compatibility surfaces for the main local coding
agents we are targeting, what Kin already does today, and what Kin should auto-
configure to improve first-run success.

## Why This Matters

Coding agents were built around file-first workflows:

- broad `rg` / `sed` scans
- ad hoc editor memory files
- tool-specific MCP setup
- prompt patterns that assume Git and plain text

Kin changes the substrate, but the agents still need a compatibility layer that:

- gives them clear repo-local guidance
- connects MCP reliably when supported
- keeps direct Kin CLI usage first-class
- nudges them toward entity-first workflows instead of file-dump habits

## Current Kin Behavior

Kin already has these compatibility features:

- `kin assistant install <assistant>`
- `kin assistant doctor`
- `kin assistant configure`
- `kin assistant sync`
- managed repo-local docs:
  - `AGENTS.md`
  - `CLAUDE.md`
  - `CODEX.md`
  - `GEMINI.md`
  - `copilot-instructions.md`
- repo-local guidance generation inside managed blocks
- native Kin MCP server via `kin mcp`

Recent fixes in the open core:

- Codex is now modeled as native-MCP capable instead of wrapper-only.
- `CODEX.md` is now a first-class managed assistant doc target.
- `kin assistant install` now auto-enables and creates assistant-specific docs.
- benchmark prep now enables `CODEX.md` for Codex workspaces too.

## Capability Matrix

| Assistant | Native MCP | Repo guidance file | Local config surface | Best Kin auto-config |
| --- | --- | --- | --- | --- |
| Claude Code | Yes | `CLAUDE.md`, `AGENTS.md` | `claude mcp ...`, project `.mcp.json`, hooks, settings | enable `AGENTS.md` + `CLAUDE.md`, show exact `claude mcp add kin -- kin mcp`, generate hook recommendations |
| Codex | Yes | `AGENTS.md`, `CODEX.md` in practice | `codex mcp ...`, `~/.codex/config.toml`, skills | enable `AGENTS.md` + `CODEX.md`, show exact `codex mcp add kin -- kin mcp`, bias prompts toward direct Kin CLI usage |
| Gemini CLI | Yes | `GEMINI.md`, `AGENTS.md` | `gemini mcp ...`, `~/.gemini/settings.json` | enable `AGENTS.md` + `GEMINI.md`, show exact `gemini mcp add kin -- kin mcp`, keep instructions narrow and command-oriented |
| Cursor | Yes | `AGENTS.md`, optional tool-specific rules | editor settings + MCP | keep generic MCP/stdio config and shared Kin guidance |

## Recommended Auto-Config by Assistant

### Claude Code

Best setup:

1. `kin assistant install claude-code`
2. `claude mcp add kin -- kin mcp`
3. enable and sync `AGENTS.md` + `CLAUDE.md`
4. optionally install hooks that remind Claude to:
   - read `AGENTS.md` first
   - prefer `kin support`, `kin search`, `kin context`, `kin review`
   - use `kin commit` after validated changes

What Kin should optimize for:

- project-scoped MCP examples
- hook templates for pre-edit / post-edit reminders
- stronger Claude-specific `CLAUDE.md` bootstrap text

### Codex

Best setup:

1. `kin assistant install codex`
2. `codex mcp add kin -- kin mcp`
3. enable and sync `AGENTS.md` + `CODEX.md`
4. keep direct Kin CLI instructions prominent

What Kin should optimize for:

- Codex-specific bootstrap guidance that explicitly says when to use:
  - `kin support`
  - `kin search`
  - `kin context`
  - `kin review`
  - `kin verify`
- local config snippets for `~/.codex/config.toml`
- a Kin-aware benchmark path, because Codex is currently the cleanest signal in our audited runs

### Gemini CLI

Best setup:

1. `kin assistant install gemini-cli`
2. `gemini mcp add kin -- kin mcp`
3. enable and sync `AGENTS.md` + `GEMINI.md`
4. keep prompts and instructions narrow, explicit, and command-shaped

What Kin should optimize for:

- a Gemini-specific guidance file that strongly favors precise Kin commands
- settings examples for `~/.gemini/settings.json`
- validation-aware guidance, since Gemini has been less reliable on correctness-sensitive tasks

## What Kin Still Does Not Do Automatically

These are still open follow-ups:

- edit assistant global config files automatically
- install Claude hooks automatically
- install Codex skills automatically
- install Gemini settings automatically
- verify MCP connectivity against the user's real external CLI config
- tailor context packs by assistant strengths / weaknesses

That is deliberate for now. Repo-local setup is low-risk; mutating user-global
assistant config should stay explicit until the flows are better proven.

## Recommended Next Iteration

1. Add assistant-specific config snippet generation under `.kin/docs/assistant-config/`
   so Kin can emit ready-to-paste:
   - Claude `.mcp.json`
   - Codex config snippets
   - Gemini settings snippets
2. Extend `kin assistant doctor` to detect:
   - missing assistant-specific repo docs
   - missing MCP install command completion hints
   - whether a repo is using fallback CLI-only mode
3. Add assistant-specific context-pack strategies in `kin context`, especially
   for broader tracing tasks where Kin currently underperforms Git-style search.

## Long-Term Direction

The likely end-state is not just "make existing agents tolerate Kin."

Long term, Kin should either:

- ship a stronger open-source Kin-first agent shell around an existing CLI, or
- fork one of the open-source CLIs and optimize it for:
  - entity-first search
  - Kin-native context packs
  - semantic review / verify loops
  - intent registration and traffic awareness

That is later work. The near-term goal is a reliable compatibility layer that
makes current assistants succeed in Kin repos without retraining them from
scratch.
