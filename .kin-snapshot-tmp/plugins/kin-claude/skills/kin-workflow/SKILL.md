---
name: kin-workflow
description: Kin semantic code navigation workflow. Use when navigating code, tracing functions, searching for symbols, understanding code flow, or answering questions about a codebase that has kin installed. Activates when kin CLI is available.
user-invocable: false
---

# Kin Semantic Code Navigation

This codebase has `kin` — a semantic code navigation tool that finds entities and their source in one command, replacing multi-step grep/find/read workflows.

## Workflow (follow this order)

1. **Start with `kin trace <ExactName> --compact`** for any named symbol or file target.
   - This is your primary entry point. It returns the entity definition, source body, and nearby symbols.
   - Use exact names: `ZodType`, `safeParse`, `Router::new`, not broad patterns.

2. **Read the traced file directly** if you need more local detail after a trace.
   - The trace output tells you the file path. Read that file for surrounding context.
   - This is usually faster than another kin command.

3. **Use `kin search <ExactName> --show-body --limit 5`** only if trace is insufficient.
   - Search is for when you know a name but trace didn't find it (e.g., it's a type alias, not a function).
   - Keep queries exact and `--limit 5` or less.
   - OR-search: `kin search "save|load|persist" --show-body` for a few related names.

4. **Use `kin overview --compact`** only for broad architecture questions ("what modules exist?").
   - Skip this for focused symbol-level tasks.

## Termination Rule

**After 2-3 kin trace commands, you have enough context to answer. Stop tracing and synthesize your answer.** Do not chain more than 3 kin commands unless the task explicitly requires tracing a multi-hop call chain. The goal is efficiency: get in, get the answer, get out.

## Anti-patterns (avoid these)

- Chaining 5+ `kin trace` calls on related symbols — you already have the answer after 2-3.
- Using `kin search` with broad patterns like `parse` or `run` — too noisy.
- Running `kin overview` before `kin trace` on a focused task — wastes a round trip.
- Re-tracing the same symbol you already traced — read the file instead.
- Using grep/find for repo-wide discovery when `kin trace` or `kin search` would be faster.
