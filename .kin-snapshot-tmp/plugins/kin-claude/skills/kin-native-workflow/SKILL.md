---
name: kin-native-workflow
description: Kin native mode workflow — use when KIN_CONTENT_MODE=deny or KIN_DISCOVERY_MODE=deny is set, or when instructed to stay on Kin surfaces only. Replaces direct file reads with kin trace and kin context.
user-invocable: false
---

# Kin Native Mode Navigation

This codebase runs in **Kin native mode**: direct file reads and filesystem discovery are restricted. All code navigation goes through Kin's semantic API.

## Workflow (strict order)

1. **`kin trace <ExactName> --compact`** — your primary and often only tool.
   - Returns entity definition, source body, file location, and nearby symbols.
   - Use exact names only: `safeParse`, `Router::new`, `ZodType`.

2. **`kin context <ExactName>`** — for broader module context after a trace.
   - Use this only if the trace result references entities you need to understand.
   - Do not re-context the same symbol you just traced.

3. **`kin search <ExactName> --show-body --limit 5`** — last resort.
   - Only if trace and context are insufficient.
   - Exact names only. No broad patterns.

## Termination Rule

**After 2-3 kin commands, you have enough context. Stop and answer immediately.** The trace output contains the source body — you can read the code right there. Do not keep tracing to "make sure" — you already have the answer.

## Restrictions

- **No `cat`, `head`, `tail`, `sed`** — file reads are blocked.
- **No `grep`, `rg`, `find`, `fd`, `ls`, `tree`** — filesystem discovery is blocked.
- **No `Read` tool** — use `kin trace` or `kin context` instead.
- Stay entirely on Kin surfaces. The semantic graph has everything you need.

## Anti-patterns (avoid these)

- Tracing the same symbol twice — you already have it.
- Tracing a parent container after tracing a specific method — wasted work.
- Using `kin search` to re-find something you already traced — redundant.
- More than 3 kin commands total — you're spiraling. Stop and answer.
