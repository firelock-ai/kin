# Real Git vs Kin Agent Benchmarks

These benchmarks compare the same task on plain Git workspaces vs Kin-initialized workspaces.
Kin repo prep (`kin init` + baseline `kin commit`) was done before timing so the timings reflect task execution, not first-time setup.

## Tasks

- `snapdocs_sort_helper` on `snapdocs`: Extract newest-first gallery ordering into a reusable helper and cover it with a test.
- `coachai_gameplan_trace` on `CoachAI`: Trace the game-plan generation flow into a structured JSON file.

## Git vs Kin by Agent

### coachai_gameplan_trace / claude

- Git: `151272 ms`, `743802` total tokens, validation `True`
- Kin: `190732 ms`, `0` total tokens, validation `False`
- Comparison caveat: at least one run failed validation or did not emit usable token data.

### coachai_gameplan_trace / codex

- Git: `184292 ms`, `877923` total tokens, validation `True`
- Kin: `231460 ms`, `1078455` total tokens, validation `True`
- Kin delta: `-47168 ms` (-25.59%), `-200532` tokens (-22.84%)

### coachai_gameplan_trace / gemini

- Git: `42194 ms`, `120920` total tokens, validation `False`
- Kin: `82663 ms`, `432927` total tokens, validation `False`
- Comparison caveat: at least one run failed validation or did not emit usable token data.

### snapdocs_sort_helper / claude

- Git: `253406 ms`, `1393534` total tokens, validation `True`
- Kin: `209912 ms`, `1403840` total tokens, validation `True`
- Kin delta: `43494 ms` (17.16%), `-10306` tokens (-0.74%)

### snapdocs_sort_helper / codex

- Git: `205362 ms`, `669418` total tokens, validation `True`
- Kin: `208407 ms`, `569487` total tokens, validation `True`
- Kin delta: `-3045 ms` (-1.48%), `99931` tokens (14.93%)

### snapdocs_sort_helper / gemini

- Git: `193209 ms`, `779047` total tokens, validation `True`
- Kin: `145679 ms`, `402600` total tokens, validation `False`
- Comparison caveat: at least one run failed validation or did not emit usable token data.

## Raw Runs

### coachai_gameplan_trace / claude / git

- Repo: `CoachAI`
- Elapsed: `151272 ms`
- Tokens: `736820 in / 6982 out / 743802 total`
- Validation: `True`
- Note: JSON flow trace contains the expected UI, API, prompt, and persistence files
- Model: `claude-opus-4-6`
- Cost: `$0.8731`
- Tool calls: `0`
- Files touched: unavailable
- Kin commands used: `none`

### coachai_gameplan_trace / claude / kin

- Repo: `CoachAI`
- Elapsed: `190732 ms`
- Tokens: `0 in / 0 out / 0 total`
- Validation: `False`
- Note: agent exited with code -15
- Model: unavailable
- Cost: unavailable from artifact
- Tool calls: `0`
- Files touched: unavailable
- Kin commands used: not reported

### coachai_gameplan_trace / codex / git

- Repo: `CoachAI`
- Elapsed: `184292 ms`
- Tokens: `868799 in / 9124 out / 877923 total`
- Validation: `True`
- Note: JSON flow trace contains the expected UI, API, prompt, and persistence files
- Model: unavailable
- Cost: unavailable from artifact
- Tool calls: `66`
- Files touched: `/private/tmp/kin-real-agent-bench/coachai_gameplan_trace/codex-git/benchmark_gameplan_flow.json`
- Kin commands used: `none`

### coachai_gameplan_trace / codex / kin

- Repo: `CoachAI`
- Elapsed: `231460 ms`
- Tokens: `1067503 in / 10952 out / 1078455 total`
- Validation: `True`
- Note: JSON flow trace contains the expected UI, API, prompt, and persistence files
- Model: unavailable
- Cost: unavailable from artifact
- Tool calls: `70`
- Files touched: `/private/tmp/kin-real-agent-bench/coachai_gameplan_trace/codex-kin/benchmark_gameplan_flow.json`
- Kin commands used: `/Users/troyfortinjr/GitHub/kin/target/debug/kin support, /Users/troyfortinjr/GitHub/kin/target/debug/kin search generateGamePlan, /Users/troyfortinjr/GitHub/kin/target/debug/kin search GAME_PLAN_PROMPT, /Users/troyfortinjr/GitHub/kin/target/debug/kin search upsertGamePlan`

### coachai_gameplan_trace / gemini / git

- Repo: `CoachAI`
- Elapsed: `42194 ms`
- Tokens: `50428 in / 1270 out / 120920 total`
- Validation: `False`
- Note: missing expected flow references: src/app/api/game-plan/route.ts
- Model: `gemini-2.5-flash-lite,gemini-2.5-pro`
- Cost: unavailable from artifact
- Tool calls: `6`
- Files touched: unavailable
- Kin commands used: `none`

### coachai_gameplan_trace / gemini / kin

- Repo: `CoachAI`
- Elapsed: `82663 ms`
- Tokens: `133586 in / 2344 out / 432927 total`
- Validation: `False`
- Note: missing expected flow references: src/app/api/game-plan/route.ts
- Model: `gemini-2.5-flash-lite,gemini-2.5-pro`
- Cost: unavailable from artifact
- Tool calls: `10`
- Files touched: unavailable
- Kin commands used: not reported

### snapdocs_sort_helper / claude / git

- Repo: `snapdocs`
- Elapsed: `253406 ms`
- Tokens: `1381438 in / 12096 out / 1393534 total`
- Validation: `True`
- Note: helper exists in both runtime files and tests; JavaScript parses cleanly
- Model: `claude-opus-4-6`
- Cost: `$1.3178`
- Tool calls: `0`
- Files touched: unavailable
- Kin commands used: `none`

### snapdocs_sort_helper / claude / kin

- Repo: `snapdocs`
- Elapsed: `209912 ms`
- Tokens: `1393303 in / 10537 out / 1403840 total`
- Validation: `True`
- Note: helper exists in both runtime files and tests; JavaScript parses cleanly
- Model: `claude-opus-4-6`
- Cost: `$1.2596`
- Tool calls: `0`
- Files touched: unavailable
- Kin commands used: `kin support, kin search renderGallery, kin search loadDocuments, kin search createGalleryItem`

### snapdocs_sort_helper / codex / git

- Repo: `snapdocs`
- Elapsed: `205362 ms`
- Tokens: `659434 in / 9984 out / 669418 total`
- Validation: `True`
- Note: helper exists in both runtime files and tests; JavaScript parses cleanly
- Model: unavailable
- Cost: unavailable from artifact
- Tool calls: `40`
- Files touched: `/private/tmp/kin-real-agent-bench/snapdocs_sort_helper/codex-git/js/app.js, /private/tmp/kin-real-agent-bench/snapdocs_sort_helper/codex-git/js/app.module.js, /private/tmp/kin-real-agent-bench/snapdocs_sort_helper/codex-git/tests/app.test.js`
- Kin commands used: `none`

### snapdocs_sort_helper / codex / kin

- Repo: `snapdocs`
- Elapsed: `208407 ms`
- Tokens: `559256 in / 10231 out / 569487 total`
- Validation: `True`
- Note: helper exists in both runtime files and tests; JavaScript parses cleanly
- Model: unavailable
- Cost: unavailable from artifact
- Tool calls: `62`
- Files touched: `/private/tmp/kin-real-agent-bench/snapdocs_sort_helper/codex-kin/js/app.module.js, /private/tmp/kin-real-agent-bench/snapdocs_sort_helper/codex-kin/js/app.js, /private/tmp/kin-real-agent-bench/snapdocs_sort_helper/codex-kin/tests/app.test.js`
- Kin commands used: `kin support, kin search renderGallery, kin search loadDocuments, kin search createGalleryItem`

### snapdocs_sort_helper / gemini / git

- Repo: `snapdocs`
- Elapsed: `193209 ms`
- Tokens: `155349 in / 15770 out / 779047 total`
- Validation: `True`
- Note: helper exists in both runtime files and tests; JavaScript parses cleanly
- Model: `gemini-2.5-flash-lite,gemini-2.5-pro`
- Cost: unavailable from artifact
- Tool calls: `27`
- Files touched: unavailable
- Kin commands used: `none`

### snapdocs_sort_helper / gemini / kin

- Repo: `snapdocs`
- Elapsed: `145679 ms`
- Tokens: `64440 in / 5645 out / 402600 total`
- Validation: `False`
- Note: sortDocumentsNewestFirst missing from tests
- Model: `gemini-2.5-flash-lite,gemini-2.5-pro,gemini-2.5-flash`
- Cost: unavailable from artifact
- Tool calls: `17`
- Files touched: unavailable
- Kin commands used: `/Users/troyfortinjr/GitHub/kin/target/debug/kin search renderGallery,/Users/troyfortinjr/GitHub/kin/target/debug/kin search loadDocuments`
