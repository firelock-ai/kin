# Request context accounting

The native run admits the complete chat request before generation, including the
system prompt, history, tool-call/result messages, and every offered tool schema.
It sends an output limit bounded by the admitted answer reserve. Generic providers
use a byte heuristic, explicitly recorded as `exact: false`; this is not a
universal tokenizer bound.

For a llama.cpp server whose rendered-template/tokenizer contract has been
calibrated for the selected model, opt in with:

```sh
KIN_AGENT_CONTEXT_ACCOUNTING=llama_cpp kin agent run ...
```

Set `KIN_AGENT_CONTEXT_ACCOUNTING=heuristic`, or leave it unset, for the generic
path. Invalid values fail explicitly. Rust callers can select
`run_with_accounting(config, RequestAccounting::LlamaCpp)` without changing the
process environment. `run_with_options(config, RunOptions { accounting,
output_reserve_tokens: Some(32768) })` also selects a positive output reserve.
Existing `ProviderConfig`, `run`, and direct completion
method signatures remain available; admission and output limits apply to the run
loop, while direct provider completion methods retain their previous behavior.

The parsed hostname `api.openai.com` selects `max_completion_tokens`, which
OpenAI documents as including visible output and reasoning tokens. Other hosts
retain `max_tokens`, including local llama.cpp endpoints; model names do not
select the dialect. For a gateway, explicitly set
`KIN_AGENT_OUTPUT_TOKEN_PARAMETER=max_completion_tokens` or `max_tokens` to
match its protocol. This does not autodetect arbitrary proxies. Invalid values
fail before run I/O. Only the selected field is sent, and the same field is
retained through recounts and reported-usage validation. Initialization and
admission records include `output_token_parameter`; their existing `max_tokens`
field denotes the numeric bound regardless of the wire field. See the
[OpenAI Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).

The opt-in mode sends the same prepared body to `/apply-template` and generation.
It tokenizes the returned text through `/tokenize` with `add_special=false`,
`parse_special=true`, and `with_pieces=false`. The selected contract treats special
tokens as already represented in the rendered prompt. The retained synthetic
Qwen3.6/llama.cpp b10930 fixture checks this wiring; it does not establish that
every server, template, multimodal prompt, or model uses that contract. Opt-in
exactness refers to this template/tokenizer contract, not to arbitrary compatible
endpoints. Reported generation prompt usage that disagrees with the admitted
count is an error, as is reported output usage above the requested bound. Missing
usage cannot verify server enforcement of the bound or the count after generation.
Rejected completions retain their reported usage in the result totals and failure
trace, because generation already occurred. Their content and tool calls are not
accepted or dispatched; the failure remains non-exact and not admitted.

Only HTTP 404, 405, or 501 from a counting route permits fallback, and its reason
is recorded. Transport failures, server errors, malformed responses, and invalid
token arrays stop admission; they do not silently become exact or heuristic
success. Each admission appears in `kin-trace.jsonl`; the result retains
`kin_agent.context.last_request_accounting`, including method, count, output bound,
contract, fallback reason, and admission decision. Initialization records the
selected mode. Failed accounting is explicitly marked non-exact and not admitted.

A forced final answer offers no tools. Its complete body is counted separately;
when only a shorter output fits, the body with the reduced bound is counted again.
It must stabilize within three admission attempts or stop explicitly. No zero-room
final request is sent. Counting and generation share the run deadline, and the
counting pair has a five-second ceiling within that deadline. Existing MCP session
and tool timeout behavior is unchanged.

The default answer reserve remains one eighth of the window, clamped to
1,024–8,192 tokens. To use a larger reasoning/output budget, set
`KIN_AGENT_OUTPUT_RESERVE_TOKENS=32768` (or use `RunOptions`). An override must be a
positive integer strictly below the configured context window; malformed, zero,
and out-of-window values fail before run I/O. The selected reserve is recorded
in the initialization transcript, result context, admission events, and actual
output-limit field. A reserve is a budget choice, not proof of model capability. The
client can request an output bound and reject reported
violations, but cannot force an arbitrary server to honor the protocol.
