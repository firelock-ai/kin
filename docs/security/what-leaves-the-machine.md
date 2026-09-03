# What Leaves the Machine

This document enumerates every network exit in the Kin CLI, the repo daemon, and the
bundled MCP launcher, and states what each one carries. It is the outbound companion to
the [threat model](./threat-model.md), which covers what can reach the daemon, and to
[signing-and-update-trust.md](./signing-and-update-trust.md), which covers the trust
chain a downloaded release carries.

The short version: in the default configuration, your source code, the graph built from
it, and every query you run stay on the machine. The exits below are the complete list,
and each is either a download of a public artifact or a surface you explicitly
configured. If a claim here stops matching the code, treat that as a bug and report it
per [SECURITY.md](../../SECURITY.md). A source review on 2026-09-03 found three exits this
list did not name and one sentence that overstated the default posture. All four are
corrected below, which is worth saying out loud: a document that claims completeness earns
exactly this kind of audit.

## The Default Posture

Kin is local-first by construction, not by policy. The daemon binds `127.0.0.1`,
authenticates requests with a bearer token, and rejects cross-origin and DNS-rebinding
tricks (see the threat model for the mechanics). Retrieval, search, context, trace, and
review all execute against the local graph over loopback. Two surfaces serialize
repository content into an outbound request, a remote embedding provider and
`kin agent run`, and neither can happen until you configure it: one needs
`KIN_EMBED_PROVIDER` set away from `local`, the other needs an endpoint passed on the
command line.

## Every Network Exit

**Release acquisition.** The npm launcher (`@kinlab/kin`) downloads the matching release
archive and its checksums from GitHub releases
(`github.com/firelock-ai/kin/releases/download`) on demand, verifies them, and caches
the binaries. `KIN_MCP_RELEASE_BASE_URL` points it at a mirror if you host one, and must
be https or a loopback address. The request carries nothing but the fetch itself. The
checksum comes from the same base URL as the archive, which is covered in
[signing-and-update-trust.md](./signing-and-update-trust.md); that document also lists
what the shell installer writes outside its own prefix.

**The update surface.** `kin update` reads release metadata from
`api.github.com/repos/firelock-ai/kin` and downloads checksum-verified assets from the
same GitHub releases. It runs when you invoke it, and the policy you record with
`kin update --set-policy` decides whether an available update may interrupt you.
Requests carry the version ask and nothing else; no repository data is attached.

**Embedding model weights.** The default embedding provider is `local`: embedding and
reranking run in-process on your hardware. The first time the embedder needs a model it
does not already hold, it fetches the weights for `KIN_EMBED_MODEL_ID` (default
`nomic-ai/nomic-embed-text-v1.5`, about 523 MB) from `huggingface.co` into the standard
`hf_hub` cache. That cache is the home-directory root, `~/.cache/huggingface/hub`: the
embedder builds its hub client with `hf_hub`'s default constructor, which does not read
`HF_HOME`, so setting that variable relocates neither the download nor the lookup. After
the fetch, inference is fully local. The download sends nothing outbound but the fetch
itself; entity text never rides along.

**Hosted login and remote surfaces (opt-in).** `kin auth login` speaks to the host you
name (default `https://kinlab.ai`), and the credential it stores is sent only to that
host. There are three storage tiers, tried in this order
(`crates/kin-cli/src/commands/auth.rs`, `store_credential`): the OS keyring; an
`age`-encrypted file when `KINLAB_AUTH_PASSPHRASE` is set; and, where neither is
available, plaintext JSON carrying the bearer token, your account email and your display
name. The third tier is the one to know about. It exists so a login can complete on a
headless host with no keyring, which is where it fires most often. The file is created
0600 inside a 0700 directory, and `kin auth login` prints a warning on stderr naming the
file and the tier when it takes it. Set `KINLAB_AUTH_PASSPHRASE` before logging in to get
the encrypted tier instead. The remote command families (`remote`, `publish`, and the
other hosted surfaces) send exactly what the command says they send, to the remote you
configured, and nothing runs against a remote you never set up.

**Remote embedding providers (opt-in).** Setting `KIN_EMBED_PROVIDER` to an
OpenAI-compatible provider sends entity text to the endpoint you configure, because that
is what remote embedding is. The default is `local`, and nothing selects a remote
provider on its own.

**Agent runs against a model endpoint (opt-in).** `kin agent run --base-url <URL>` posts
repository-derived text to the OpenAI-compatible endpoint you name. The endpoint is a
required argument, so there is no default and no host to be surprised by, but the content
is worth stating plainly: the run drives Kin's own MCP tools and pushes every tool result
back into the conversation as a message (`crates/kin-agent/src/run.rs`, the `"role":
"tool"` push), so graph answers and entity source ride along to that endpoint. Together
with remote embedding this is the second configuration in which source-derived text
leaves the machine, and the sentence that used to call remote embedding the only one was
wrong.

**Language-server install (opt-in).** `kin doctor --fix --install-language-servers`
downloads rust-analyzer's own release binary from `github.com/rust-lang/rust-analyzer`
(`crates/kin-cli/src/commands/language_server_release.rs`, `RUST_ANALYZER_RELEASE`). The
release tag, the asset name, the SHA-256 and the byte size are all pinned in the source,
the digest is checked before anything is installed, and the base-URL override is honoured
only alongside a digest override. The request carries nothing but the fetch.

**A reachability probe in `kin doctor`.** When the embedding model is not in the cache and
nothing is blocking a fetch, `kin doctor` opens a TCP connection to `huggingface.co:443`
and closes it, so it can tell "this host has no route to the weights" apart from "the
weights are still downloading" (`crates/kin-cli/src/commands/health.rs`,
`model_host_reachable`). `HF_ENDPOINT` changes the host it probes. It is a connect and a
close rather than an HTTP request, and it carries no repository data. A machine that
already holds the model is never probed.

**Telemetry: none.** Kin uploads no telemetry. The opt-in `locate` telemetry described
in [PRIVACY.md](../../PRIVACY.md) writes to a local spool under `.kin/telemetry/` and
stays there.

## What Never Leaves, In the Default Configuration

Source code. Graph entities, edges, and history. Embeddings and the vector index.
Queries and their results. The telemetry spool. Credentials, beyond the single host you
chose to log into. Two opt-in surfaces move source-derived text once you turn them on,
and only then: a remote embedding provider, and `kin agent run` against an endpoint you
name.

## Hosted Deployments

A daemon deployed behind the hosted registry can be configured with
`KIN_REGISTRY_NPM_AUTH_URL` to validate publish tokens against that registry's
introspection endpoint. The variable is unset on a workstation, and with it unset the
code path does not exist at runtime.

## Checking the Claim

Each exit above is owned by a small number of files: the launcher's fetch lives in
`packages/kin-mcp/src/index.js`, the update surface in
`crates/kin-cli/src/commands/update.rs`, weight acquisition in kin-db's `embed` module,
and the hosted client surfaces in `crates/kin-cli/src/commands/` beside the commands
that use them. The daemon's own HTTP clients target loopback. Grep for the HTTP client
constructors and you will find the same list; if you find one this document does not
name, that is a documentation bug and we want the report.
