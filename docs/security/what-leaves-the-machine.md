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
per [SECURITY.md](../../SECURITY.md).

## The Default Posture

Kin is local-first by construction, not by policy. The daemon binds `127.0.0.1`,
authenticates requests with a bearer token, and rejects cross-origin and DNS-rebinding
tricks (see the threat model for the mechanics). Retrieval, search, context, trace, and
review all execute against the local graph over loopback. No code path serializes
repository content into an outbound request unless you configure one of the two opt-in
surfaces named below, and both are off until you turn them on.

## Every Network Exit

**Release acquisition.** The npm launcher (`@kinlab/kin`) downloads the matching release
archive and its checksums from GitHub releases
(`github.com/firelock-ai/kin/releases/download`) on demand, verifies them, and caches
the binaries. `KIN_MCP_RELEASE_BASE_URL` points it at a mirror if you host one. The
request carries nothing but the fetch itself.

**The update surface.** `kin update` reads release metadata from
`api.github.com/repos/firelock-ai/kin` and downloads checksum-verified assets from the
same GitHub releases. It runs when you invoke it, and the policy you record with
`kin update --set-policy` decides whether an available update may interrupt you.
Requests carry the version ask and nothing else; no repository data is attached.

**Embedding model weights.** The default embedding provider is `local`: embedding and
reranking run in-process on your hardware. The first time the embedder needs a model it
does not already hold, it fetches the weights for `KIN_EMBED_MODEL_ID` (default
`nomic-ai/nomic-embed-text-v1.5`) from Hugging Face through the standard `hf_hub` cache,
which honors `HF_HOME`. After that fetch, inference is fully local. The download sends
nothing outbound but the fetch itself; entity text never rides along.

**Hosted login and remote surfaces (opt-in).** `kin auth login` speaks to the host you
name (default `https://kinlab.ai`). Credentials are stored in the OS keyring, or in an
`age`-encrypted file where no keyring exists, and are sent only to the host you logged
into. The remote command families (`remote`, `publish`, and the other hosted surfaces)
send exactly what the command says they send, to the remote you configured, and nothing
runs against a remote you never set up.

**Remote embedding providers (opt-in).** Setting `KIN_EMBED_PROVIDER` to an
OpenAI-compatible provider sends entity text to the endpoint you configure, because that
is what remote embedding is. This is the one configuration in which source-derived text
leaves the machine outside the hosted remote surfaces. The default is `local`, and
nothing selects a remote provider on its own.

**Telemetry: none.** Kin uploads no telemetry. The opt-in `locate` telemetry described
in [PRIVACY.md](../../PRIVACY.md) writes to a local spool under `.kin/telemetry/` and
stays there.

## What Never Leaves, In the Default Configuration

Source code. Graph entities, edges, and history. Embeddings and the vector index.
Queries and their results. The telemetry spool. Credentials, beyond the single host you
chose to log into.

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
