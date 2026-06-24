# Privacy

Kin is local-first. The semantic graph that Kin builds from your repository —
entities, relations, snapshots, search and vector indexes — is stored on your
own machine under the repository's `.kin/` directory. Running Kin does not send
your code, your queries, or usage analytics to Firelock or any third party.

This document describes the data Kin handles and the one optional, local-only
telemetry feature that exists today. It covers the `kin` repository (the CLI,
daemon, and MCP server). Hosted services such as KinLab are separate products
with their own privacy terms.

## What Kin Collects By Default

By default, **nothing leaves your machine.**

- There is no usage analytics, crash reporting, or "phone-home" behavior. Kin
  does not contain a Segment, Sentry, PostHog, Amplitude, or similar client,
  and it does not POST events to a Firelock-operated endpoint.
- The daemon binds to loopback (`127.0.0.1`) by default and serves only local
  clients. See [Daemon and Network Behavior](#daemon-and-network-behavior).
- Operations you explicitly invoke may use the network because that is their
  purpose — for example, fetching dependencies or publishing to a remote. Those
  are user-initiated actions, not background collection.

## Locate Telemetry (Opt-In, Local-Only)

Kin includes one optional telemetry feature, scoped to the `kin locate`
command, to help you understand and tune retrieval quality. It is **disabled by
default** and, when disabled, is a complete no-op: no telemetry directory is
created and `kin locate` behaves byte-for-byte as if the feature did not exist.

When enabled, each `kin locate` query appends a single JSON line to a local
spool file. **Nothing is ever uploaded.** No network connection and no daemon
are involved in writing telemetry — it is a plain local file append.

### Enabling It

Telemetry turns on through either of two opt-in signals:

- **Environment variable** — set `KIN_LOCATE_TELEMETRY` to a truthy value
  (`1`, `true`, `yes`, or `on`).
- **Consent marker file** — create the file `.kin/telemetry/consent` inside the
  repository.

The environment variable takes precedence when it is decisive: setting
`KIN_LOCATE_TELEMETRY=0` (or `false`/`no`/`off`) forces telemetry **off** even
if the consent marker file is present. When the environment variable is unset or
not decisive, the presence of the consent marker governs. With neither signal,
telemetry is off.

The first time telemetry actually records an event in a process, Kin prints a
one-time notice to stderr stating that telemetry is on, what it records, where
it is stored, and how to disable and purge it.

### What Is Recorded

Each event is a `locate_query` record containing:

- a schema version and the event timestamp (Unix milliseconds, UTC);
- the **query text** you passed to `kin locate`;
- the requested result limit (`max_files`);
- the **ranked results** — for each: file path, rank, score, the scoring
  signals that fired, and the top entity attributed to that file;
- when you run `kin locate --explain`, the scoring track and the **funnel** of
  pruned candidates (path, score, and the reason each was pruned).

Because the query text and the matched file paths and entity names are recorded,
treat the spool as you would your source: it can contain identifiers from your
codebase. It stays local, but it is readable by anything that can read your
repository.

### Where It Is Stored

Events are written as append-only [JSON Lines](https://jsonlines.org/) to
day-bucketed files under the repository's `.kin/telemetry/` directory, named
`locate-YYYY-MM-DD.jsonl` (UTC date). Writing telemetry is best-effort: if a
write fails, Kin logs it at debug level and the `kin locate` result is
unaffected.

### Disabling It

- Delete the consent marker: `rm .kin/telemetry/consent`, and/or
- Set `KIN_LOCATE_TELEMETRY=0` in your environment.

### Purging Collected Data

Telemetry lives entirely in one directory, so you can purge it by deleting that
directory:

```sh
rm -rf .kin/telemetry/
```

This removes both the recorded events and the consent marker. A dedicated
`kin telemetry purge` subcommand is planned to make this a first-class
operation; until it ships, deleting the directory is the supported way to purge.

## Daemon and Network Behavior

The Kin daemon is a local process. By default it binds to loopback
(`127.0.0.1`) and is reachable only from your own machine; it does not transmit
your repository contents or queries anywhere. Binding the daemon to a
non-loopback address is refused unless an authentication token is configured, so
the daemon is not exposed off-host by accident. See
[docs/security/threat-model.md](docs/security/threat-model.md) for the full
daemon trust boundary.

## Hosted Services

KinLab and any other hosted Kin services are separate products. When you choose
to use a hosted service — for example to publish or collaborate — data you send
to it is governed by that service's own terms, not by this document. The `kin`
CLI, daemon, and MCP server described here do not enroll you in any hosted
service on their own.

## Questions

If something about Kin's data handling is unclear or appears to contradict this
document, please open an issue. For anything you believe is a security or
privacy vulnerability, follow the private process in [SECURITY.md](SECURITY.md)
instead of filing a public issue.
