# Privacy Policy

## What Kin collects

Kin can collect **local-only telemetry** about how you use the `locate`
command. This helps us improve result quality.

Telemetry is **off by default**. Nothing is collected unless you explicitly
opt in with `kin telemetry consent`.

### What is recorded (when you opt in)

For each `kin locate` query:

| Field | Example |
| ----- | ------- |
| Query text | `"where is the HTTP handler"` |
| Timestamp (UTC, milliseconds) | `1719187200000` |
| Result ranking (file paths + scores + signals) | `[{path: "src/api.rs", score: 0.92, ...}]` |
| Scoring track used | `"BroadBlend"` |
| Number of results requested | `10` |
| Funnel candidates pruned (paths + scores) | `[{path: "src/x.rs", ...}]` |

### What is never recorded

- File contents
- Entity payloads or graph data
- Diff or change data
- Authentication tokens or secrets
- Any data from commands other than `locate`

## Where data goes

All telemetry is written **locally only** to `.kin/telemetry/*.jsonl` in your
repository. No data is uploaded to Firelock or any third party in this
version. A future opt-in upload feature (described in the roadmap) will
require a separate, explicit consent step.

## What leaves the machine

Telemetry is one slice of the network story. The complete enumeration of every network
exit in the CLI, the daemon, and the launcher, and of what stays local by construction,
lives in
[docs/security/what-leaves-the-machine.md](docs/security/what-leaves-the-machine.md).

## How to manage your data

```sh
kin telemetry status   # show what is on/off and how much data is stored
kin telemetry consent  # opt in to local telemetry collection
kin telemetry revoke   # revoke consent (new queries stop being recorded)
kin telemetry purge    # delete all local spool files
```

You can also delete the spool directory directly:

```sh
rm -rf .kin/telemetry/
```

And you can override consent per-session with an environment variable:

```sh
KIN_LOCATE_TELEMETRY=1   kin locate "..."   # force on
KIN_LOCATE_TELEMETRY=0   kin locate "..."   # force off
```

## Contact

For privacy questions or deletion requests, contact
[security@firelock.ai](mailto:security@firelock.ai).
