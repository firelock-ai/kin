# Hosted daemon start requirements

A hosted `kin-daemon` needs more configuration than a local one, and the list has grown with every
release. `kin-daemon --compat-json` now declares it, so a deployment can read what an image needs
straight off the image instead of keeping a list in sync by hand.

Run it against any build:

```bash
kin-daemon --compat-json | jq .hosted_start_requirements
```

## What the block says

```json
{
  "schema": "kin.daemon.hosted-start.v1",
  "features": { "gcs": true, "firestore": true },
  "requirements": [
    {
      "name": "GOOGLE_CLOUD_PROJECT",
      "kind": "env",
      "required": true,
      "introduced_in": "0.6.2",
      "absence": "readiness-closed",
      "required_but_unenforced": false,
      "consequence": "the daemon binds, loads the graph, and holds /readiness at 503 ...",
      "refusals": [
        { "stage": "spine", "message": "GOOGLE_CLOUD_PROJECT is required for hosted durable spine" }
      ]
    }
  ]
}
```

`requirements` is sorted by name, so two images diff cleanly.

`features` reports the cargo features the binary was built with. Both must be true for hosted
service. A build without `firestore` refuses the durable spine whatever the environment holds,
because it cannot compare-and-swap a cursor-bound head, and no amount of configuration fixes that.

`absence` is the field to read first. It has three values.

- `refuses-to-start` means the process exits during startup and prints the refusal on stderr.
  Nothing serves, and the reason is in the pod's logs.
- `readiness-closed` means the process starts, binds, loads the graph, and then holds `/readiness`
  at 503 for as long as it runs. Liveness stays green. Everything except the readiness gate reads
  this pod as healthy, which is why it gets its own value rather than being folded into "required".
- `silent` means nothing refuses. The daemon takes a default and runs. Paired with `required: true`
  this is the class to grade hardest, because the configuration is the only thing holding the
  invariant and the binary will not tell anyone it is missing. `required_but_unenforced` is that
  pair, precomputed.

`refusals` carries the verbatim message each stage prints, so an operator can grep a log for the
exact string and a deployment can show it before applying a change.

`introduced_in` is the first `kin` release whose hosted path refuses without the requirement. It is
a historical record the running binary cannot measure, so treat it as provenance for a version
floor rather than as something the image proved. The binary does check that it is a well-formed
version no later than itself.

## Where the list comes from

`crates/kin-daemon/src/hosted_start.rs` is the single table. Every refusal site reads its message
from that table rather than spelling it again, so the declaration and the refusal cannot drift.
Three tests hold the seam, and they fail in opposite directions:

- `the_hosted_start_path_reads_no_environment_of_its_own` scans the two enforcing functions and
  fails if either reads the environment outside the registry, which catches a requirement added
  without a declaration.
- `every_declared_bind_requirement_refuses_startup` runs the real start path once per declared
  bind requirement, with that one value removed, and fails if the declared refusal does not appear.
  That catches a declaration nothing enforces.
- `every_declared_spine_requirement_closes_the_hosted_contract` does the same for the spine stage.

## Why it exists

Every hosted daemon release so far has added a start requirement, and each one reached production
as a rollback rather than as a diff. A deployment cannot read a requirement out of an image, so the
env list was typed by hand after the last outage and was always one release behind the binary it
configured.

The central `KIN_*` environment registry cannot answer this either. It covers `KIN_*` names only,
and `GOOGLE_CLOUD_PROJECT`, whose absence produced the 2026-09-02 rollback, is not one of those.

The consumer is kin-infra. `scripts/hosted-daemon-images.py record` already runs `--version` and
`--compat-json` against an image and records the verbatim output, and this block is what lets that
evidence grade a config rather than only name a version.
