<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Firelock, LLC
-->

# Publishing to the Kin Cargo and OCI Registries

The Kin daemon serves Cargo and OCI registries (the `kin-registry` crate,
mounted by `kin-daemon`). **Publishing and other mutations require
authentication; reads remain open.** Cargo and OCI use separate write
credentials so one ecosystem's publisher cannot mutate the other.

- Read endpoints — `config.json`, the sparse index, and `dl/{name}/{version}`
  downloads — never check a token, so `cargo` can fetch dependencies without
  credentials.
- The write endpoint — `POST /registry/cargo/api/v1/crates/publish` — requires a
  bearer token that matches the daemon's configured secret.
- OCI `POST`, `PUT`, and `DELETE` routes require the OCI bearer token; OCI
  `GET` and `HEAD` routes remain public for pulls and discovery.

## Daemon configuration (fail-closed)

The daemon reads independent publish secrets from the environment variables:

```
KIN_REGISTRY_CARGO_TOKEN=<secret>
KIN_REGISTRY_OCI_WRITE_TOKEN=<different-secret>
```

These populate `CargoRegistryState.publish_token` and
`OciRegistryState.write_token`, respectively. The behavior is **fail-closed**:

- If either variable is **unset or empty**, that ecosystem's mutations are
  rejected. A misconfigured deployment cannot silently fall open.
- If it is set, a publish request is accepted only when its
  `Authorization: Bearer <token>` header carries the exact same value.
- The Cargo credential never authorizes an OCI mutation (or vice versa).

### Production deployment action required

The production GKE deployment must set both variables:

- project: `kin-ecosystem`
- namespace: `kin`
- deployment: `kin-daemon`

Because each registry fails closed, its writes are disabled until the matching
secret is added to the `kin-daemon` deployment and the daemon is redeployed.
Use distinct Kubernetes Secret keys for Cargo and OCI.

> Ephemeral store note: the registry's blob/manifest store is currently backed by
> the daemon pod's ephemeral `emptyDir`. A pod restart loses published crates, so
> they must be re-seeded by re-publishing through the same authenticated paths
> below. Persisting that store is a separate follow-up.

## Publisher authentication

Every publisher sends:

```
Authorization: Bearer <token>
```

Cargo publishers must match the daemon's `KIN_REGISTRY_CARGO_TOKEN`. OCI clients
must instead match `KIN_REGISTRY_OCI_WRITE_TOKEN`. There are two supported Cargo
publishing paths, both of which send this header.

### 1. `kin publish` CLI

`kin publish` (see `crates/kin-cli/src/commands/publish.rs`) reads the token from
the environment, trying in order:

1. `KINLAB_CARGO_TOKEN`
2. `KIN_REGISTRY_CARGO_TOKEN`

The first non-empty value is sent as the bearer token. If neither is set, the CLI
prints a warning to stderr —

```
warning: no KINLAB_CARGO_TOKEN set; publish will be rejected by an authenticated registry
```

— and posts without the header, which an authenticated registry rejects.

### 2. Per-repo `scripts/publish-kinlab-crates.sh`

The release scripts in `kin-db` and `kin-vfs`
(`scripts/publish-kinlab-crates.sh`) read:

```
registry_token="${KINLAB_CARGO_TOKEN:-${KINLAB_TOKEN:-}}"
```

and attach `authorization: Bearer ${registry_token}` to the upload. These run in
CI on `v*.*.*` release tags, wired through:

- `KINLAB_CARGO_TOKEN` — from the `KINLAB_CARGO_TOKEN` CI secret
- `KINLAB_CARGO_REGISTRY_URL` — from the `KINLAB_CARGO_REGISTRY_URL` CI variable

If the token is empty the scripts omit the header and the publish is rejected by
the now-fail-closed registry (surfaced as a non-2xx HTTP error).

## Summary contract

| Side | Variable | Effect when unset |
| --- | --- | --- |
| Daemon | `KIN_REGISTRY_CARGO_TOKEN` | Cargo mutations disabled (fail-closed); reads still work |
| Daemon | `KIN_REGISTRY_OCI_WRITE_TOKEN` | OCI mutations disabled (fail-closed); reads still work |
| `kin publish` | `KINLAB_CARGO_TOKEN`, else `KIN_REGISTRY_CARGO_TOKEN` | Warns; publish rejected by registry |
| `publish-kinlab-crates.sh` | `KINLAB_CARGO_TOKEN` (or `KINLAB_TOKEN`) | No header; publish rejected by registry |

The sender's token must match the credential for the ecosystem it is mutating.
