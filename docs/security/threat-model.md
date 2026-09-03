# Threat Model: Daemon and Filesystem Projection

This document describes the security model of the parts of Kin that run as
long-lived local processes or interpose on the operating system: the **Kin
daemon** (its graph and coordination control API) and the **filesystem
projection** that serves graph-backed content to ordinary tools. It
describes behavior as it exists today, including the residual risks a shipped
protection does not cover. Where a boundary is owned by another
repository in the ecosystem, that is called out so the authority for the
implementation is unambiguous.

For how to report a suspected vulnerability, see [SECURITY.md](../../SECURITY.md).
For the trust chain a downloaded release carries and how it is verified on
install, see [signing-and-update-trust.md](./signing-and-update-trust.md).

## Scope and Trust Model

Kin's baseline trust boundary is the **local operating-system user account**. Kin
trusts the user it runs as, the integrity of that user's filesystem, and the
OS-level isolation between users and between a user's processes and other users'
processes. A repository's graph, indexes, blobs, and configuration live under the
repository's `.kin/` directory and are protected by ordinary filesystem
permissions.

The following are therefore **in scope** for this document:

- the daemon's network exposure, request authentication, and cross-origin
  defenses;
- the daemon's graph, session, reconcile, and coordination control surfaces;
- the trust boundary of the filesystem projection (library interposition);
- the integrity properties of the content-addressed blob store.

The following are **out of scope** here:

- hosted services such as KinLab, which run under their own operational security
  model;
- an attacker who already has code execution as the same OS user (that is inside
  the trust boundary; see [Residual Risks](#residual-risks-and-hardening) for
  the partial defenses that still apply);
- physical access and full-disk compromise.

## The Kin Daemon

The daemon exposes an HTTP control API used by the CLI, the MCP server, and
editor integrations. Three layers defend it: where it binds, a cross-origin
guard, and an optional bearer token.

### Network binding

By default the daemon binds to loopback (`127.0.0.1`) and is reachable only from
the local host. Binding to a non-loopback address is **refused** unless an
authentication token is configured: the listener setup returns an error
(`KIN_DAEMON_AUTH_TOKEN is required when binding to a non-loopback host`) when
the resolved bind address is not a loopback address and no token is present. This
prevents accidentally exposing an unauthenticated daemon off-host.

### Cross-origin and DNS-rebinding guard

A Host/Origin validation layer runs on **every** request, including the public
package-registry routes. It enforces an allowlist of Host values
(`localhost`, `127.0.0.1`, `::1`, and the configured bind host) and rejects
anything else. A request that omits the `Host` header is rejected on sensitive
routes; only the public liveness routes (`/health`, `/ready`, `/readiness`,
`/spine/health`) remain reachable without a Host so that health-probe tooling is
unaffected.

This is the primary defense against a browser-driven DNS-rebinding attack: a web
page cannot rebind a name to `127.0.0.1` and drive the loopback daemon, because
the rebound request still carries the attacker's Host value and is rejected by
the allowlist. This guard is always active, independent of whether bearer
authentication is enabled.

### Request authentication (bearer token)

The daemon supports a per-install bearer token. On first run it auto-provisions a
random token at `.kin/daemon.token` with owner-only permissions (`0600` on
Unix); local clients read the same file and present it as
`Authorization: Bearer <token>`. The authentication middleware is scoped to the
daemon's own control routes. The package-registry routes (cargo/npm/oci/go) stay
public so that build tooling, which does not send credentials on reads, can fetch
from a token-protected daemon.

Enforcement of the per-install token is **on by default**:

- On first run the daemon provisions the token file and requires it: requests to
  non-public routes without a valid `Authorization: Bearer <token>` header get
  `401`. The CLI (`daemon_client.rs`) and the MCP delegate (`daemon_delegate.rs`,
  and the spine federation client in `handlers/common.rs`) all auto-read
  `.kin/daemon.token` and send it, so a fresh install authenticates out of the
  box with no operator setup.
- `KIN_DAEMON_REQUIRE_TOKEN` is the documented escape hatch: set it to a falsy
  value (`0`, `false`, `no`, or `off`) to run without bearer auth. One example
  is an older local client that predates token support and cannot yet send the
  header. In that state the daemon relies on the loopback bind, the
  Host/Origin guard, and OS-level filesystem and process isolation rather than
  on bearer authentication. An explicit truthy value is equivalent to the default.
- Setting `KIN_DAEMON_AUTH_TOKEN` to an explicit value always takes precedence
  and is always enforced, even while `KIN_DAEMON_REQUIRE_TOKEN` is opted out;
  this is also the token required to bind a non-loopback address.

### The machine-wide supervisor

The supervisor is a second HTTP control plane, one per user rather than one per
repository, and it holds the same policy. It provisions `~/.kin/supervisor.token`
on first run and enforces it by default; `KIN_SUPERVISOR_REQUIRE_TOKEN` set to a
falsy value (`0`, `false`, `no`, `off`) is the escape hatch, and
`KIN_SUPERVISOR_AUTH_TOKEN` is the explicit override that always wins. Only
`/health` and `/readiness` are public. Everything else, including `/repos`,
`/daemons`, `/daemons/register` and `/shutdown`, needs the bearer token, because
unauthenticated those routes name every repository the user has open and let any
local process stop the supervisor for all of them.

The CLI trusts a route the supervisor hands back only when it names loopback. The
supervisor stores whatever endpoint a registration reports, so that value is
another process's claim rather than a fact, and a route naming another host is
refused before any request is sent to it. The same rule governs `KIN_DAEMON_URL`:
the auto-provisioned `<repo>/.kin/daemon.token` is attached only to a loopback
endpoint, and a remote endpoint must be paired with its own
`KIN_DAEMON_AUTH_TOKEN` or the client refuses by name rather than sending a local
credential to a host it cannot vouch for.

### Resulting trust boundary

In its default configuration the daemon's effective trust boundary is **any
process running as the same OS user**: such a process can reach the loopback
daemon and can read the `0600` token file. Cross-user access is blocked by file
permissions, and remote/browser access is blocked by the loopback bind and the
Host/Origin guard. Operators on shared or multi-tenant hosts should raise this
boundary explicitly (see [Residual Risks](#residual-risks-and-hardening)).

## Filesystem Projection (Library Interposition)

Kin's transparent filesystem projection (the `kin-vfs` repository) serves
graph-backed content to unmodified tools by interposing on libc file calls using
the dynamic loader's preload mechanism (`LD_PRELOAD` on Linux,
`DYLD_INSERT_LIBRARIES` on macOS). The projection's implementation and its
detailed security properties are owned by `kin-vfs`; this section states the
trust boundary as it pertains to running Kin. For the shim's re-entrancy and
signal-safety handling specifically, see the `kin-vfs` note
`docs/security/shim-reentrancy-and-signal-safety.md`.

The interposition library is loaded **into the address space of the target
process** and runs with that process's privileges. Two consequences follow:

- **The shim is as trusted as the program it is injected into.** Because it
  intercepts that process's file I/O, a user enabling projection for a tool is
  extending that tool's trust to the projection library. Install the shim only
  from a trusted build, exactly as you would any other code you run.
- **Projection is per-user and per-process.** It is configured through the
  environment of the processes a user launches; it does not grant cross-user
  access and does not run with elevated privilege of its own. Consistent with the
  platform loaders, preload-based interposition is ignored by the OS for
  privileged (for example setuid) binaries, so it cannot be used to inject into a
  more-privileged process.

The daemon-side counterpart of projection, materializing graph-owned files into
a workspace for a session or an exec request, runs within the same-user
daemon trust boundary described above.

Preload interposition is not the only projection surface Kin ships. The macOS
release builds `kin-vfs` with `--features nfs` and the Linux release with
`--features fuse` (`.github/workflows/release.yml`), so `kin mode nfs` and
`kin mode fuse` present the graph through a mount the operating system serves
rather than through a library in one process. A mount is not per-process: the
NFS export in particular authenticates no client, so every account on the
machine can read what it serves for as long as it runs. What that export does
and does not enforce, including the read-only default and where writes are
contained, is owned by `kin-vfs` and stated in its
`docs/security/nfs-export.md`.

## Blob-Store Integrity

Kin stores file and artifact content in a content-addressed blob store (the
`kin-blobs` substrate). A blob's identity **is** the SHA-256 hash of its
contents: blobs are keyed and read by that hash, and workspace snapshots derive a
content hash over their materialized contents. Package artifacts served by the
bundled registries (cargo/npm/oci) likewise carry SHA-256 digests.

Content-addressing gives integrity by construction: changing a single byte of a
blob changes its address, so stored content cannot be silently substituted under
an existing key without producing a hash collision. Where a consumer re-derives
or verifies the address on read, tampering is detectable rather than transparent.
The storage substrate that performs reads and any read-time verification is
`kin-blobs`; this repository consumes it and relies on those integrity
properties.

An attacker with write access to a repository's `.kin/` directory could modify
stored blobs or graph state, but such an attacker already holds same-user
filesystem access, which is inside the trust boundary. Content-addressing limits
that actor to detectable substitution rather than silent tampering wherever
addresses are re-verified.

## Residual Risks and Hardening

- **Shared and multi-tenant hosts.** Bearer authentication is enforced by
  default, but the token file is readable by its owner, so any process running as
  your user can read it and reach the loopback daemon. That is the default
  same-user trust boundary, and a token does not raise it. On hosts where the
  assumption does not hold, set an explicit `KIN_DAEMON_AUTH_TOKEN` that lives
  outside the repository, and never set `KIN_DAEMON_REQUIRE_TOKEN` to a falsy
  value.
- **The escape hatch is real.** A falsy `KIN_DAEMON_REQUIRE_TOKEN` turns bearer
  authentication off for a daemon that then relies on the loopback bind and the
  Host/Origin guard alone. Check the variable before assuming an audited host is
  enforcing the token, since the opt-out survives in whatever shell profile or
  service unit set it.
- **Off-host exposure.** Binding the daemon to a non-loopback address requires a
  token, but exposing it to a network still widens the attack surface
  considerably; treat it as a deliberate, audited deployment choice.

## Reporting

Report suspected vulnerabilities privately through the process described in
[SECURITY.md](../../SECURITY.md). Do not open a public issue for a suspected
vulnerability.
