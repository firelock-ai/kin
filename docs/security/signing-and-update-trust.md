# Release Signing and Update Trust

This document describes the trust chain a downloaded Kin release carries and how
that trust is verified on install, for a reviewer auditing the supply chain. It
describes the release pipeline as it exists in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) and the
installer in [`scripts/install.sh`](../../scripts/install.sh); where a property
is conditional or not yet enforced, that is called out.

For the daemon/projection runtime trust model see
[threat-model.md](./threat-model.md); for vulnerability reporting see
[SECURITY.md](../../SECURITY.md).

## What a Release Contains

A tagged release (`v*.*.*`) builds one archive per platform. Each archive bundles
the `kin` CLI and the mandatory `kin-daemon`, plus the `kin-vfs` projection CLI
and its interposition shim when built. Every archive is published alongside a
per-artifact SHA-256 file:

| Platform | Archive | Checksum |
| --- | --- | --- |
| Linux x86_64 | `kin-linux-x86_64.tar.gz` | `.tar.gz.sha256` |
| Linux aarch64 | `kin-linux-aarch64.tar.gz` | `.tar.gz.sha256` |
| macOS x86_64 | `kin-macos-x86_64.tar.gz` | `.tar.gz.sha256` |
| macOS aarch64 | `kin-macos-aarch64.tar.gz` | `.tar.gz.sha256` |
| Windows x86_64 | `kin-windows-x86_64.zip` | `.zip.sha256` |
| Windows x86_64 | `kin-windows-x86_64.tar.gz` | `.tar.gz.sha256` |

Windows ships the same components in two containers. The zip is the name the
PowerShell installer, the npm launcher, and `kin update` resolve; the tarball is
the name the POSIX installer builds on every platform it supports, including the
MSYS, MINGW, and CYGWIN shells, so piping the documented curl command into a
shell on Windows resolves instead of 404ing. Both are checksummed, attested, and
verified against one content inventory, so they cannot ship different bytes.

A convenience `checksums-sha256.txt` aggregating every per-artifact file is also
attached to the release, but the installer verifies against the per-artifact
`.sha256` file, not the aggregate. Each archive also has a provenance manifest,
and the release includes an aggregate manifest binding the Kin and pinned
`kin-vfs` commits, both lockfile hashes, every archive hash, and every packaged
binary hash. GitHub signs an artifact attestation over the final archives and
aggregate manifest before the prerelease is created.

The Windows archive is a release-blocking target. Native Windows x86_64 support is early. Repository admission works: `kin init` imports a Git repository and publishes graph authority, and graph, lexical, and daemon-backed queries answer natively. Transparent filesystem projection is not shipped on Windows, and the end-to-end install proof does not yet cover MCP or review workflows there, so WSL2 remains the recommended path for the full Kin experience.
The archive carries semantic vector search, and is checksum-protected and
GitHub-attested, but it is not OS-code-signed by this pipeline. Windows VFS
projection is not shipped.

Every tag is first published as a non-latest prerelease. The anonymous install
proof installs all five archives (Linux x86_64/aarch64, macOS x86_64/aarch64,
and Windows x86_64) and verifies the GitHub attestation plus exact
tag/commit/lock provenance. The four Unix legs exercise a fresh repository,
graph search/locate, MCP initialize/list/call, and supported agent configuration
writers. The Windows leg instead requires both `kin init` boundaries to refuse
without publishing a repository, then proves the remaining repository-free CLI
diagnostics and setup writers. The four Unix legs also make the source
file unreadable on raw disk, then require
the installed VFS shim and real Kin daemon to return the exact graph-owned bytes.
That probe also calls `fstat` on stdout before opening the workspace path, which
guards the Linux AArch64 passthrough ABI. The same legs build embeddings and
prove semantic search/locate at complete coverage. Both npm packages are then
published under their final channel through protected npm Trusted Publishing
with short-lived OIDC. Anonymous exact-byte, provenance, and install proof runs
after publication. GitHub Latest is promoted only after both packages pass
every gate.

The protected `release` environment intentionally has no required reviewer.
After the coalescing release PR passes protected-main checks, the repository-
scoped release App automatically creates the authorized version tag at that
exact reviewed commit. The tag policy, main-ancestor check, exact Trusted
Publishing identity, and post-publication proofs then admit and verify every
public release surface without a second manual approval. A typed
`repository_dispatch` is break glass, not the normal release path. GitHub runs
that event from the last commit on the default branch and only when the workflow
exists there; the caller cannot select a branch copy of the release controller.

Both workflows that mint an App token declare the separate `release-tag`
Environment, whose custom deployment policy admits `main` and no other branch.
That boundary is defense in depth: the tag controller forbids
branch-selectable `workflow_dispatch`, accepts only the typed `release_tag`
repository event, validates its authorized actor and exact current-main payload,
and rechecks main immediately before writing the ref. The App credentials must
exist only as Environment secrets; repository and organization secrets are
available to other workflows in scope, so every broader copy must be removed or
rotated away before the release controller is production-ready.

After GitHub stable/latest, public install proof, both npm packages, and GHCR
version/latest all succeed, the release publishes deterministic
`release-promotion.json` plus its checksum and a source-bound GitHub
attestation. This terminal marker is durable release-completion authority when
an Actions run record later expires. Its attested stable run ID preserves
downstream audit linkage without making the mutable Actions API authoritative;
aggregate archive provenance alone is not.

The daemon container is a separate attested subject. The protected tag workflow
builds one exact commit-tagged image in GHCR, verifies its embedded source and
lockfile identity, then passes that digest to a separate attestation-only job.
That job re-resolves the commit tag, refuses digest drift, attaches SLSA
provenance to the immutable digest in GHCR, and self-verifies the repository,
release workflow, source tag, peeled source commit, and hosted-runner identity.
It cannot rebuild the image. Later version-tag promotion reuses that digest
without rebuilding and never writes an implicit `latest` image.
Hosted infrastructure may copy the exact manifest into its private registry,
but that operation is a separately attested promotion, not a second build.

The Homebrew formula and public convenience installers are post-release
promotions, not mutable `main` content. After the complete tag-only Release
workflow succeeds,
[`publish-release-installers.yml`](../../.github/workflows/publish-release-installers.yml)
revalidates the completed run, exact tag and peeled commit, published Latest
release, and both installer hashes. It then uses one short-lived GitHub App
token scoped only to `firelock-ai/homebrew-kin` and `firelock-ai/kin-infra` to
request both downstream updates. The callback waits for each exact correlated
workflow run, verifies the public formula version, URLs, and all four release
checksums, then verifies installer byte parity. It has no cloud credential. The
downstream installer publisher stages immutable objects, generation-CAS
activates `/install`, `/install.ps1`, and `/current.json`, proves all three
public bytes, and restores the previous generations if proof fails.

The callback runs in the `release-followups` GitHub environment, admitted only
from protected `main`. That environment holds `KIN_RELEASE_APP_ID` and
`KIN_RELEASE_APP_PRIVATE_KEY`. The GitHub App must be installed only on
`firelock-ai/homebrew-kin` and
`firelock-ai/kin-infra` with repository Contents write permission, which is the
minimum permission required to create a repository dispatch, plus Actions read
permission so the callback can wait for and verify both exact downstream runs.
The downstream `installer` environment and its dedicated WIF identity remain a
separate cloud authorization boundary. Missing environments, secrets, a
disabled downstream workflow, or a non-successful Release run fail closed and
leave the currently served installer generations unchanged.

The repository variable `RELEASE_FOLLOWUP_READY` must equal `true` before the
callback job is admitted. Leave it unset until the environment, GitHub App,
downstream workflows, bucket versioning, and public readback paths are all
verified; this prevents a merged workflow from creating or using an unprotected
environment during bootstrap.

Public OSS readiness requires exact live byte parity, not merely a safe or
functioning installer. Run
`python3 scripts/verify_installer_parity.py <release-tag>` and require success
before an announcement or public-launch claim. The gate compares both served
scripts with the exact peeled release commit and requires `/current.json` to
bind the same tag, commit, hashes, and GCS generations. Even wording-only drift
in `install.ps1` fails this gate. For the first migration to the atomic
publisher, leave `RELEASE_FOLLOWUP_READY` unset, publish the exact release via
the protected break-glass workflow, prove parity, and only then set
`RELEASE_FOLLOWUP_READY` to `true` for future completed-release callbacks.

## Three Independent Integrity Layers

Kin's release trust rests on three layers that are verified independently:

1. **A SHA-256 checksum** published next to every archive. This is the
   cross-platform integrity check the installer enforces on every platform.
2. **A GitHub artifact attestation** over the final archives and aggregate
   provenance manifest. The release workflow signs it through GitHub OIDC;
   install proof verifies the signer workflow, source tag, source commit, and
   hosted-runner provenance. The convenience installers do not yet perform
   this verification themselves, so users who need the additional supply-chain
   check should run `gh attestation verify <archive> --repo firelock-ai/kin`.
3. **Apple code-signing and notarization** of the macOS binaries. This is an
   OS-level authenticity and integrity check enforced by macOS Gatekeeper, and
   it applies only to the macOS artifacts.

Linux and Windows artifacts rely on the SHA-256 and GitHub-attestation layers;
they are not OS-code-signed by this pipeline today.

## macOS Trust Chain

The macOS legs sign and notarize **before** packaging, so the published tarball
and its SHA-256 cover the already-signed binaries. The chain has three links.

### 1. Developer ID Application signature (hardened runtime)

The signing certificate is imported into a throwaway keychain on the runner from
the `MACOS_CERTIFICATE` / `MACOS_CERTIFICATE_PWD` secrets, then each binary
(`kin`, `kin-daemon`, `kin-vfs`, and the `libkin_vfs_shim.dylib` shim) is signed:

```
codesign --force --options runtime --timestamp --sign "$MACOS_DEVELOPER_ID" "$f"
codesign --verify --strict --verbose=2 "$f"
```

- `--sign "$MACOS_DEVELOPER_ID"` signs with the project's **Developer ID
  Application** identity. This is the identity Gatekeeper checks to attribute the
  binary to a known Apple Developer account.
- `--options runtime` opts the binary into the **hardened runtime**, which
  Apple requires for notarization.
- `--timestamp` embeds a **secure (trusted) timestamp** from Apple's timestamp
  authority, so the signature remains valid after the signing certificate later
  expires.
- The immediate `codesign --verify --strict` re-checks each binary in the same
  job, so a signing failure fails the build rather than shipping an unsigned
  binary under a signed-looking name.

The signing secrets are surfaced as job-level environment so steps can guard on
`env.MACOS_CERTIFICATE != ''`. Tagged releases require the certificate,
password, and Developer ID and fail before packaging when any is absent. A
manual branch workflow may exercise unsigned build plumbing, but the publish job
is tag-only, so that path cannot create a public release.

### 2. Apple notarization

After signing, the macOS binaries are zipped and submitted to Apple's
notarization service:

```
xcrun notarytool submit "$NOTARIZE_ZIP" \
  --apple-id "$APPLE_ID" \
  --password "$APPLE_APP_SPECIFIC_PASSWORD" \
  --team-id "$APPLE_TEAM_ID" \
  --wait --timeout 30m
```

Notarization uploads the signed binaries to Apple, which scans them and, on
success, issues a notarization ticket bound to the binaries' code-signing
identity. The `--wait` makes the job block on the result (capped at 30 minutes so
a stalled Apple queue fails fast rather than burning the runner), and a
notarization rejection fails the job. Tagged releases require either the native
Apple ID credential set or the explicitly selected Linux rcodesign credential
set; missing credentials fail the release.

### 3. Online ticket validation (no stapling)

The released artifacts are bare CLI binaries inside a `.tar.gz`. Apple's
`xcrun stapler` can only staple `.app` bundles, `.dmg`, `.pkg`, and `.xip`, so
the notarization ticket is **not stapled to the artifact**. Instead the ticket
lives on Apple's servers and is validated **online by Gatekeeper on first run**.

Audit consequence: an end user verifying notarization offline (e.g.
`stapler validate`) will not find a stapled ticket on the tarball or the bare
binary. That is expected for this artifact shape, not a signing gap. If a
`.dmg`/`.pkg` installer is added later, the pipeline has a documented place to
add `xcrun stapler staple`.

## Linux Release Posture (static musl)

The Linux core binaries (`kin`, `kin-daemon`) target
`*-unknown-linux-musl` and link **static by default**. A single Linux artifact
per architecture therefore runs across distros, musl (Alpine) and glibc
(Ubuntu/Debian/RHEL) alike, with no OpenSSL or glibc-version coupling. From a
supply-chain standpoint this means the Linux binary does not dynamically pull a
host TLS/crypto library at runtime for its own operation; the musl C toolchain
(`musl-tools`) is installed only to build the static C dependencies (ring,
oniguruma, sqlite, tree-sitter).

The `kin-vfs` shim is the deliberate exception: an `LD_PRELOAD` interposer is
intrinsically libc-specific, so the VFS leg is built against the `gnu` target
(`vfs_target`) so it can preload into the host distro's glibc programs. The
core CLI/daemon remain static-musl regardless.

## Install-Time Verification

The installer (`scripts/install.sh`) refuses to install an unverified download.
Its checksum gate is mandatory and fail-closed:

1. It downloads the archive and its per-artifact `.sha256`. If the checksum file
   cannot be fetched or is empty/malformed, the installer **aborts** ("Refusing
   to install an unverified download").
2. It recomputes the archive's SHA-256 with `shasum -a 256` (or `sha256sum`). If
   neither tool is present it **aborts** rather than skipping verification.
3. It compares the computed hash against the published one and **aborts on
   mismatch** ("The download may be corrupted or tampered with").

Only after the checksum matches does it extract and install. The installer also
asserts `kin-daemon` is present in the archive before moving any files, so a
daemon-less archive aborts cleanly instead of leaving a half-installed
environment.

### Unattended pinned updater contract

An unattended mutating `kin update` requires the complete
`--expect-version`, `--expect-sha`, and `--expect-archive-sha256` tuple. The
version and peeled tag commit select one release, but they do not authenticate
the platform archive bytes. External automation must first verify the exact
platform archive with `gh attestation verify` against
`firelock-ai/kin/.github/workflows/release.yml` and the expected tagged source
commit, require the verified attestation's `sourceRepositoryDigest` to equal
that commit, then hash those verified downloaded bytes and supply that SHA-256
through `--expect-archive-sha256`.

The updater downloads and owns a fresh copy of the platform archive. Before it
opens the install lock or performs local mutation, it hashes those bytes and
compares them with the independently supplied digest. It then validates the
co-published checksum, schema-v2 provenance, and fixed-width static build
identities as defense in depth. The updater has no runtime dependency on `gh`;
attestation verification remains the responsibility of the external automation
supplying the archive digest.

`kin update --check-only` is read-only and does not fetch platform archive
bytes. With the complete pin tuple, it compares the supplied archive digest to
bounded published checksum metadata in addition to version and peeled tag
commit selection. That comparison is selection and drift evidence only; it
does not authenticate archive bytes that check-only never downloaded.

On macOS, the second, independent layer is enforced by the OS at run time:
because the binaries are signed with a Developer ID and notarized, Gatekeeper
validates the signature and (online) the notarization ticket the first time each
binary runs. A tampered macOS binary fails Gatekeeper even if it somehow passed
the checksum step.

### Verifying a download manually

```sh
# Compare the recomputed checksum against the published per-artifact file.
shasum -a 256 -c kin-macos-aarch64.tar.gz.sha256

# macOS: confirm the binary is signed with a Developer ID and accepted.
codesign --verify --strict --verbose=2 ./kin
spctl --assess --type execute --verbose ./kin
```

## Trust Boundaries and Residual Risk

- **CI is in the trusted computing base.** The signing identity and Apple
  credentials are GitHub Actions secrets available to the release workflow. A
  compromise of the release pipeline or its secrets could produce a validly
  signed malicious build. This is the standard trust assumption for
  CI-signed releases.
- **Tagged macOS publication is fail-closed.** Missing signing or notarization
  credentials fail the tagged workflow, and publication cannot proceed. Manual
  branch workflows may build unsigned binaries for diagnostics but cannot
  publish a GitHub release.
- **Linux/Windows have checksum plus workflow-attestation layers.** They do not
  carry an OS code signature from this pipeline, but the release gate verifies
  both the published SHA-256 sidecar and a GitHub artifact attestation pinned to
  this repository, the release workflow, the source tag, and the source commit.
  The installer itself performs the checksum verification; users who want the
  separate authorship/provenance check can run `gh attestation verify`.
- **npm and Homebrew distribution** are downstream of the GitHub release. Both
  public npm packages trust only `firelock-ai/kin`'s `release.yml` in the
  protected `release` environment, and that identity may run `npm publish`
  only through short-lived OIDC. Traditional npm tokens remain disabled. Each
  publish helper packs the reviewed tag tree, records the expected SRI and
  SHA-1, rechecks the destination channel immediately before mutation, and
  publishes with npm provenance. Reruns never overwrite a version: they accept
  an existing version only after anonymous verification proves its exact bytes,
  final channel, workflow identity, tag, and commit.
- **npm's exact-byte proof is necessarily post-publication.** npm versions are
  immutable, so anonymous CI can fetch and verify registry bytes, provenance,
  and clean install/provision behavior only after each publish. The two package
  writes are not atomic; a transient failure can expose one before the other.
  An idempotent rerun verifies the first and completes the second. Any proof
  failure leaves GitHub Latest and the Homebrew tap blocked and requires
  incident response for that same release rather than a rollback or manual tag
  mutation.
