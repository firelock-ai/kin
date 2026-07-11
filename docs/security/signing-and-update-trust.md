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
the `kin` CLI, the mandatory `kin-daemon`, and — when built — the `kin-vfs`
projection CLI and its interposition shim. Every archive is published alongside a
per-artifact SHA-256 file:

| Platform | Archive | Checksum |
| --- | --- | --- |
| Linux x86_64 | `kin-linux-x86_64.tar.gz` | `.tar.gz.sha256` |
| Linux aarch64 | `kin-linux-aarch64.tar.gz` | `.tar.gz.sha256` |
| macOS x86_64 | `kin-macos-x86_64.tar.gz` | `.tar.gz.sha256` |
| macOS aarch64 | `kin-macos-aarch64.tar.gz` | `.tar.gz.sha256` |
| Windows x86_64 | `kin-windows-x86_64.zip` | `.zip.sha256` |

A convenience `checksums-sha256.txt` aggregating every per-artifact file is also
attached to the release, but the installer verifies against the per-artifact
`.sha256` file, not the aggregate. Each archive also has a provenance manifest,
and the release includes an aggregate manifest binding the Kin and pinned
`kin-vfs` commits, both lockfile hashes, every archive hash, and every packaged
binary hash. GitHub signs an artifact attestation over the final archives and
aggregate manifest before the prerelease is created.

The Windows archive is a release-blocking target. It ships the supported
vector-free runtime: graph, lexical, daemon, setup, and MCP surfaces are present,
while vector similarity and local embedding are reported explicitly as
unsupported. Windows VFS projection is also not shipped. The archive is
checksum-protected and GitHub-attested, but is not OS-code-signed by this pipeline.

Every tag is first published as a non-latest prerelease. The anonymous install
proof installs all five archives (Linux x86_64/aarch64, macOS x86_64/aarch64,
and Windows x86_64), verifies the GitHub attestation plus exact tag/commit/lock
provenance, and exercises a fresh repository, graph search/locate, MCP
initialize/list/call, and all supported agent configuration writers. The four
Unix legs additionally build embeddings and prove semantic search/locate at
complete coverage. Both npm packages are then staged under their final channel
through npm Trusted Publishing. An authenticated maintainer inspects the staged
tarballs and approves both packages with 2FA; anonymous exact-byte, provenance,
and install proof runs after approval. GitHub Latest is promoted only after
every gate passes.

The daemon container is a separate attested subject. The protected tag workflow
builds one exact commit-tagged image in GHCR, verifies its embedded source and
lockfile identity, attaches SLSA provenance to that immutable digest, and
self-verifies the tag/ref/workflow identity. Later version-tag promotion reuses
that digest without rebuilding and never writes an implicit `latest` image.
Hosted infrastructure may copy the exact manifest into its private registry,
but that operation is a separately attested promotion, not a second build.

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
binary — that is expected for this artifact shape, not a signing gap. If a
`.dmg`/`.pkg` installer is added later, the pipeline has a documented place to
add `xcrun stapler staple`.

## Linux Release Posture (static musl)

The Linux core binaries (`kin`, `kin-daemon`) target
`*-unknown-linux-musl` and link **static by default**. A single Linux artifact
per architecture therefore runs across distros — musl (Alpine) and glibc
(Ubuntu/Debian/RHEL) alike — with no OpenSSL or glibc-version coupling. From a
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
  protected `release` environment, and that OIDC identity may only run
  `npm stage publish`. It stages each version under its final channel without a
  long-lived token. The maintainer should wait for both stage jobs to succeed,
  then use an authenticated npm account to download both staged tarballs (for
  example, with `npm stage download`) and compare their contents plus the
  workflow-emitted SRI and SHA-1 values before approving either package with
  2FA. The release workflow's OIDC identity deliberately cannot download or
  inspect pending stages, so this pre-approval inspection is a human-enforced
  gate. npm cannot make the two approvals atomic, so one package can still
  become public before the other. Never cut or approve a newer release while an
  older staged version remains pending. If the workflow fails or times out,
  finish that same release immediately or reject every remaining staged version
  before starting another release.
- **npm's automated exact-byte proof is post-publication.** Approval makes the
  npm version and final channel public before anonymous CI can fetch and verify
  exact bytes, provenance, and clean install/provision behavior. A failure at
  that point leaves an immutable public npm version requiring incident response;
  it is not pre-public proof. GitHub Latest and the Homebrew tap remain blocked
  until both npm versions and channels are visible and all post-public checks
  pass.
