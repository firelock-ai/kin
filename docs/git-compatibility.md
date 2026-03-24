# Git Compatibility

KinLab implements the **Git Smart HTTP Protocol**, making it a drop-in Git remote. Any standard Git client can `git clone`, `git fetch`, and `git pull` from KinLab without specialized tooling.

## How It Works

KinLab translates Kin's semantic graph into native Git objects on the fly:

1. **Ref Discovery** — `GET /:org/:repo.git/info/refs?service=git-upload-pack`
   The client asks "what refs do you have?" KinLab queries the gateway for the repo's refs (branches, tags, HEAD) and returns them in Git pkt-line format with capability advertisement.

2. **Pack Negotiation** — `POST /:org/:repo.git/git-upload-pack`
   The client sends `want` lines for the SHAs it needs. KinLab fetches the projected file tree from the gateway, builds Git blob/tree/commit objects, and returns a native Git packfile.

3. **Clone/Fetch completes** — the client unpacks the packfile into a normal `.git` repository. From this point forward, it is an ordinary Git checkout.

## Supported Operations

| Operation    | Status      | Protocol Endpoint      |
|-------------|-------------|------------------------|
| `git clone` | Supported   | `git-upload-pack`      |
| `git fetch` | Supported   | `git-upload-pack`      |
| `git pull`  | Supported   | `git-upload-pack`      |
| `git push`  | Not yet     | `git-receive-pack`     |

Read-only access is fully supported. Push support (`git-receive-pack`) is planned for a future release.

## Why This Matters

- **CI/CD compatibility**: Any pipeline that can `git clone` can work with KinLab. No special CLI, no plugins, no vendor SDKs.
- **Zero-friction onboarding**: Developers use standard Git until they want semantic features. The learning curve for read access is zero.
- **Escape hatch**: `git clone` your way out at any time. Your code is never locked in — it is always one command away from a standard Git repo.
- **Enterprise trust**: Procurement teams see a standard protocol, not a proprietary black box.

## Architecture

Two modules handle Git protocol:

- **`git-protocol.ts`** — URL matching, pkt-line encoding/decoding, ref discovery, and upload-pack request handling. This is the protocol layer that speaks Git's wire format.
- **`git-packfile.ts`** — Native packfile generation. Takes the projected file tree from the gateway and builds Git blob objects, tree objects (with proper sorting and binary SHA encoding), and commit objects. Packs them into Git packfile v2 format with zlib-compressed objects and a SHA-1 checksum trailer.

The protocol handler is wired into the control plane's main request handler before API routing. Git URLs (anything matching `/:org/:repo.git/...`) are intercepted and handled by the protocol layer; everything else falls through to normal API routing.

## Advertised Capabilities

The ref discovery response advertises these Git capabilities:

- `multi_ack_detailed` — multi-round acknowledgment for efficient pack negotiation
- `thin-pack` — allow thin packs (deltas against objects not in the pack)
- `side-band-64k` — multiplexed output channels
- `ofs-delta` — offset-based delta compression
- `shallow` — shallow clone support
- `no-progress` — suppress progress messages
- `include-tag` — include tag objects when sending tagged commits
- `agent=kinlab/1.0` — server identification

## Usage Examples

```bash
# Clone from KinLab
git clone https://kinlab.yourdomain.com/org/repo.git

# Fetch updates
cd repo && git fetch origin

# Use in CI/CD — just use the KinLab URL as your Git remote
git clone https://kinlab.yourdomain.com/myorg/myrepo.git
cd myrepo && make test

# Local development against KinLab control plane
git clone http://localhost:4010/default/kin.git
```

## Limitations

- **Read-only**: Push (`git-receive-pack`) is not yet implemented. Use `kin publish` for writes.
- **Full clone only**: Every clone/fetch returns the complete projected tree. Incremental fetch (sending only objects the client is missing) requires commit history tracking.
- **Native packfile generation**: Packfiles are built in pure TypeScript without shelling out to `git pack-objects`. This keeps the dependency footprint at zero but does not yet support delta compression.
- **Gateway dependency**: The quality of the Git clone depends on what the gateway provides. If the repo has no projected files, the clone will be empty.

## Future Work

- **`git-receive-pack`** — accept pushes from standard Git clients, translating Git objects back into Kin semantic operations.
- **Incremental fetch** — track commit history so subsequent fetches only send new objects.
- **Shallow clone** — honor `--depth` to reduce transfer size for CI pipelines that only need the latest snapshot.
- **Partial clone / sparse checkout** — allow clients to request only specific paths, reducing bandwidth for large repos.
- **Delta compression** — use ofs-delta and ref-delta encoding in packfiles for smaller transfer sizes.
