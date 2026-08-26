# Both base images are pinned by digest and reachable through two independent
# registries. The tag is kept for review; the digest is what gets pulled, and a
# digest cannot serve different bytes whichever registry answers. The build
# configures BuildKit to try mirror.gcr.io before docker.io (see docker.yml and
# release.yml), and falls back to docker.io when the mirror cannot serve the
# digest, so neither registry is a single point of failure.
#
# This matters beyond reproducibility. `Docker Image Build (no push)` publishes
# a check-run against every commit that reaches main, and release-tag.yml's
# second sweep refuses a release commit carrying any non-green check-run,
# required or not. A registry blip lasting minutes therefore refuses a release
# permanently, which is how one cut was already lost.
#
# scripts/verify-base-image-pins.sh proves both registries still serve both
# pinned digests, and reports when the upstream tag has moved past the pin.
# Dependency compilation is split away from workspace compilation. `cargo chef
# prepare` distills the workspace manifests into a recipe whose bytes change
# only when a dependency changes, so the `cook` layer in the builder keys on
# dependencies alone and survives across source-only commits in the
# registry-backed BuildKit cache that cloudbuild.yaml imports and exports.
# Before the split, `COPY . /build/kin` preceded the only cargo invocation, so
# every push to main recompiled the entire dependency graph from scratch and
# each hosted build burned 11-20 minutes on E2_HIGHCPU_8.
#
# The planner repeats the pinned reference instead of deriving `FROM builder`.
# Every FROM in this file is asserted to name docker.io and end in a digest by
# both scripts/verify-base-image-pins.sh and
# scripts/test-release-workflow-authority.py, and a bare stage name carries
# neither, so stage-chaining would fail the release gates.
FROM docker.io/library/rust:slim@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS planner
RUN apt-get update && apt-get install -y git pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version 0.1.68
WORKDIR /build/kin
COPY . /build/kin
RUN cargo chef prepare --recipe-path /recipe.json

FROM docker.io/library/rust:slim@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS builder
RUN apt-get update && apt-get install -y git pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version 0.1.68
ARG KIN_DB_REF=main
ARG KIN_BUILD_GIT_SHA=""
ARG KIN_BUILD_DIRTY=""
ARG KIN_BUILD_BRANCH=""
# The hosted image links its release profile with the LTO mode the build passes in,
# because the fat link of kin-daemon exceeds the 8 GB the trigger's machine carries and
# the only larger Cloud Build machine type is quota-blocked for this project. The
# default stays fat so every other consumer of this Dockerfile is unchanged.
ARG KIN_LTO=fat
ENV CARGO_PROFILE_RELEASE_LTO=$KIN_LTO

# Cargo will fetch the pinned kin-db dependency from Cargo.lock.
WORKDIR /build

# Build from kin directory
WORKDIR /build/kin
# The kin sparse registry can return a brief 502 during a deploy/cold start.
# Cargo's default of 3 retries can be exhausted inside such a window and fail
# the whole build; raise the retry budget so a transient blip is ridden out.
ENV CARGO_NET_RETRY=10
# Keep the committed cargo config intact: it defines the [registries.kin] sparse
# registry that kin-* crates resolve from (the Git [patch.kin] pins were dropped
# at the registry cutover — kin no longer depends on GitHub for crate deps).
# It lands before the cook because cooking resolves those same kin-* crates.
COPY .cargo /build/kin/.cargo
RUN test -f .cargo/config.toml && grep -q '^\[registries\.kin\]' .cargo/config.toml

# Compile dependencies only. Feature and target selection must match the real
# build below, or the cooked artifacts are keyed differently and the workspace
# build recompiles them anyway.
COPY --from=planner /recipe.json /recipe.json
RUN cargo chef cook --locked --release --features gcs --recipe-path /recipe.json

# Copy kin source (this repository)
COPY . /build/kin
# kin-daemon needs --features gcs for GCS StorageBackend in cloud deployment.
# `.dockerignore` deliberately excludes `.git`, so hosted image builders pass
# the exact source identity as an atomic three-value override. A local image
# build may omit all three and remains explicitly unknown/dirty; supplying only
# part of the identity fails in kin-buildinfo rather than looking trustworthy.
RUN if [ -n "$KIN_BUILD_GIT_SHA" ] || [ -n "$KIN_BUILD_DIRTY" ] || [ -n "$KIN_BUILD_BRANCH" ]; then \
      KIN_BUILD_GIT_SHA_OVERRIDE="$KIN_BUILD_GIT_SHA" \
      KIN_BUILD_DIRTY_OVERRIDE="$KIN_BUILD_DIRTY" \
      KIN_BUILD_BRANCH_OVERRIDE="$KIN_BUILD_BRANCH" \
      cargo build --locked --release --features gcs --bin kin-daemon --bin kin; \
    else \
      cargo build --locked --release --features gcs --bin kin-daemon --bin kin; \
    fi

# Alternate image: Kin's MCP stdio server instead of the daemon. Select it
# explicitly with `docker build --target mcp`. It sits BEFORE the runtime stage
# on purpose: a build with no `--target` takes the last stage, so the daemon
# image every existing build produces (docker.yml, cloudbuild.yaml,
# release.yml, docker-compose.yml) is unchanged by this stage existing.
#
# It repeats the pinned base rather than deriving from that runtime stage
# because every FROM here has to name its registry and pin a digest:
# scripts/verify-base-image-pins.sh proves each pin against two registries, and
# scripts/test-release-workflow-authority.py refuses any base a mirror could
# resolve differently. A `FROM <stage>` line carries neither, and both checks
# gate a release.
FROM docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS mcp
RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
RUN groupadd -r kin \
    && useradd -r -g kin -d /home/kin -m kin \
    && chmod 0700 /home/kin
ENV HOME=/home/kin
WORKDIR /app
COPY --from=builder /build/kin/target/release/kin /usr/local/bin/kin
# The MCP server is transport-only: it forwards graph tools to the repo daemon
# it resolves for the mounted repository, so the daemon binary has to be here
# even though nothing in this image starts one and no port is published.
COPY --from=builder /build/kin/target/release/kin-daemon /usr/local/bin/kin-daemon
USER kin
# stdio transport: MCP travels over stdin and stdout, so run this image with
# `-i`, mount the repository, and set the working directory to it.
ENTRYPOINT ["/usr/local/bin/kin", "mcp", "start"]

FROM docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates curl libssl3 && rm -rf /var/lib/apt/lists/*
RUN groupadd -r kin \
    && useradd -r -g kin -d /home/kin -m kin \
    && chmod 0700 /home/kin
ENV HOME=/home/kin
WORKDIR /app
COPY --from=builder /build/kin/target/release/kin-daemon /usr/local/bin/kin-daemon
COPY --from=builder /build/kin/target/release/kin /usr/local/bin/kin
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
# Pre-create the default workspace owned by the runtime user. Docker seeds a
# freshly created named volume from the image path's ownership, so a volume
# mounted here (see docker-compose.yml) stays writable by the non-root daemon;
# without this the volume is created root-owned and the daemon cannot write it.
RUN mkdir -p /tmp/kin-workspace && chown kin:kin /tmp/kin-workspace
USER kin
EXPOSE 4219
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# The entrypoint owns --repo: it resolves and prepares the workspace
# (KIN_WORKSPACE_DIR, default /tmp/kin-workspace) and passes it to the daemon.
# Hardcoding --repo /workspace here would name an unwritable image-root path with
# no volume mounted, so only pass the port and let the entrypoint set the repo.
CMD ["--port", "4219"]
