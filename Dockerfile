FROM rust:slim AS builder
RUN apt-get update && apt-get install -y git pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*
ARG KIN_DB_REF=main
ARG KIN_BUILD_GIT_SHA=""
ARG KIN_BUILD_DIRTY=""
ARG KIN_BUILD_BRANCH=""

# Cargo will fetch the pinned kin-db dependency from Cargo.lock.
WORKDIR /build

# Copy kin source (this repository)
COPY . /build/kin

# Build from kin directory
WORKDIR /build/kin
# Keep the committed cargo config intact: it defines the [registries.kin] sparse
# registry that kin-* crates resolve from (the Git [patch.kin] pins were dropped
# at the registry cutover — kin no longer depends on GitHub for crate deps).
RUN test -f .cargo/config.toml && grep -q '^\[registries\.kin\]' .cargo/config.toml
# The kin sparse registry can return a brief 502 during a deploy/cold start.
# Cargo's default of 3 retries can be exhausted inside such a window and fail
# the whole build; raise the retry budget so a transient blip is ridden out.
ENV CARGO_NET_RETRY=10
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

FROM debian:trixie-slim
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
