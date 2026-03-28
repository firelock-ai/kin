FROM rust:slim AS builder
RUN apt-get update && apt-get install -y git pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*

# Cargo will fetch the pinned kin-db dependency from Cargo.lock.
WORKDIR /build

# Copy kin source (this repository)
COPY . /build/kin

# Build from kin directory
WORKDIR /build/kin
# .cargo/config.toml is gitignored. For Docker builds, we configure the Kin
# registry AND patch deps to use git repos as a fallback (the live registry may
# not have all features indexed yet). Once the registry is fully GCS-backed
# with complete metadata, the [patch] section can be removed.
RUN mkdir -p .cargo && printf '\
[registries.kin]\n\
index = "sparse+https://kinlab.ai/registry/cargo/"\n\
\n\
[patch.kin]\n\
kin-model = { git = "https://github.com/firelock-ai/kin-db.git", package = "kin-model" }\n\
kin-db = { git = "https://github.com/firelock-ai/kin-db.git", package = "kin-db" }\n\
kin-vfs-core = { git = "https://github.com/firelock-ai/kin-vfs.git", package = "kin-vfs-core" }\n\
kin-blobs = { git = "https://github.com/firelock-ai/kin-blobs.git" }\n\
kin-search = { git = "https://github.com/firelock-ai/kin-search.git" }\n\
kin-vector = { git = "https://github.com/firelock-ai/kin-vector.git" }\n\
kin-infer = { git = "https://github.com/firelock-ai/kin-infer.git" }\n\
' > .cargo/config.toml
# kin-daemon needs --features gcs for GCS StorageBackend in cloud deployment.
RUN cargo build --release --features gcs --bin kin-daemon --bin kin

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates curl libssl3 && rm -rf /var/lib/apt/lists/*
RUN groupadd -r kin && useradd -r -g kin kin
WORKDIR /app
COPY --from=builder /build/kin/target/release/kin-daemon /usr/local/bin/kin-daemon
COPY --from=builder /build/kin/target/release/kin /usr/local/bin/kin
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
USER kin
EXPOSE 4219
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--repo", "/workspace", "--port", "4219"]
