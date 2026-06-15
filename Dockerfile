FROM rust:slim AS builder
RUN apt-get update && apt-get install -y git pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*
ARG KIN_DB_REF=main

# Cargo will fetch the pinned kin-db dependency from Cargo.lock.
WORKDIR /build

# Copy kin source (this repository)
COPY . /build/kin

# Build from kin directory
WORKDIR /build/kin
# Keep the committed cargo config intact: it contains the public Git [patch.kin]
# pins needed until every kin-* crate is published in the sparse registry.
RUN test -f .cargo/config.toml && grep -q '^\[registries\.kin\]' .cargo/config.toml
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
