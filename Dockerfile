FROM rust:slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*

# Mirror the real directory layout so all relative paths resolve
WORKDIR /build

# Copy kin-db (sibling repo workspace root + crate)
COPY kin-db/Cargo.toml /build/kin-db/Cargo.toml
COPY kin-db/crates/ /build/kin-db/crates/

# Copy kin source (includes vendored deps and .cargo/config.toml)
COPY kin/ /build/kin/

# Build from kin directory using vendored dependencies
WORKDIR /build/kin
RUN cargo build --release --locked --bin kin-daemon --bin kin

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -r kin && useradd -r -g kin kin
WORKDIR /app
COPY --from=builder /build/kin/target/release/kin-daemon /usr/local/bin/kin-daemon
COPY --from=builder /build/kin/target/release/kin /usr/local/bin/kin
COPY kin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
USER kin
EXPOSE 4219
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--repo", "/workspace", "--port", "4219"]
