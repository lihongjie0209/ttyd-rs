FROM rust:1-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY frontend ./frontend

RUN cargo build --release

FROM mcr.microsoft.com/devcontainers/base:ubuntu

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates lrzsz \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY --from=builder /app/target/release/ttyd /usr/local/bin/ttyd

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 7681

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["bash"]
