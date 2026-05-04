# Multi-stage build for demo-live with cargo-chef for dependency caching
# Usage: docker build -t oauth2-passkey-demo-live -f demo-live/Dockerfile .

# Stage 1: Install cargo-chef
FROM rust:latest-alpine AS chef
RUN apk add --no-cache musl-dev cmake make perl
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Analyze dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build dependencies (CACHED when only source code changes)
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --manifest-path demo-live/Cargo.toml --features bundled-tls --recipe-path recipe.json
# Build application (only this layer rebuilds on source changes)
COPY . .
RUN cargo build --release --manifest-path demo-live/Cargo.toml --features bundled-tls

# Stage 4: Minimal runtime (no OS, no shell, no libc)
FROM scratch

COPY --from=builder /app/target/release/demo-live /demo-live

# Cloud Run sets PORT=8080 by default; demo-live reads it
EXPOSE 8080

ENTRYPOINT ["/demo-live"]
