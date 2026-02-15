# Multi-stage build for demo-live
# Usage: docker build -t oauth2-passkey-demo-live -f demo-live/Dockerfile .

# Stage 1: Build with Alpine (musl libc for static linking)
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl

WORKDIR /app
COPY . .

RUN cargo build --release --manifest-path demo-live/Cargo.toml --features bundled-tls

# Stage 2: Minimal runtime (no OS, no shell, no libc)
FROM scratch

COPY --from=builder /app/target/release/demo-live /demo-live

# Cloud Run sets PORT=8080 by default; demo-live reads it
EXPOSE 8080

ENTRYPOINT ["/demo-live"]
