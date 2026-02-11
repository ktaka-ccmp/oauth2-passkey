# Multi-stage build for demo-both
# Usage: docker build -t oauth2-passkey-demo-both -f demo-both/Dockerfile .

# Stage 1: Build with Alpine (musl libc for static linking)
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl

WORKDIR /app
COPY . .

RUN cargo build --release --manifest-path demo-both/Cargo.toml --features bundled-tls

# Stage 2: Minimal runtime (no OS, no shell, no libc)
FROM scratch

COPY --from=builder /app/target/release/demo-both /demo-both

# Cloud Run sets PORT=8080 by default; demo-both reads it
EXPOSE 8080

ENTRYPOINT ["/demo-both"]
