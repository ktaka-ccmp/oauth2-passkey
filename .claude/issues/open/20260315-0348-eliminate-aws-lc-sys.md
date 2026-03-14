# Issue: Eliminate aws-lc-sys Dependency

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260315-0348

## Created: 2026-03-15-03-48

## Closed:

## Status: open

## Priority: high

## Difficulty: small

## Description

The `aws-lc-sys` crate is pulled into the dependency tree by reqwest 0.13's default TLS
configuration (`rustls` feature -> `aws-lc-rs` provider). This requires CMake and a C++
compiler at build time, which:

- Breaks `cargo build` on minimal environments without CMake
- Complicates cross-compilation
- Adds significant build time
- Is problematic for crates.io users who expect `cargo build` to just work

The project already depends on `ring` directly (for WebAuthn signature verification), so
switching rustls's crypto provider from aws-lc-rs to ring eliminates aws-lc-sys without
adding new dependencies.

### Current dependency chain

```
reqwest 0.13 (default features)
  -> rustls 0.23 (default: aws_lc_rs)
    -> aws-lc-rs
      -> aws-lc-sys  <-- CMake + C++ required
```

### Target dependency chain

```
reqwest 0.13 (rustls-no-provider)
  -> rustls 0.23 (ring only, default-features = false)
    -> ring  <-- already in dependency tree, vendored C/asm, cargo build only
```

## Related Issues

- `20260315-0349` Eliminate ring Dependency (related: further Pure Rust goal)

## Approach

### Step 1: Modify workspace Cargo.toml

Change reqwest to use `rustls-no-provider` and configure rustls with ring only:

```toml
reqwest = { version = "0.13.2", default-features = false, features = [
    "rustls-no-provider", "charset", "http2", "json", "cookies", "form", "system-proxy"
] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
```

### Step 2: Verify aws-lc-sys is eliminated

```bash
cargo tree | grep -i aws-lc
# Should return nothing
```

### Step 3: Verify install_default() is NOT needed

With only the `ring` feature enabled on rustls (and `aws_lc_rs` disabled), rustls should
auto-detect ring as the sole provider. `ClientConfig::builder()` should work without
`CryptoProvider::install_default()`.

If auto-detection does NOT work, fallback options:
- Use `builder_with_provider(ring)` in the bundled-tls code path
- Add `install_default()` in library initialization (last resort)

### Step 4: Update bundled-tls code (if needed)

In `oauth2_passkey/src/utils.rs`, the `rustls_config_with_webpki_roots()` function uses
`ClientConfig::builder()`. If explicit provider selection is needed, change to:

```rust
let provider = rustls::crypto::ring::default_provider();
let mut config = rustls::ClientConfig::builder_with_provider(provider.into())
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

### Step 5: Run full test suite

```bash
cargo test
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --all-features
```

## Related Files

- `Cargo.toml` (workspace dependencies)
- `oauth2_passkey/Cargo.toml` (reqwest, rustls dependencies)
- `oauth2_passkey/src/utils.rs` (bundled-tls TLS configuration)

## Implementation Tasks

- [ ] Modify workspace Cargo.toml: reqwest features and rustls features
- [ ] Verify `cargo tree | grep aws-lc` returns nothing
- [ ] Verify `cargo build` succeeds without CMake
- [ ] Check if `install_default()` is needed or auto-detection works
- [ ] Update bundled-tls code if needed
- [ ] Run full test suite
- [ ] Test demo apps manually

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-15: Choose ring over RustCrypto for rustls provider

- Context: Need to eliminate aws-lc-sys. Options: (1) ring provider, (2) rustls-rustcrypto provider
- Decision: Use ring as rustls crypto provider
- Reason: ring is already a direct dependency (WebAuthn uses it). rustls-rustcrypto is experimental. Adding ring to rustls adds no new dependencies.

### 2026-03-15: Use rustls-no-provider feature on reqwest

- Context: reqwest 0.13 removed the `__rustls-ring` feature that 0.12 had. Only options are `rustls` (aws-lc-rs) or `rustls-no-provider`.
- Decision: Use `rustls-no-provider` and add `ring` feature to rustls workspace dependency
- Reason: This is the only way to avoid aws-lc-rs in reqwest 0.13. Cargo feature unification should propagate ring to all rustls consumers.

## Resolution
