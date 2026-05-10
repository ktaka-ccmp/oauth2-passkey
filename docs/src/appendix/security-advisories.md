# Security Advisory Management

## Active Security Considerations

### RUSTSEC-2023-0071 - RSA Marvin Attack

**Status:** Eliminated from Direct Dependencies
**Advisory:** [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)
**Severity:** Medium (5.9)
**Date:** 2023-11-22

#### Vulnerability Description

The Marvin Attack is a potential key recovery attack through timing side-channels that affects RSA **decryption operations** using private keys.

#### Current Status

**✅ Direct Usage Eliminated (June 2025):**
- Removed direct dependency on `rsa` crate from oauth2-passkey
- Replaced with `jsonwebtoken::DecodingKey::from_rsa_components()` for JWT verification
- No longer performing any RSA operations in our codebase
- Removed `pkcs1` crate dependency used for PEM conversion

**Remaining Exposure:**
- Transitive dependency through `sqlx-mysql` → `rsa` crate
- Pulled in two ways:
  1. SQLx's macro system (`sqlx-macros-core`) includes all database drivers at compile time
  2. The `mysql` feature added in v0.5.0 enables the runtime driver
- **Impact:** None - the Marvin Attack targets RSA *decryption* timing
  to recover a private key, but `sqlx-mysql` only performs RSA *public-key
  encryption* of the password during the MySQL `caching_sha2_password`
  authentication handshake. The client never holds an RSA private key, so
  no decryption oracle exists in this code path
- **Risk:** Minimal - vulnerability not in our execution path
- **CI Status:** Advisory ignored (RUSTSEC-2023-0071)

**Technical Details:**
- Even with MySQL backend selected (`GENERIC_DATA_STORE_TYPE=mysql`), the
  client only encrypts outbound credentials with the server's public key
- Marvin Attack mitigation is the responsibility of the MySQL server
  (which holds the private key), not the Rust client
- SQLite and PostgreSQL backends do not pull `sqlx-mysql` at runtime at all

#### Migration Details

**Before (Vulnerable Pattern):**
```rust
// Used rsa crate directly
let rsa_public_key = RsaPublicKey::new(
    rsa::BigUint::from_bytes_be(&n),
    rsa::BigUint::from_bytes_be(&e),
)?;
let pem = rsa_public_key.to_pkcs1_pem(LineEnding::default())?;
Ok(DecodingKey::from_rsa_pem(pem.as_bytes())?)
```

**After (Secure Pattern):**
```rust
// Uses jsonwebtoken's built-in RSA support
Ok(DecodingKey::from_rsa_components(n, e)?)
```

#### Benefits of Migration

1. **Security:** Eliminated direct RSA crate usage and vulnerability exposure
2. **Simplicity:** Reduced code complexity and dependency count
3. **Maintenance:** Relies on well-maintained `jsonwebtoken` crate for RSA handling
4. **Performance:** Eliminated unnecessary base64 decode/encode cycles

#### Mitigation
- Regular monitoring of RustSec advisories for RSA crate updates
- Consider migration when rsa 0.10+ becomes stable with security fixes
- Current usage pattern remains secure for intended public key operations

#### Review Schedule
- **Next Review:** When rsa 0.10.0 stable is released
- **Trigger for Action:** If vulnerability scope expands to affect public key operations
- **Alternative:** Monitor for JWT libraries that don't depend on RSA crate

---

*Last Updated: 2026-05-11 (revised for v0.5.0 MySQL support)*
*Review Frequency: Quarterly or upon new RSA crate releases*
