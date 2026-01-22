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
- Transitive dependency through `sqlx-mysql` → `rsa` crate (via SQLx macros)
- **Impact:** None - we only use SQLite and PostgreSQL features, never MySQL
- **Risk:** Minimal - vulnerability not in our execution path
- **CI Status:** Advisory ignored (RUSTSEC-2023-0071) due to unused dependency path

**Technical Details:**
- SQLx's macro system (`sqlx-macros-core`) includes all database drivers at compile time
- This is a known SQLx architectural limitation
- MySQL driver dependencies are never loaded or executed in our applications
- All actual database operations use only SQLite or PostgreSQL drivers

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

*Last Updated: June 22, 2025*
*Review Frequency: Quarterly or upon new RSA crate releases*
