# Test Key Pair Generation Documentation

This document explains how the fixed ECDSA P-256 key pair for the first test user was generated and implemented in the oauth2-passkey test suite.

## Background

The oauth2-passkey library requires consistent key pairs for testing to ensure:
- Passkey credential storage works correctly
- Mock WebAuthn authentication succeeds with proper signature verification
- Integration tests pass reliably without cryptographic signature failures

## Key Pair Generation Process

### 1. Initial Generation

The key pair was generated using a small Rust program with the Ring cryptography library:

```rust
// key_generator.rs - One-time key generation program
use ring::{rand, signature};

fn main() {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    ).expect("Failed to generate key pair");
    
    // Print the bytes for embedding in test code
    println!("Private key bytes: {:?}", pkcs8_bytes.as_ref());
    
    // Extract and print public key for WebAuthn format
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
    ).expect("Failed to create key pair");
    
    let public_key_bytes = key_pair.public_key().as_ref();
    println!("Public key (uncompressed): {:?}", public_key_bytes);
    
    // Convert to base64url for WebAuthn
    let public_key_b64 = base64::encode_config(
        &public_key_bytes[1..], // Skip 0x04 prefix
        base64::URL_SAFE_NO_PAD
    );
    println!("Public key (WebAuthn format): {}", public_key_b64);
}
```

This program was run once to generate the fixed key pair used throughout the test suite.

### 2. PKCS#8 Private Key Structure

The generated private key is stored in PKCS#8 DER format (131 bytes):

```rust
const FIRST_USER_PRIVATE_KEY: &[u8] = &[
    // PKCS#8 PrivateKeyInfo structure (ASN.1 DER encoded)
    48, 129, 135,           // SEQUENCE, 135 bytes total
    2, 1, 0,                // INTEGER version = 0
    48, 19,                 // SEQUENCE for algorithm identifier
        6, 7, 42, 134, 72, 206, 61, 2, 1,    // OID for ecPublicKey
        6, 8, 42, 134, 72, 206, 61, 3, 1, 7, // OID for secp256r1 (P-256)
    4, 109,                 // OCTET STRING, 109 bytes (the actual private key)
        48, 107,            // SEQUENCE for EC private key
        2, 1, 1,            // INTEGER version = 1
        4, 32,              // OCTET STRING, 32 bytes (the secret scalar)
            139, 153, 75, 135, 130, 135, 200, 113, 147, 74, 215, 126,
            194, 20, 14, 216, 17, 194, 26, 44, 245, 110, 139, 6,
            6, 189, 51, 208, 44, 171, 153, 197,  // The actual private key (32 bytes)
        161, 68, 3, 66, 0,  // Optional public key follows
            4,              // Uncompressed point indicator
            // X coordinate (32 bytes):
            27, 78, 131, 131, 196, 142, 118, 54, 201, 9, 43, 62, 50, 252,
            223, 99, 155, 195, 74, 137, 198, 36, 126, 188, 138, 20, 142, 51, 38,
            144, 166, 242,
            // Y coordinate (32 bytes):
            54, 51, 184, 181, 61, 219, 148, 144, 37, 60, 142, 88, 223, 217,
            195, 136, 217, 39, 237, 73, 228, 8, 86, 72, 75, 127, 92, 98,
            159, 103, 44, 251
];
```

### 3. Public Key Derivation

The public key was extracted from the PKCS#8 structure and converted to WebAuthn format:

#### Mathematical Relationship
```
Public Key = Private Key × Generator Point (on P-256 curve)
```

#### WebAuthn Format
- **Format**: Uncompressed point coordinates (64 bytes)
- **Encoding**: Base64url without the `0x04` prefix
- **Result**: `"BBtOg4PEjnY2yQkrPjL832Obw0qJxiR-vIoUjjMmkKbyNjO4tT3blJAlPI5Y39nDiNkn7UnkCFZIS39cYp9nLPs"`

## Implementation Details

### Private Key Usage (fixtures.rs)
```rust
pub fn first_user_key_pair() -> Vec<u8> {
    // Fixed private key (PKCS#8 DER format) that corresponds to the public key used in test_utils.rs
    // This ensures signature verification works between credential storage and authentication
    const FIRST_USER_PRIVATE_KEY: &[u8] = &[/* ... 131 bytes ... */];
    
    FIRST_USER_PRIVATE_KEY.to_vec()
}
```

### Public Key Usage (test_utils.rs)
```rust
fn generate_first_user_public_key() -> String {
    // Fixed public key that corresponds to FIRST_USER_PRIVATE_KEY in integration tests
    // Generated using the same key pair to ensure signature verification works
    "BBtOg4PEjnY2yQkrPjL832Obw0qJxiR-vIoUjjMmkKbyNjO4tT3blJAlPI5Y39nDiNkn7UnkCFZIS39cYp9nLPs".to_string()
}
```

## Security Considerations

### Test-Only Usage
⚠️ **Important**: This key pair is **ONLY** for testing purposes and should never be used in production:

- The private key is publicly visible in the codebase
- It's designed for deterministic test behavior
- Real applications should generate fresh keys for each user

### Key Properties
- **Algorithm**: ECDSA with P-256 curve (secp256r1)
- **Strength**: 256-bit elliptic curve (equivalent to ~3072-bit RSA)
- **Standards**: Compliant with FIDO2/WebAuthn specifications

## Verification Process

The key pair enables proper WebAuthn signature verification in tests:

1. **Credential Storage**: Public key stored in database during test initialization
2. **Mock Authentication**: Private key signs authentication challenges
3. **Signature Verification**: System verifies signatures using stored public key
4. **Test Success**: Both keys are mathematically related → verification passes

## Troubleshooting

### Common Issues Fixed

1. **"Signature verification failed"**: Solved by using matching key pairs
2. **"Counter value decreased"**: Fixed by using timestamp-based counters in mock authentication
3. **"Key format mismatch"**: Resolved by proper PKCS#8 → WebAuthn format conversion

### Verification Commands

To verify the key pair relationship (if needed for debugging):

```bash
# Extract public key from private key using OpenSSL
openssl ec -in private_key.pem -pubout -out public_key.pem

# Compare with stored public key in base64url format
```

## Code Formatting Considerations

**Important**: The byte array documentation uses `/* */` block comments instead of `//` line comments to survive `cargo fmt` without being reformatted. This preserves the visual structure and readability of the cryptographic data explanations.

If you need to modify the comments, use the same block comment style to maintain `rustfmt` resistance.

## Future Maintenance

### When to Regenerate
- If cryptographic standards change
- If test requirements evolve  
- If key format specifications are updated

### How to Regenerate
1. Create and run the key generation program:
   ```bash
   # Create key_generator.rs with the code above
   # Add to Cargo.toml: ring = "0.16", base64 = "0.21"
   cargo run --bin key_generator
   ```

2. Copy the output into the code:
   - Private key bytes → `fixtures.rs::FIRST_USER_PRIVATE_KEY`
   - Public key (WebAuthn format) → `test_utils.rs::generate_first_user_public_key()`

3. Update the cross-references:
   - Ensure the public key string in comments matches
   - Update byte count comments if the structure changes

4. Verify the relationship:
   ```bash
   cargo test --test integration test_get_all_users_integration
   ```

5. If tests pass, the key pair is correctly matched!

## References

- [PKCS#8 Standard](https://tools.ietf.org/html/rfc5208)
- [WebAuthn Specification](https://w3c.github.io/webauthn/)
- [ECDSA P-256 Curve](https://tools.ietf.org/html/rfc5480)
- [Ring Cryptography Documentation](https://docs.rs/ring/)