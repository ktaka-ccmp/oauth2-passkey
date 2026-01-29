# AAGUID and Authenticator Metadata

This document explains how passkey authenticator icons and names are determined using AAGUID.

## What is AAGUID?

AAGUID (Authenticator Attestation Globally Unique Identifier) is a 128-bit identifier that indicates the type (make and model) of an authenticator. It allows Relying Parties (RPs) to identify which device or password manager created a passkey.

Examples:
- `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4` - Google Password Manager
- `adce0002-35bc-c60a-648b-0b25f1f05503` - 1Password
- `00000000-0000-0000-0000-000000000000` - Unknown (often Apple devices)

## Metadata Sources

### FIDO Metadata Service (MDS)

The official [FIDO Metadata Service](https://fidoalliance.org/metadata/) provides metadata for FIDO-certified hardware authenticators.

| Aspect | Details |
|--------|---------|
| Endpoint | `https://mds3.fidoalliance.org/` |
| Format | JWT BLOB (requires signature verification) |
| Auth | Not required (public) |
| Coverage | Hardware security keys (YubiKey, Titan Key, etc.) |
| Update frequency | Monthly recommended |

**Limitation**: FIDO MDS does **not** include password managers (Google Password Manager, iCloud Keychain, 1Password, etc.) because they don't go through FIDO certification.

### Community AAGUID Repository

The [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) project provides a community-sourced list that includes both hardware authenticators and password managers.

| Aspect | Details |
|--------|---------|
| Endpoint | `https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json` |
| Format | Simple JSON |
| Auth | Not required |
| Coverage | Hardware keys + Password managers |
| Recommended by | [web.dev](https://web.dev/articles/webauthn-aaguid) |

**This library uses the community repository** to support displaying icons for all authenticator types.

## Comparison of Data Sources

| Source | Hardware Keys | Password Managers | Verification | Complexity |
|--------|---------------|-------------------|--------------|------------|
| FIDO MDS | Yes | **No** | JWT signature | High |
| Community repo | Yes | **Yes** | None | Low |

## How This Library Uses AAGUID

### Data Flow

```
Registration
    |
    v
Authenticator returns AAGUID
    |
    v
Store in passkey_credentials table
    |
    v
get_authenticator_info(aaguid)
    |
    v
Lookup from cache (loaded from community JSON)
    |
    v
Display name + icon in templates
```

### Implementation

The AAGUID lookup is implemented in `oauth2_passkey/src/passkey/main/aaguid.rs`:

```rust
// Embedded fallback data
const AAGUID_JSON: &str = include_str!("../../../assets/aaguid.json");

// Remote source (updated regularly)
const AAGUID_URL: &str = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json";

// Lookup function
pub async fn get_authenticator_info(aaguid: &str) -> Result<Option<AuthenticatorInfo>, PasskeyError>
```

### Data Structure

```rust
pub struct AuthenticatorInfo {
    pub name: String,           // e.g., "Google Password Manager"
    pub icon_dark: Option<String>,  // Base64-encoded SVG for dark theme
    pub icon_light: Option<String>, // Base64-encoded SVG for light theme
}
```

## Attestation vs AAGUID

| Aspect | Attestation | AAGUID |
|--------|-------------|--------|
| Purpose | Cryptographic proof of authenticator | Identifier for display |
| Verification | Certificate chain | None (self-reported) |
| Security use | Yes (device policy enforcement) | No (can be spoofed) |
| Display use | No | Yes (icons, names) |

**Important**: AAGUID should only be used for UI display purposes (showing icons and names). It should **not** be used for security decisions because it can be spoofed without attestation verification.

## Comparison with Other Libraries

| Library | AAGUID Extraction | FIDO MDS | Password Manager Icons |
|---------|-------------------|----------|------------------------|
| SimpleWebAuthn (JS) | Yes | No | Requires separate JSON |
| webauthn4j (Java) | Yes | Yes (for attestation) | No |
| Yubico java-webauthn-server | Yes | Yes (full) | No |
| **This library** | Yes | No | **Yes** (community repo) |

All libraries require the community AAGUID repository for password manager icon display.

## Apple's Zero AAGUID

Apple devices historically return `00000000-0000-0000-0000-000000000000` (all zeros) as the AAGUID. This is because:

1. Apple prioritizes user privacy
2. Apple devices don't support attestation
3. Revealing the exact device model could be a fingerprinting vector

When this AAGUID is encountered, the library displays "Unknown Authenticator" or a generic icon.

## References

- [FIDO Metadata Service](https://fidoalliance.org/metadata/)
- [web.dev: Determine the passkey provider with AAGUID](https://web.dev/articles/webauthn-aaguid)
- [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
- [FIDO MDS Specification v3](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html)
