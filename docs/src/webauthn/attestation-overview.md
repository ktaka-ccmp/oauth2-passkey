# Attestation Overview

## What is Attestation?

Attestation in WebAuthn is a mechanism that allows a relying party (your application) to verify the provenance and characteristics of an authenticator during registration. When a user creates a new credential, the authenticator can provide cryptographic proof about itself, including information about its manufacturer, security properties, and certification status.

The attestation statement is included in the registration response and contains:
- The attestation format identifier (e.g., "none", "packed", "tpm")
- Format-specific attestation data (signatures, certificates, etc.)
- The authenticator data containing the new credential

## Why Attestation Matters

Attestation provides several security benefits:

1. **Authenticator Verification**: Confirm that a credential was created by a genuine, certified authenticator rather than a software emulator or compromised device.

2. **Security Policy Enforcement**: Organizations can require specific authenticator types or certification levels based on their security requirements.

3. **AAGUID Identification**: The Authenticator Attestation GUID (AAGUID) identifies the authenticator model, enabling relying parties to make policy decisions based on known device characteristics.

4. **Supply Chain Trust**: For high-security environments, attestation provides cryptographic proof that traces back to the authenticator manufacturer.

However, attestation also has privacy implications. Detailed attestation can potentially be used to track users across services, which is why many platform authenticators use "none" attestation by default.

## Supported Formats

The oauth2-passkey library supports three attestation formats, each suitable for different use cases.

### None Attestation

The "none" attestation format provides no cryptographic proof of authenticator provenance. It is the simplest format and is typically used by platform authenticators (built-in biometric sensors, operating system passkey implementations).

**Key characteristics:**
- Empty attestation statement
- Relies on platform security guarantees
- Maximum user privacy
- Suitable for most consumer applications

For detailed verification procedures and implementation notes, see [Chapter 16: None Attestation](none.md).

### Packed Attestation

The "packed" attestation format is commonly used by security keys (like YubiKeys) and provides a compact but comprehensive attestation statement. It supports multiple attestation types:

- **Basic/Full Attestation**: Includes an attestation certificate chain for full authenticator verification
- **Self Attestation**: The credential signs its own attestation (no external certificate)

**Key characteristics:**
- Contains algorithm identifier and signature
- Optional certificate chain (x5c) for full attestation
- Supports ES256 algorithm
- Common format for FIDO2 security keys

For detailed verification procedures and certificate requirements, see [Chapter 17: Packed Attestation](packed.md).

### TPM Attestation

The TPM (Trusted Platform Module) attestation format is used by authenticators that leverage hardware TPM chips for cryptographic operations. This format provides strong hardware-backed attestation with detailed device information.

**Key characteristics:**
- Requires TPM 2.0
- Includes AIK (Attestation Identity Key) certificate
- Contains TPM-specific structures (certInfo, pubArea)
- Provides hardware-rooted trust
- Common on Windows Hello and enterprise devices

For detailed verification procedures, TPM structures, and certificate requirements, see [Chapter 18: TPM Attestation](tpm.md).

## Choosing an Attestation Format

The choice of attestation format depends on your security requirements and use case:

| Use Case | Recommended Format | Reason |
|----------|-------------------|--------|
| Consumer applications | None | Maximum privacy, broad compatibility |
| Enterprise with security keys | Packed | Verifies authenticator authenticity |
| High-security environments | TPM or Packed (Full) | Hardware-backed trust, certificate verification |
| Privacy-sensitive applications | None | No tracking potential |
| Authenticator inventory management | Packed or TPM | AAGUID and certificate provide device information |

**General guidelines:**

1. **Default to "none"**: Unless you have specific requirements to verify authenticator provenance, accepting "none" attestation provides the best user experience and privacy.

2. **Use "packed" for security keys**: When deploying hardware security keys in an organization, packed attestation allows verification of genuine devices.

3. **Use "tpm" for Windows environments**: Windows Hello typically provides TPM attestation, suitable for enterprise Windows deployments.

4. **Consider privacy implications**: Full attestation can potentially identify specific authenticator models, which may have privacy implications for your users.

## Library Configuration

The oauth2-passkey library handles attestation verification automatically during credential registration. The library:

1. **Detects the attestation format** from the registration response's `fmt` field.

2. **Routes to the appropriate verifier** based on the format ("none", "packed", or "tpm").

3. **Performs format-specific verification** following WebAuthn specification requirements.

4. **Extracts the credential public key** and AAGUID for storage.

**Configuration options:**

- **User Verification**: The `PASSKEY_USER_VERIFICATION` setting controls whether user verification (biometric, PIN) is required during registration.

- **Attestation Preference**: When initiating registration, you can request specific attestation conveyance:
  - `none`: Request no attestation (default for privacy)
  - `indirect`: Accept any attestation the authenticator provides
  - `direct`: Request direct attestation from the authenticator
  - `enterprise`: Request enterprise attestation (for managed devices)

The library accepts all supported attestation formats regardless of the preference setting, as authenticators may provide different formats than requested.

**Verification behavior:**

- All formats verify the RP ID hash and authenticator flags
- Certificate-based formats (packed full, TPM) verify certificate chains
- The library logs AAGUIDs for debugging and potential policy use
- Verification failures result in registration rejection with appropriate error messages
