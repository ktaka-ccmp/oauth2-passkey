# None Attestation in WebAuthn

This document describes the "none" attestation format as implemented in the oauth2-passkey library, following the WebAuthn specification.

## Overview

The "none" attestation format is typically used by platform authenticators (like built-in biometric sensors) where the browser or operating system vouches for the authenticator. This format provides no cryptographic proof of the authenticator's provenance but relies on the platform's security guarantees.

## Attestation Statement Format

The "none" attestation statement is the simplest of all formats:

```json
attStmtType = (
    fmt: "none",
    attStmt: {}
)
```

### Field Descriptions

- **fmt**: The attestation statement format identifier, which is "none".
- **attStmt**: An empty map ({}), as no attestation-specific data is provided.

## Verification Procedure

The verification procedure for "none" attestation statements follows these steps:

1. **Empty Statement Verification**:
   - Verify that the attestation statement (attStmt) is empty.

2. **RP ID Hash Verification**:
   - Verify that the RP ID hash in authenticatorData matches the SHA-256 hash of the RP ID.

3. **Flag Verification**:
   - Verify that the User Present (UP) flag is set.
   - If User Verification (UV) is required by policy, verify that the UV flag is set.
   - Verify that the Attested Credential Data flag is set.

4. **AAGUID Extraction**:
   - Extract and log the AAGUID from the authenticator data.

5. **Public Key Verification**:
   - Verify that the credential public key is in the correct COSE format.
   - Extract and validate the public key coordinates.

## Implementation Notes

- The library performs basic checks on the authenticator data structure.
- User Verification requirements are configurable through the `PASSKEY_USER_VERIFICATION` setting.
- The implementation extracts and logs the AAGUID for potential future use.
- The public key is verified to ensure it follows the expected COSE key format.

## Compliance Assessment

The oauth2-passkey library implementation of "none" attestation has been assessed against the WebAuthn specification requirements. Here's a summary of the compliance status:

| Requirement | Status | Notes |
|-------------|--------|-------|
| Empty Statement Verification | ✅ Compliant | Verifies that attStmt is empty |
| RP ID Hash Verification | ✅ Compliant | Ensures the RP ID hash matches the expected value |
| User Present Flag | ✅ Compliant | Verifies the UP flag is set |
| User Verification Flag | ✅ Compliant | Checks UV flag when required by policy |
| Attested Credential Data | ✅ Compliant | Verifies the flag is set and data is present |
| AAGUID Extraction | ✅ Compliant | Successfully extracts and logs the AAGUID |
| Public Key Format | ✅ Compliant | Validates the COSE key format and coordinates |

### Areas for Improvement

While the implementation is fully compliant with the WebAuthn specification, there are some areas that could be enhanced:

1. **Logging Enhancement**: More detailed logging of the verification steps could aid in debugging and auditing.

2. **Error Messages**: More specific error messages could be provided for each verification step.

3. **Configuration Options**: Additional configuration options could be provided for customizing the verification behavior.

## References

1. [WebAuthn Specification - None Attestation](https://www.w3.org/TR/webauthn-2/#sctn-none-attestation)
2. [WebAuthn Specification - Authenticator Data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
