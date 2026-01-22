# Packed Attestation in WebAuthn

This document describes the "packed" attestation format as implemented in the oauth2-passkey library, following the WebAuthn specification.

## Overview

The "packed" attestation format is commonly used by security keys and provides a compact but comprehensive attestation statement. It supports multiple attestation types: Basic, AttCA (with an attestation certificate), and Self Attestation.

## Attestation Statement Format

The "packed" attestation statement follows this structure:

```json
attStmtType = (
    fmt: "packed",
    attStmt: packedStmtFormat
)

packedStmtFormat = {
    alg: COSEAlgorithmIdentifier,
    sig: bytes,
    [x5c: [ attestnCert: bytes, * (caCert: bytes) ]],
    [ecdaaKeyId: bytes]
}
```

### Field Descriptions

- **fmt**: The attestation statement format identifier, which is "packed".
- **alg**: A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature.
- **sig**: The attestation signature.
- **x5c** (optional): The attestation certificate and its certificate chain, in X.509 encoding.
- **ecdaaKeyId** (optional): The identifier of the ECDAA key used for the attestation (not supported in current implementation).

## Verification Procedure

The verification procedure for "packed" attestation statements follows these steps:

1. **Algorithm and Signature Extraction**:
   - Extract the algorithm identifier (alg) and signature (sig) from the attestation statement.

2. **Signed Data Construction**:
   - Concatenate authenticatorData and clientDataHash to form the signed data.

3. **Algorithm Verification**:
   - Verify that the algorithm is supported (currently only ES256 is supported).

4. **Attestation Type Determination**:
   - Check for the presence of x5c and ecdaaKeyId to determine the attestation type.

5. **Attestation Verification**:
   - For Full Attestation (x5c present):
     - Parse and verify the attestation certificate.
     - Verify certificate attributes according to FIDO standards.
     - Verify the signature using the attestation certificate's public key.
     - Verify the certificate chain if intermediates are present.
   - For Self Attestation (neither x5c nor ecdaaKeyId present):
     - Extract the credential public key from authenticatorData.
     - Verify the signature using this public key.
   - For ECDAA Attestation (ecdaaKeyId present):
     - Currently not supported.

## Certificate Verification

For Full Attestation, the attestation certificate is verified to ensure it meets these requirements:

1. **Basic Constraints**: Verify the certificate is not a CA certificate.

2. **AAGUID Verification**: If the certificate contains the FIDO AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4), verify it matches the AAGUID in authenticatorData.

## Certificate Chain Verification

If the attestation statement includes intermediate certificates, the library verifies:

1. **Certificate Parsing**: Each certificate in the chain can be parsed correctly.

2. **Certificate Validity**: Each certificate is currently valid (not expired or not yet valid).

## Self Attestation Verification

For Self Attestation, the library:

1. **Extracts the Credential Public Key**: From the authenticatorData.

2. **Constructs the Full Public Key**: Formats the extracted coordinates as an uncompressed EC point.

3. **Verifies the Signature**: Using the credential's own public key.

## Compliance Assessment

The oauth2-passkey library implementation of "packed" attestation has been assessed against the WebAuthn specification requirements. Here's a summary of the compliance status:

| Requirement | Status | Notes |
|-------------|--------|-------|
| Algorithm Extraction | ✅ Compliant | Correctly extracts and verifies the algorithm |
| Signature Extraction | ✅ Compliant | Correctly extracts the signature |
| Signed Data Construction | ✅ Compliant | Properly concatenates authenticatorData and clientDataHash |
| Algorithm Verification | ✅ Compliant | Verifies ES256 algorithm support |
| Attestation Type Determination | ✅ Compliant | Correctly identifies attestation type |
| Full Attestation Verification | ✅ Compliant | Properly verifies certificates and signatures |
| Self Attestation Verification | ✅ Compliant | Correctly extracts and verifies using credential's own key |
| Certificate Basic Constraints | ✅ Compliant | Verifies certificate is not a CA |
| AAGUID Verification | ✅ Compliant | Matches certificate AAGUID with authenticator AAGUID |
| Certificate Chain Verification | ✅ Compliant | Verifies intermediate certificates when present |
| ECDAA Attestation | ❌ Not Implemented | ECDAA attestation is not currently supported |

### Areas for Improvement

While the implementation is largely compliant with the WebAuthn specification, there are some areas that could be enhanced:

1. **ECDAA Support**: The current implementation does not support ECDAA attestation, which is optional in the WebAuthn specification.

2. **Certificate Verification**: More comprehensive certificate verification could be implemented, including checking for revocation status.

3. **Error Handling**: More detailed error messages could be provided for specific verification failures.

4. **Performance Optimization**: The certificate parsing and verification could potentially be optimized for better performance.

## References

1. [WebAuthn Specification - Packed Attestation](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation)
2. [FIDO Metadata Service](https://fidoalliance.org/metadata/)
3. [WebAuthn Specification - Attestation Types](https://www.w3.org/TR/webauthn-2/#sctn-attestation-types)
