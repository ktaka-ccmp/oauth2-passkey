# TPM Attestation in WebAuthn

This document describes the TPM (Trusted Platform Module) attestation format as implemented in the oauth2-passkey library, following the WebAuthn specification.

## Overview

TPM attestation is used by authenticators that use a Trusted Platform Module as their cryptographic engine. The TPM attestation statement format is identified by the string "tpm" and supports the AttCA attestation type.

## Attestation Statement Format

The TPM attestation statement follows this structure:

```json
attStmtType = (
    fmt: "tpm",
    attStmt: tpmStmtFormat
)

tpmStmtFormat = {
    ver: "2.0",
    (
        alg: COSEAlgorithmIdentifier,
        x5c: [ aikCert: bytes, * (caCert: bytes) ]
    )
    sig: bytes,
    certInfo: bytes,
    pubArea: bytes
}
```

### Field Descriptions

- **ver**: The version of the TPM specification to which the signature conforms.
- **alg**: A COSEAlgorithmIdentifier containing the identifier of the algorithm used to generate the attestation signature.
- **x5c**: aikCert followed by its certificate chain, in X.509 encoding.
  - **aikCert**: The AIK certificate used for the attestation, in X.509 encoding.
- **sig**: The attestation signature, in the form of a TPMT_SIGNATURE structure.
- **certInfo**: The TPMS_ATTEST structure over which the signature was computed.
- **pubArea**: The TPMT_PUBLIC structure used by the TPM to represent the credential public key.

## Verification Procedure

The verification procedure for TPM attestation statements follows these steps:

1. **Basic Structure Verification**:
   - Verify that the attestation statement is valid CBOR with the required fields (ver, alg, x5c, sig, certInfo, pubArea)
   - Check that the version is "2.0"

2. **Public Key Verification**:
   - Verify that the public key in pubArea matches the credential public key in authenticatorData

3. **certInfo Validation**:
   - Verify that magic is set to TPM_GENERATED_VALUE
   - Verify that type is set to TPM_ST_ATTEST_CERTIFY
   - Verify that extraData is set to the hash of attToBeSigned (authenticatorData + clientDataHash)
   - Verify that attested contains a valid TPMS_CERTIFY_INFO structure with the correct name field

4. **x5c Verification**:
   - Verify that x5c is present
   - The qualifiedSigner, clockInfo, and firmwareVersion fields are ignored

5. **Signature Verification**:
   - Verify that the signature is valid over certInfo using the attestation public key in aikCert

6. **AIK Certificate Requirements**:
   - Verify that the AIK certificate version is 3
   - Verify that the Subject field is empty
   - Verify the Subject Alternative Name extension
   - Verify the Extended Key Usage extension contains the required OID (2.23.133.8.3)
   - Verify the Basic Constraints extension has CA set to false
   - If present, verify the AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4) matches the AAGUID in authenticatorData

## TPM Structures

### TPMS_ATTEST Structure

The TPMS_ATTEST structure contains the following fields:

- **magic**: Must be set to TPM_GENERATED_VALUE (0xff544347)
- **type**: Must be set to TPM_ST_ATTEST_CERTIFY (0x8017)
- **qualifiedSigner**: TPM name of the key signing the attestation
- **extraData**: The hash of attToBeSigned (authenticatorData + clientDataHash)
- **clockInfo**: Information about the TPM's clock
- **firmwareVersion**: The TPM's firmware version
- **attested**: Contains a TPMS_CERTIFY_INFO structure

### TPMS_CERTIFY_INFO Structure

The TPMS_CERTIFY_INFO structure contains:

- **name**: The TPM name of the certified key (hash of pubArea)
- **qualifiedName**: The qualified name of the certified key

### Name Verification

The name field in the TPMS_CERTIFY_INFO structure is a hash of the pubArea using the nameAlg algorithm. The verification process includes:

```rust
// Extract the name algorithm from pubArea
let _name_alg = u16::from_be_bytes([pub_area[2], pub_area[3]]);

// Calculate the hash of pubArea using the nameAlg
let pub_area_hash = match _name_alg {
    0x000B => {
        // TPM_ALG_SHA256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(pub_area);
        hasher.finalize().to_vec()
    }
    0x000C => {
        // TPM_ALG_SHA384
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(pub_area);
        hasher.finalize().to_vec()
    }
    0x000D => {
        // TPM_ALG_SHA512
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(pub_area);
        hasher.finalize().to_vec()
    }
    _ => {
        // Unsupported algorithm
        return Error;
    }
};

// The name field includes a 2-byte algorithm ID followed by the hash
// Verify that the hash part matches our calculated hash
```

## AIK Certificate Verification

The AIK certificate must meet specific requirements:

1. **Version**: Must be set to 3
2. **Subject**: Must be empty
3. **Subject Alternative Name**: Must be present as defined in TPMv2-EK-Profile
4. **Extended Key Usage**: Must contain the OID 2.23.133.8.3
5. **Basic Constraints**: Must have CA set to false
6. **AAGUID Extension**: If present (OID 1.3.6.1.4.1.45724.1.1.4), must match the AAGUID in authenticatorData

## Compliance Assessment

The oauth2-passkey library implementation of TPM attestation has been assessed against the WebAuthn specification requirements. Here's a summary of the compliance status:

| Requirement | Status | Notes |
|-------------|--------|-------|
| Basic Structure Verification | ✅ Compliant | Verifies all required fields and format |
| Public Key Verification | ✅ Compliant | Ensures pubArea matches credentialPublicKey |
| certInfo Validation | ✅ Compliant | Verifies magic, type, extraData, and attested fields |
| x5c Verification | ✅ Compliant | Checks presence and properly ignores specified fields |
| Signature Verification | ✅ Compliant | Validates signature over certInfo using AIK certificate |
| AIK Certificate Version | ✅ Compliant | Verifies version is 3 |
| AIK Certificate Subject | ✅ Compliant | Verifies subject is empty |
| Subject Alternative Name | ✅ Compliant | Verifies extension is present |
| Extended Key Usage | ✅ Compliant | Verifies OID 2.23.133.8.3 is present |
| Basic Constraints | ✅ Compliant | Verifies CA is false |
| AAGUID Extension | ✅ Compliant | Verifies match with authenticatorData when present |

### Areas for Improvement

While the implementation is fully compliant with the WebAuthn specification, there are some areas that could be enhanced:

1. **Fallback Verification Robustness**: The fallback verification using x509-parser could benefit from more detailed error messages to help diagnose specific validation failures.

2. **Error Handling**: Current error handling could be enhanced with more specific error types for each verification step.

3. **Testing Coverage**: Comprehensive tests for various edge cases and failure modes would strengthen the implementation.

4. **Performance Optimization**: The current implementation prioritizes correctness and compliance over performance. There may be opportunities to optimize the verification process for high-volume deployments.

## Implementation Notes

- The library uses both webpki and x509-parser for certificate verification
- A fallback verification mechanism is implemented when webpki cannot parse the certificate
- The implementation follows a modular approach to separate core attestation logic from TPM-specific logic
- Comprehensive error handling is provided throughout the attestation verification process

## References

1. [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
2. [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
3. [TPM 2.0 EK Profile](https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/)
