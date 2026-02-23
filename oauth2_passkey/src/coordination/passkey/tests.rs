use super::*;
use crate::passkey::PasskeyCredential;
use crate::test_utils::init_test_environment;
use crate::userdb::User;
use serial_test::serial;

// ---- WebAuthn fixture helpers for _core() function testing ----

/// Fixed ECDSA P-256 private key in PKCS#8 DER format (131 bytes)
///
/// This key pair is shared with test_utils.rs (public key) and axum integration tests.
/// The public key stored in credentials must correspond to this private key for
/// authentication signature verification to succeed.
const FIRST_USER_PRIVATE_KEY: &[u8] = &[
    48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
    1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 139, 153, 75, 135, 130, 135, 200, 113, 147, 74, 215,
    126, 194, 20, 14, 216, 17, 194, 26, 44, 245, 110, 139, 6, 6, 189, 51, 208, 44, 171, 153, 197,
    161, 68, 3, 66, 0, 4, 27, 78, 131, 131, 196, 142, 118, 54, 201, 9, 43, 62, 50, 252, 223, 99,
    155, 195, 74, 137, 198, 36, 126, 188, 138, 20, 142, 51, 38, 144, 166, 242, 54, 51, 184, 181,
    61, 219, 148, 144, 37, 60, 142, 88, 223, 217, 195, 136, 217, 39, 237, 73, 228, 8, 86, 72, 75,
    127, 92, 98, 159, 103, 44, 251,
];

/// Build authenticator data bytes with attested credential data.
///
/// Creates the binary auth_data structure containing:
/// - RP ID hash (SHA-256 of the RP ID derived from origin)
/// - Flags byte (UP|UV|AT = 0x45)
/// - Counter (4 bytes, zero)
/// - AAGUID (16 bytes, zeros)
/// - Credential ID (length-prefixed)
/// - COSE public key (EC2 P-256)
fn build_auth_data_for_registration(origin: &str, credential_id_bytes: &[u8]) -> Vec<u8> {
    use ciborium::value::{Integer, Value as CborValue};
    use ring::signature;

    let rp_id = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    let mut auth_data = Vec::new();

    // RP ID hash (32 bytes)
    let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, rp_id.as_bytes());
    auth_data.extend_from_slice(rp_id_hash.as_ref());

    // Flags: UP|UV|AT = 0x45
    auth_data.push(0x45);

    // Counter (4 bytes)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // AAGUID (16 bytes, all zeros)
    auth_data.extend_from_slice(&[0x00; 16]);

    // Credential ID length (2 bytes big-endian)
    auth_data.extend_from_slice(&(credential_id_bytes.len() as u16).to_be_bytes());

    // Credential ID bytes
    auth_data.extend_from_slice(credential_id_bytes);

    // COSE public key - extract from the fixed key pair
    let rng = ring::rand::SystemRandom::new();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        FIRST_USER_PRIVATE_KEY,
        &rng,
    )
    .expect("Fixed key pair should be valid");

    let pk_bytes = ring::signature::KeyPair::public_key(&key_pair).as_ref();
    let x_coord = &pk_bytes[1..33];
    let y_coord = &pk_bytes[33..65];

    let cose_key = CborValue::Map(vec![
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ), // kty = EC2
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ), // alg = ES256
        (
            CborValue::Integer(Integer::from(-1)),
            CborValue::Integer(Integer::from(1)),
        ), // crv = P-256
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(x_coord.to_vec()),
        ), // x
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(y_coord.to_vec()),
        ), // y
    ]);

    let mut cose_key_bytes = Vec::new();
    ciborium::ser::into_writer(&cose_key, &mut cose_key_bytes).unwrap();
    auth_data.extend_from_slice(&cose_key_bytes);

    auth_data
}

/// Build a valid RegisterCredential JSON for "none" attestation format.
///
/// Uses the challenge from start_registration and constructs a client-side
/// WebAuthn response with "none" attestation (no signature validation needed).
fn build_none_registration_response(
    challenge: &str,
    user_handle: &str,
    origin: &str,
) -> serde_json::Value {
    use base64::{Engine as _, engine::general_purpose};
    use ciborium::value::Value as CborValue;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let credential_id = format!("test_cred_{ts}");
    let credential_id_bytes = credential_id.as_bytes();

    // Client data JSON
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": origin
    });
    let client_data_json =
        general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());

    // Auth data with attested credential
    let auth_data = build_auth_data_for_registration(origin, credential_id_bytes);

    // Attestation object with "none" format (no signature validation)
    let attestation_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        ),
        (
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(auth_data),
        ),
        (
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(vec![]),
        ),
    ]);

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&attestation_obj, &mut cbor_bytes).unwrap();
    let attestation_object = general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes);

    serde_json::json!({
        "id": credential_id,
        "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id_bytes),
        "response": {
            "client_data_json": client_data_json,
            "attestation_object": attestation_object,
        },
        "type": "public-key",
        "user_handle": user_handle
    })
}

/// Build a valid AuthenticatorResponse JSON with a cryptographically valid signature.
///
/// Uses the first_user private key to sign the authentication challenge,
/// matching the public key stored in the credential.
fn build_signed_authentication_response(
    credential_id: &str,
    challenge: &str,
    auth_id: &str,
    user_handle: &str,
    origin: &str,
) -> serde_json::Value {
    use base64::{Engine as _, engine::general_purpose};

    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        FIRST_USER_PRIVATE_KEY,
        &rng,
    )
    .expect("Fixed key pair should be valid");

    // Client data JSON
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin
    });
    let client_data_str = client_data.to_string();
    let client_data_hash = ring::digest::digest(&ring::digest::SHA256, client_data_str.as_bytes());
    let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data_str.as_bytes());

    // Authentication auth_data (no attested credential data)
    let rp_id = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    let mut auth_data = Vec::new();
    let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, rp_id.as_bytes());
    auth_data.extend_from_slice(rp_id_hash.as_ref());
    auth_data.push(0x05); // Flags: UP|UV (no AT for authentication)

    // Monotonically increasing counter
    use std::sync::atomic::{AtomicU32, Ordering};
    static AUTH_COUNTER: AtomicU32 = AtomicU32::new(100);
    let counter = AUTH_COUNTER.fetch_add(1, Ordering::Relaxed);
    auth_data.extend_from_slice(&counter.to_be_bytes());

    // Sign: auth_data + SHA256(client_data_json)
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());
    let sig = key_pair
        .sign(&rng, &signed_data)
        .expect("Signing should succeed");

    let auth_data_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&auth_data);
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref());

    serde_json::json!({
        "id": credential_id,
        "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id.as_bytes()),
        "response": {
            "client_data_json": client_data_json,
            "authenticator_data": auth_data_b64,
            "signature": signature_b64,
            "user_handle": user_handle
        },
        "type": "public-key",
        "authenticator_attachment": "platform",
        "auth_id": auth_id
    })
}

async fn create_test_user_in_db(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let user = User {
        id: user_id.to_string(),
        account: "test_account".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    UserStore::upsert_user(user).await?;
    Ok(())
}

/// Insert a test passkey credential for list/update/delete tests.
///
/// Uses a placeholder public key because these tests do not perform signature
/// verification. For end-to-end authentication tests, use the real key pair
/// from `FIRST_USER_PRIVATE_KEY` / `generate_first_user_public_key()` instead.
async fn insert_test_passkey_credential(
    credential_id: &str,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = serde_json::json!({
        "name": "Test User",
        "displayName": "Test Display Name",
        "user_handle": user_id.to_string()
    });

    let passkey_user = serde_json::from_value(user).expect("Failed to create user entity");

    // Placeholder public key: not a valid EC key, but sufficient for
    // list/update/delete tests that never verify signatures.
    let credential = PasskeyCredential {
        credential_id: credential_id.to_string(),
        user_id: user_id.to_string(),
        public_key: "test_public_key".to_string(),
        aaguid: "test-aaguid".to_string(),
        rp_id: "127.0.0.1".to_string(),
        user: passkey_user,
        counter: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_used_at: Utc::now(),
    };

    PasskeyStore::store_credential(
        CredentialId::new(credential.credential_id.clone()).expect("Valid test credential ID"),
        credential,
    )
    .await?;
    Ok(())
}

/// Test deletion of a nonexistent passkey credential
///
/// This test verifies that `delete_passkey_credential_core` returns a ResourceNotFound error
/// when called with a credential ID that does not exist in the database.
/// It performs the following steps:
/// 1. Initializes a test environment
/// 2. Creates a test user in the database
/// 3. Calls `delete_passkey_credential_core` with a nonexistent credential ID
/// 4. Verifies that the function returns a ResourceNotFound error
///
#[tokio::test]
#[serial]
async fn test_delete_passkey_credential_core_not_found() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test database
    init_test_environment().await;

    // Create test user
    let user_id = "test_user_4";
    let credential_id = "nonexistent_credential";

    create_test_user_in_db(user_id).await?;

    // Try to delete a nonexistent passkey credential
    let result = delete_passkey_credential_core(
        UserId::new(user_id.to_string()).expect("Valid user ID"),
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
    )
    .await;
    assert!(
        matches!(result, Err(CoordinationError::ResourceNotFound { .. })),
        "Expected ResourceNotFound error, got: {result:?}"
    );

    Ok(())
}

/// Test successful update of a passkey credential
///
/// This test verifies that `update_passkey_credential_core` correctly updates
/// a passkey credential when given valid input. It performs the following steps:
/// 1. Initializes a test environment
/// 2. Creates a test user and passkey credential in the database
/// 3. Calls `update_passkey_credential_core` to update the credential
/// 4. Verifies that the credential was successfully updated
///
#[tokio::test]
#[serial]
async fn test_update_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test user and passkey credential
    let user_id = "test_user_6";
    let credential_id = "test_credential_6";

    create_test_user_in_db(user_id).await?;
    insert_test_passkey_credential(credential_id, user_id).await?;

    // Create a session user for authentication
    let session_user = SessionUser {
        id: user_id.to_string(),
        account: "test_account".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Update the passkey credential
    let new_name = "Updated Name";
    let new_display_name = "Updated Display Name";
    let result = update_passkey_credential_core(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
        new_name,
        new_display_name,
        Some(session_user),
    )
    .await;

    assert!(
        result.is_ok(),
        "Failed to update passkey credential: {result:?}"
    );

    // Verify the credential was updated
    let updated_credential = PasskeyStore::get_credential(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
    )
    .await?
    .unwrap();
    assert_eq!(
        updated_credential.user.name, new_name,
        "Name was not updated"
    );
    assert_eq!(
        updated_credential.user.display_name, new_display_name,
        "Display name was not updated"
    );

    Ok(())
}

/// Test unauthorized update of a passkey credential
///
/// This test verifies that `update_passkey_credential_core` returns an Unauthorized error
/// when called with a different user ID than the one associated with the credential.
/// It performs the following steps:
/// 1. Initializes a test environment
/// 2. Creates test users and a passkey credential in the database
/// 3. Calls `update_passkey_credential_core` with a different user ID
/// 4. Verifies that the function returns an Unauthorized error
///
#[tokio::test]
#[serial]
async fn test_update_passkey_credential_core_unauthorized() -> Result<(), Box<dyn std::error::Error>>
{
    // Setup test environment
    init_test_environment().await;

    // Create test users and passkey credential
    let user_id = "test_user_7";
    let other_user_id = "test_user_8";
    let credential_id = "test_credential_7";

    create_test_user_in_db(user_id).await?;
    create_test_user_in_db(other_user_id).await?;
    insert_test_passkey_credential(credential_id, user_id).await?;

    // Create a session user for authentication with a different user ID
    let session_user = SessionUser {
        id: other_user_id.to_string(),
        account: "other_account".to_string(),
        label: "Other User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Try to update the passkey credential as a different user
    let result = update_passkey_credential_core(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
        "Updated Name",
        "Updated Display Name",
        Some(session_user),
    )
    .await;

    assert!(
        matches!(result, Err(CoordinationError::Unauthorized)),
        "Expected Unauthorized error, got: {result:?}"
    );

    Ok(())
}

/// Test update of a passkey credential without a session user
///
/// This test verifies that `update_passkey_credential_core` returns an Unauthorized error
/// when called without a session user. It performs the following steps:
/// 1. Initializes a test environment
/// 2. Creates a test user and passkey credential in the database
/// 3. Calls `update_passkey_credential_core` without a session user
/// 4. Verifies that the function returns an Unauthorized error
///
#[tokio::test]
#[serial]
async fn test_update_passkey_credential_core_no_session() -> Result<(), Box<dyn std::error::Error>>
{
    // Setup test environment
    init_test_environment().await;

    // Create test user and passkey credential
    let user_id = "test_user_9";
    let credential_id = "test_credential_9";

    create_test_user_in_db(user_id).await?;
    insert_test_passkey_credential(credential_id, user_id).await?;

    // Try to update the passkey credential without a session user
    let result = update_passkey_credential_core(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
        "Updated Name",
        "Updated Display Name",
        None,
    )
    .await;

    assert!(
        matches!(result, Err(CoordinationError::Unauthorized)),
        "Expected Unauthorized error, got: {result:?}"
    );

    Ok(())
}

/// Test listing credentials for a user with stored credentials
///
/// Verifies that `list_credentials_core` returns the correct credentials
/// when the user has multiple passkey credentials in the database.
///
#[tokio::test]
#[serial]
async fn test_list_credentials_core_with_credentials() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let user_id = "test_user_list_1";
    create_test_user_in_db(user_id).await?;
    insert_test_passkey_credential("cred_list_1a", user_id).await?;
    insert_test_passkey_credential("cred_list_1b", user_id).await?;

    let result =
        list_credentials_core(UserId::new(user_id.to_string()).expect("Valid user ID")).await?;

    assert_eq!(result.len(), 2, "Should return 2 credentials");
    let credential_ids: Vec<&str> = result.iter().map(|c| c.credential_id.as_str()).collect();
    assert!(
        credential_ids.contains(&"cred_list_1a"),
        "Should contain first credential"
    );
    assert!(
        credential_ids.contains(&"cred_list_1b"),
        "Should contain second credential"
    );

    Ok(())
}

/// Test listing credentials for a user with no credentials
///
/// Verifies that `list_credentials_core` returns an empty list when the user
/// has no passkey credentials in the database.
///
#[tokio::test]
#[serial]
async fn test_list_credentials_core_empty() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let user_id = "test_user_list_empty";
    create_test_user_in_db(user_id).await?;

    let result =
        list_credentials_core(UserId::new(user_id.to_string()).expect("Valid user ID")).await?;

    assert!(
        result.is_empty(),
        "Should return empty list for user with no credentials"
    );

    Ok(())
}

/// Test handle_start_registration_core in CreateUser mode without auth
///
/// Verifies that a new user can start passkey registration without being
/// authenticated (the expected flow for new user creation).
///
#[tokio::test]
#[serial]
async fn test_start_registration_core_create_user_mode() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let body = RegistrationStartRequest {
        username: "new_user@example.com".to_string(),
        displayname: "New User".to_string(),
        mode: RegistrationMode::CreateUser,
    };

    let result = handle_start_registration_core(None, body).await;
    assert!(
        result.is_ok(),
        "CreateUser mode without auth should succeed: {result:?}"
    );

    let options = result.unwrap();
    let options_json = serde_json::to_value(&options)?;
    assert!(
        !options_json["challenge"].as_str().unwrap_or("").is_empty(),
        "Should contain a non-empty challenge"
    );
    assert_eq!(
        options_json["rpId"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP ID should match the test origin host"
    );
    assert_eq!(
        options_json["rp"]["id"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP entity ID should match rpId"
    );
    assert!(
        options_json["user"]["user_handle"].is_string(),
        "Should contain a user handle"
    );
    assert_eq!(
        options_json["user"]["name"].as_str().unwrap_or(""),
        "new_user@example.com",
        "User name should match the requested username"
    );
    assert_eq!(
        options_json["user"]["displayName"].as_str().unwrap_or(""),
        "New User",
        "Display name should match the requested displayname"
    );
    assert!(
        options_json["pubKeyCredParams"].is_array(),
        "Should contain pubKeyCredParams"
    );

    Ok(())
}

/// Test handle_start_registration_core in CreateUser mode with auth (should reject)
///
/// Verifies that an already-authenticated user cannot start a "create new user"
/// registration flow. This prevents accidental account creation while logged in.
///
#[tokio::test]
#[serial]
async fn test_start_registration_core_create_user_rejects_authenticated()
-> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let session_user = SessionUser {
        id: "test_user_reg_create".to_string(),
        account: "test_account".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let body = RegistrationStartRequest {
        username: "new_user@example.com".to_string(),
        displayname: "New User".to_string(),
        mode: RegistrationMode::CreateUser,
    };

    let result = handle_start_registration_core(Some(&session_user), body).await;
    assert!(
        matches!(result, Err(CoordinationError::UnexpectedlyAuthorized)),
        "CreateUser mode with auth should fail with UnexpectedlyAuthorized: {result:?}"
    );

    Ok(())
}

/// Test handle_start_registration_core in AddToUser mode with auth
///
/// Verifies that an authenticated user can start adding a new passkey
/// to their existing account.
///
#[tokio::test]
#[serial]
async fn test_start_registration_core_add_to_user_mode() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let user_id = "test_user_reg_add";
    create_test_user_in_db(user_id).await?;

    let session_user = SessionUser {
        id: user_id.to_string(),
        account: "test_account".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let body = RegistrationStartRequest {
        username: "test_user@example.com".to_string(),
        displayname: "Test User".to_string(),
        mode: RegistrationMode::AddToUser,
    };

    let result = handle_start_registration_core(Some(&session_user), body).await;
    assert!(
        result.is_ok(),
        "AddToUser mode with auth should succeed: {result:?}"
    );

    let options = result.unwrap();
    let options_json = serde_json::to_value(&options)?;
    assert!(
        !options_json["challenge"].as_str().unwrap_or("").is_empty(),
        "Should contain a non-empty challenge"
    );
    assert_eq!(
        options_json["rpId"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP ID should match the test origin host"
    );
    assert!(
        options_json["user"]["user_handle"].is_string(),
        "Should contain a user handle"
    );

    Ok(())
}

/// Test handle_start_registration_core in AddToUser mode without auth (should reject)
///
/// Verifies that adding a passkey to an existing user requires authentication.
/// Without a session, the server cannot determine which user to add the passkey to.
///
#[tokio::test]
#[serial]
async fn test_start_registration_core_add_to_user_rejects_unauthenticated()
-> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let body = RegistrationStartRequest {
        username: "test_user@example.com".to_string(),
        displayname: "Test User".to_string(),
        mode: RegistrationMode::AddToUser,
    };

    let result = handle_start_registration_core(None, body).await;
    assert!(
        matches!(result, Err(CoordinationError::Unauthorized)),
        "AddToUser mode without auth should fail with Unauthorized: {result:?}"
    );

    Ok(())
}

/// Test handle_start_authentication_core with no username (discoverable credential flow)
///
/// Verifies that starting authentication without a username succeeds.
/// This is the discoverable credential (passkey) flow where the authenticator
/// presents available credentials to the user.
///
#[tokio::test]
#[serial]
async fn test_start_authentication_core_no_username() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let body = serde_json::json!({});
    let result = handle_start_authentication_core(&body).await;
    assert!(
        result.is_ok(),
        "Authentication without username should succeed: {result:?}"
    );

    let options = result.unwrap();
    let options_json = serde_json::to_value(&options)?;
    assert!(
        !options_json["challenge"].as_str().unwrap_or("").is_empty(),
        "Should contain a non-empty challenge"
    );
    assert_eq!(
        options_json["rpId"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP ID should match the test origin host"
    );
    assert!(
        options_json["authId"].is_string(),
        "Should contain an authId"
    );
    // Discoverable flow: allowCredentials should be empty (no username filtering)
    assert!(
        options_json["allowCredentials"]
            .as_array()
            .is_none_or(|a| a.is_empty()),
        "Discoverable flow should have empty allowCredentials"
    );

    Ok(())
}

/// Test handle_start_authentication_core with a username matching stored credentials
///
/// Verifies that starting authentication with a known username succeeds.
/// The username is used to look up stored credentials by user_name column.
///
#[tokio::test]
#[serial]
async fn test_start_authentication_core_with_username() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    // Create a user with a passkey credential
    // The credential's user.name = "Test User" (set in insert_test_passkey_credential)
    let user_id = "test_user_auth_start";
    create_test_user_in_db(user_id).await?;
    insert_test_passkey_credential("cred_auth_start_1", user_id).await?;

    // Search by the credential's user.name field stored as user_name in DB
    let body = serde_json::json!({ "username": "Test User" });
    let result = handle_start_authentication_core(&body).await;
    assert!(
        result.is_ok(),
        "Authentication with known username should succeed: {result:?}"
    );

    let options = result.unwrap();
    let options_json = serde_json::to_value(&options)?;
    assert!(
        !options_json["challenge"].as_str().unwrap_or("").is_empty(),
        "Should contain a non-empty challenge"
    );
    assert_eq!(
        options_json["rpId"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP ID should match the test origin host"
    );
    assert!(
        options_json["authId"].is_string(),
        "Should contain an authId"
    );
    // With known username: allowCredentials should contain the matching credential
    let allow_creds = options_json["allowCredentials"]
        .as_array()
        .expect("Should have allowCredentials array");
    assert!(
        !allow_creds.is_empty(),
        "Should have non-empty allowCredentials for known username"
    );
    assert!(
        allow_creds
            .iter()
            .any(|c| c["id"].as_str() == Some("cred_auth_start_1")),
        "allowCredentials should contain the test credential"
    );

    Ok(())
}

/// Test handle_start_authentication_core with nonexistent username
///
/// Verifies that starting authentication with an unknown username still succeeds
/// (returns options with empty allow_credentials for discoverable credential fallback).
///
#[tokio::test]
#[serial]
async fn test_start_authentication_core_nonexistent_username()
-> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let body = serde_json::json!({ "username": "nonexistent_user_12345" });
    let result = handle_start_authentication_core(&body).await;
    assert!(
        result.is_ok(),
        "Authentication with nonexistent username should succeed: {result:?}"
    );

    let options = result.unwrap();
    let options_json = serde_json::to_value(&options)?;
    assert!(
        !options_json["challenge"].as_str().unwrap_or("").is_empty(),
        "Should contain a non-empty challenge"
    );
    assert_eq!(
        options_json["rpId"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP ID should match the test origin host"
    );
    // Nonexistent username: allowCredentials should be empty (no matching credentials)
    let allow_creds = options_json["allowCredentials"]
        .as_array()
        .expect("Should have allowCredentials array");
    assert!(
        allow_creds.is_empty(),
        "Should have empty allowCredentials for nonexistent username"
    );

    Ok(())
}

/// Test handle_start_authentication_core with string body format
///
/// Verifies that the function handles a plain string value as the body,
/// treating it as the username directly.
///
#[tokio::test]
#[serial]
async fn test_start_authentication_core_string_body() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let body = serde_json::json!("some_username");
    let result = handle_start_authentication_core(&body).await;
    assert!(
        result.is_ok(),
        "Authentication with string body should succeed: {result:?}"
    );

    let options = result.unwrap();
    let options_json = serde_json::to_value(&options)?;
    assert!(
        !options_json["challenge"].as_str().unwrap_or("").is_empty(),
        "Should contain a non-empty challenge"
    );
    assert_eq!(
        options_json["rpId"].as_str().unwrap_or(""),
        "127.0.0.1",
        "RP ID should match the test origin host"
    );
    assert!(
        options_json["authId"].is_string(),
        "Should contain an authId"
    );

    Ok(())
}

/// Test handle_finish_registration_core in CreateUser mode (full end-to-end)
///
/// Exercises the complete new-user registration flow:
/// 1. Start registration (stores challenge in cache)
/// 2. Construct valid WebAuthn response with "none" attestation
/// 3. Finish registration (validates challenge, creates user, stores credential, creates session)
///
#[tokio::test]
#[serial]
async fn test_finish_registration_core_create_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let origin = crate::test_utils::get_test_origin();

    // Step 1: Start registration to get challenge stored in cache
    let body = RegistrationStartRequest {
        username: "finish_reg_user@example.com".to_string(),
        displayname: "Finish Reg User".to_string(),
        mode: RegistrationMode::CreateUser,
    };
    let options = handle_start_registration_core(None, body).await?;

    // Step 2: Extract challenge and user_handle from serialized options
    let options_json = serde_json::to_value(&options)?;
    let challenge = options_json["challenge"]
        .as_str()
        .expect("Options should contain challenge");
    let user_handle = options_json["user"]["user_handle"]
        .as_str()
        .expect("Options should contain user.user_handle");

    // Step 3: Construct valid RegisterCredential
    let reg_data_json = build_none_registration_response(challenge, user_handle, &origin);
    let reg_data: RegisterCredential = serde_json::from_value(reg_data_json)?;

    // Step 4: Finish registration (CreateUser mode: no auth_user)
    let result = handle_finish_registration_core(None, reg_data).await;
    assert!(
        result.is_ok(),
        "CreateUser finish registration should succeed: {result:?}"
    );

    let (headers, message) = result.unwrap();
    assert!(!message.is_empty(), "Should return a success message");
    // CreateUser mode creates a session -> headers should contain session cookie
    assert!(
        !headers.is_empty(),
        "Should contain session headers for newly created user"
    );

    Ok(())
}

/// Test handle_finish_registration_core in AddToUser mode (full end-to-end)
///
/// Exercises the add-credential-to-existing-user flow:
/// 1. Create a user
/// 2. Start registration with auth user (stores challenge + session info in cache)
/// 3. Construct valid WebAuthn response
/// 4. Finish registration (validates session, stores credential)
///
#[tokio::test]
#[serial]
async fn test_finish_registration_core_add_to_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let origin = crate::test_utils::get_test_origin();
    let user_id = "test_user_finish_reg_add";
    create_test_user_in_db(user_id).await?;

    let session_user = SessionUser {
        id: user_id.to_string(),
        account: "test_account".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Step 1: Start registration with authenticated user
    let body = RegistrationStartRequest {
        username: "add_cred_user@example.com".to_string(),
        displayname: "Add Cred User".to_string(),
        mode: RegistrationMode::AddToUser,
    };
    let options = handle_start_registration_core(Some(&session_user), body).await?;

    // Step 2: Extract challenge and user_handle
    let options_json = serde_json::to_value(&options)?;
    let challenge = options_json["challenge"]
        .as_str()
        .expect("Options should contain challenge");
    let user_handle = options_json["user"]["user_handle"]
        .as_str()
        .expect("Options should contain user.user_handle");

    // Step 3: Construct valid RegisterCredential
    let reg_data_json = build_none_registration_response(challenge, user_handle, &origin);
    let reg_data: RegisterCredential = serde_json::from_value(reg_data_json)?;

    // Step 4: Finish registration (AddToUser mode: with auth_user)
    let result = handle_finish_registration_core(Some(&session_user), reg_data).await;
    assert!(
        result.is_ok(),
        "AddToUser finish registration should succeed: {result:?}"
    );

    let (headers, message) = result.unwrap();
    assert!(!message.is_empty(), "Should return a success message");
    // AddToUser mode does NOT create a new session -> headers should be empty
    assert!(
        headers.is_empty(),
        "Should not contain session headers for existing user"
    );

    // Verify: the user now has a stored credential
    let credentials =
        list_credentials_core(UserId::new(user_id.to_string()).expect("Valid user ID")).await?;
    assert!(
        !credentials.is_empty(),
        "User should have at least one credential after registration"
    );

    Ok(())
}

/// Test handle_finish_authentication_core (full end-to-end)
///
/// Exercises the complete authentication flow:
/// 1. Use the first-user credential (created by init_test_environment)
/// 2. Start authentication to get challenge stored in cache
/// 3. Construct a signed authenticator response using the matching private key
/// 4. Finish authentication (verifies signature, creates session, records login)
///
#[tokio::test]
#[serial]
async fn test_finish_authentication_core_success() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    let origin = crate::test_utils::get_test_origin();
    let credential_id = "first-user-test-passkey-credential";
    let user_handle = "first-user-handle";

    // Step 1: Start authentication (stores challenge in cache)
    let body = serde_json::json!({});
    let auth_options = handle_start_authentication_core(&body).await?;

    // Step 2: Extract challenge and auth_id from serialized options
    let options_json = serde_json::to_value(&auth_options)?;
    let challenge = options_json["challenge"]
        .as_str()
        .expect("Options should contain challenge");
    let auth_id = options_json["authId"]
        .as_str()
        .expect("Options should contain authId");

    // Step 3: Construct signed AuthenticatorResponse
    let auth_response_json = build_signed_authentication_response(
        credential_id,
        challenge,
        auth_id,
        user_handle,
        &origin,
    );
    let auth_response: AuthenticatorResponse = serde_json::from_value(auth_response_json)?;

    // Step 4: Finish authentication
    let result = handle_finish_authentication_core(auth_response, None).await;
    assert!(result.is_ok(), "Authentication should succeed: {result:?}");

    let (auth_resp, headers) = result.unwrap();
    assert_eq!(
        auth_resp.user_handle, user_handle,
        "Should return correct user_handle"
    );
    assert!(
        !auth_resp.credential_ids.is_empty(),
        "Should return at least one credential ID"
    );
    assert!(
        auth_resp
            .credential_ids
            .contains(&credential_id.to_string()),
        "Should contain the authenticated credential ID"
    );
    // Authentication creates a session
    assert!(!headers.is_empty(), "Should contain session headers");

    Ok(())
}

/// Test default field mappings
///
/// This test verifies that `get_passkey_field_mappings` returns the default field mappings
/// when called without any environment variables set. It performs the following steps:
/// 1. Initializes a test environment
/// 2. Calls `get_passkey_field_mappings` to retrieve the field mappings
/// 3. Verifies that the returned values are the default values
///
#[test]
fn test_get_passkey_field_mappings_defaults() {
    // Test default mappings - since .env_test doesn't set these variables,
    // they should use their default values
    let (account_field, label_field) = get_passkey_field_mappings();
    assert_eq!(
        account_field, "name",
        "Default account field should be 'name'"
    );
    assert_eq!(
        label_field, "display_name",
        "Default label field should be 'display_name'"
    );
}
