use base64::{Engine as _, engine::general_purpose};
use serde_json::{Value, json};

/// Test user fixtures for integration testing
pub struct TestUsers;

impl TestUsers {
    /// Get a standard test user for OAuth2 flows
    pub fn oauth2_user() -> TestUser {
        TestUser {
            id: "test_oauth2_user".to_string(),
            email: "oauth2@example.com".to_string(),
            name: "OAuth2 Test User".to_string(),
            given_name: "OAuth2".to_string(),
            family_name: "User".to_string(),
        }
    }

    /// Get a standard test user for passkey flows
    pub fn passkey_user() -> TestUser {
        TestUser {
            id: "test_passkey_user".to_string(),
            email: "passkey@example.com".to_string(),
            name: "Passkey Test User".to_string(),
            given_name: "Passkey".to_string(),
            family_name: "User".to_string(),
        }
    }

    /// Get an admin test user
    pub fn admin_user() -> TestUser {
        TestUser {
            id: "test_admin_user".to_string(),
            email: "admin@example.com".to_string(),
            name: "Admin Test User".to_string(),
            given_name: "Admin".to_string(),
            family_name: "User".to_string(),
        }
    }
}

/// Test user data structure
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
}

impl TestUser {
    /// Convert to OAuth2 userinfo response format
    pub fn to_oauth2_userinfo(&self) -> Value {
        json!({
            "id": self.id,
            "sub": self.id,
            "email": self.email,
            "name": self.name,
            "given_name": self.given_name,
            "family_name": self.family_name,
            "picture": format!("https://example.com/avatar/{}.jpg", self.id)
        })
    }
}

/// Mock WebAuthn credentials for testing
pub struct MockWebAuthnCredentials;

impl MockWebAuthnCredentials {
    /// Generate a mock registration credential response
    pub fn registration_response(username: &str, _display_name: &str) -> Value {
        let user_handle =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{username}"));
        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibW9ja19jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAifQ",
                "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAK3-KAQt7h2gWk7pJFaOY7gAQbW9ja19jcmVkZW50aWFsX2lkXzEyM6UBAgMmIAEhWCBh7UdJLMdGfhQwBYwfh7dHGl9Yt2bQcRHjdSFNdlRa-yJYIP8QAEkjzIjTa7dKd2Md6_7kEbCFKCwqJqEjz1hNaFjk",
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Generate a mock registration credential response with a specific challenge
    #[allow(dead_code)]
    pub fn registration_response_with_challenge(
        username: &str,
        _display_name: &str,
        challenge: &str,
    ) -> Value {
        let user_handle =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{username}"));

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": "http://localhost:3000"
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": client_data_json,
                "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAK3-KAQt7h2gWk7pJFaOY7gAQbW9ja19jcmVkZW50aWFsX2lkXzEyM6UBAgMmIAEhWCBh7UdJLMdGfhQwBYwfh7dHGl9Yt2bQcRHjdSFNdlRa-yJYIP8QAEkjzIjTa7dKd2Md6_7kEbCFKCwqJqEjz1hNaFjk",
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Generate a mock registration credential response with specific challenge and user_handle
    #[allow(dead_code)]
    pub fn registration_response_with_challenge_and_user_handle(
        _username: &str,
        _display_name: &str,
        challenge: &str,
        user_handle: &str,
    ) -> Value {
        Self::registration_response_with_challenge_user_handle_and_origin(
            _username,
            _display_name,
            challenge,
            user_handle,
            "http://localhost:3000",
        )
    }

    /// Generate a mock registration credential response with specific challenge, user_handle, and origin
    pub fn registration_response_with_challenge_user_handle_and_origin(
        _username: &str,
        _display_name: &str,
        challenge: &str,
        user_handle: &str,
        _origin: &str,
    ) -> Value {
        // Use the actual test origin to match LazyLock ORIGIN configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": test_origin
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": client_data_json,
                "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAK3-KAQt7h2gWk7pJFaOY7gAQbW9ja19jcmVkZW50aWFsX2lkXzEyM6UBAgMmIAEhWCBh7UdJLMdGfhQwBYwfh7dHGl9Yt2bQcRHjdSFNdlRa-yJYIP8QAEkjzIjTa7dKd2Md6_7kEbCFKCwqJqEjz1hNaFjk",
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Generate a mock authentication assertion response
    #[allow(dead_code)]
    pub fn authentication_response(credential_id: &str) -> Value {
        json!({
            "id": credential_id,
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "response": {
                "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibW9ja19hdXRoX2NoYWxsZW5nZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9",
                "authenticator_data": "EsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaABAAAAAw",
                "signature": "MEUCIQCj8BLqLqxHWBULHOhD6YKl7z8mhVisuLr1jq8MNkJ6nAIgOhYZ-tScOLJ8q5OLqxOdCJlF8zN7K9C7ZXjNFkJQhzg",
                "user_handle": general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{credential_id}"))
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "auth_id": "mock_auth_id_123"
        })
    }

    /// Generate a mock authentication assertion response with specific challenge
    #[allow(dead_code)]
    pub fn authentication_response_with_challenge(credential_id: &str, challenge: &str) -> Value {
        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:3000"
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": credential_id,
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "response": {
                "client_data_json": client_data_json,
                "authenticator_data": "EsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaABAAAAAw",
                "signature": "MEUCIQCj8BLqLqxHWBULHOhD6YKl7z8mhVisuLr1jq8MNkJ6nAIgOhYZ-tScOLJ8q5OLqxOdCJlF8zN7K9C7ZXjNFkJQhzg",
                "user_handle": general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{credential_id}"))
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "auth_id": "mock_auth_id_123"
        })
    }

    /// Generate a mock authentication assertion response with specific challenge and auth_id
    #[allow(dead_code)]
    pub fn authentication_response_with_challenge_and_auth_id(
        credential_id: &str,
        challenge: &str,
        auth_id: &str,
    ) -> Value {
        Self::authentication_response_with_challenge_auth_id_and_origin(
            credential_id,
            challenge,
            auth_id,
            "http://localhost:3000",
        )
    }

    /// Generate a mock authentication assertion response with specific challenge, auth_id, and origin
    pub fn authentication_response_with_challenge_auth_id_and_origin(
        credential_id: &str,
        challenge: &str,
        auth_id: &str,
        _origin: &str,
    ) -> Value {
        // Use the actual test origin to match LazyLock ORIGIN configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": test_origin
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": credential_id,
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "response": {
                "client_data_json": client_data_json,
                "authenticator_data": "EsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaABAAAAAw",
                "signature": "MEUCIQCj8BLqLqxHWBULHOhD6YKl7z8mhVisuLr1jq8MNkJ6nAIgOhYZ-tScOLJ8q5OLqxOdCJlF8zN7K9C7ZXjNFkJQhzg",
                "user_handle": general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{credential_id}"))
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "auth_id": auth_id
        })
    }

    /// Generate mock registration options (what server would send to client)
    #[allow(dead_code)]
    pub fn registration_options(username: &str, display_name: &str) -> Value {
        json!({
            "rp": {
                "name": "OAuth2-Passkey Test",
                "id": "localhost"
            },
            "user": {
                "id": general_purpose::STANDARD.encode(format!("user_{username}")),
                "name": username,
                "displayName": display_name
            },
            "challenge": general_purpose::STANDARD.encode("mock_challenge_bytes"),
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "required",
                "residentKey": "preferred"
            }
        })
    }

    /// Generate mock authentication options (what server would send to client)
    #[allow(dead_code)]
    pub fn authentication_options(allowed_credentials: Option<Vec<&str>>) -> Value {
        let allowed_creds = if let Some(creds) = allowed_credentials {
            creds
                .iter()
                .map(|id| {
                    json!({
                        "type": "public-key",
                        "id": general_purpose::STANDARD.encode(id)
                    })
                })
                .collect()
        } else {
            vec![]
        };

        json!({
            "challenge": general_purpose::STANDARD.encode("mock_auth_challenge_bytes"),
            "timeout": 60000,
            "rpId": "localhost",
            "allowCredentials": allowed_creds,
            "userVerification": "required"
        })
    }
}

/// OAuth2 test data
pub struct MockOAuth2Responses;

impl MockOAuth2Responses {
    /// Generate a mock ID token for the given user
    pub fn id_token(user: &TestUser) -> String {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let claims = json!({
            "iss": "https://accounts.google.com",
            "sub": user.id,
            "aud": "mock_client_id",
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            "iat": chrono::Utc::now().timestamp(),
            "email": user.email,
            "name": user.name,
            "given_name": user.given_name,
            "family_name": user.family_name,
            "email_verified": true
        });

        let key = EncodingKey::from_secret("test_secret".as_ref());
        encode(&Header::default(), &claims, &key)
            .unwrap_or_else(|_| format!("mock.jwt.token.{}", user.id))
    }

    /// Generate a mock access token response
    pub fn token_response(user: &TestUser) -> Value {
        json!({
            "access_token": format!("mock_access_token_{}", user.id),
            "id_token": Self::id_token(user),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid email profile"
        })
    }
}

/// Common test state values
pub struct TestConstants;

impl TestConstants {
    #[allow(dead_code)]
    pub const MOCK_STATE: &'static str = "test_state_12345";
    #[allow(dead_code)]
    pub const MOCK_AUTH_CODE: &'static str = "mock_authorization_code";
    #[allow(dead_code)]
    pub const MOCK_CLIENT_ID: &'static str = "mock_client_id";
    #[allow(dead_code)]
    pub const MOCK_CLIENT_SECRET: &'static str = "mock_client_secret";
    #[allow(dead_code)]
    pub const TEST_ORIGIN: &'static str = "http://localhost:3000";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_fixtures() {
        let oauth2_user = TestUsers::oauth2_user();
        assert_eq!(oauth2_user.email, "oauth2@example.com");

        let passkey_user = TestUsers::passkey_user();
        assert_eq!(passkey_user.email, "passkey@example.com");

        let admin_user = TestUsers::admin_user();
        assert_eq!(admin_user.email, "admin@example.com");
    }

    #[test]
    fn test_oauth2_userinfo_conversion() {
        let user = TestUsers::oauth2_user();
        let userinfo = user.to_oauth2_userinfo();

        assert_eq!(userinfo["email"], "oauth2@example.com");
        assert_eq!(userinfo["name"], "OAuth2 Test User");
        assert!(userinfo["picture"].as_str().unwrap().contains(&user.id));
    }

    #[test]
    fn test_webauthn_credential_generation() {
        let cred = MockWebAuthnCredentials::registration_response("testuser", "Test User");
        assert_eq!(cred["type"], "public-key");
        assert!(cred["id"].as_str().is_some());
        assert!(cred["response"]["client_data_json"].as_str().is_some());
    }

    #[test]
    fn test_oauth2_token_generation() {
        let user = TestUsers::oauth2_user();
        let token_response = MockOAuth2Responses::token_response(&user);

        assert_eq!(token_response["token_type"], "Bearer");
        assert_eq!(token_response["expires_in"], 3600);
        assert!(
            token_response["access_token"]
                .as_str()
                .unwrap()
                .contains(&user.id)
        );
    }
}
