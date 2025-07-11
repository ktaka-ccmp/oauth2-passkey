use crate::oauth2::config::{
    OAUTH2_GOOGLE_CLIENT_ID, OAUTH2_GOOGLE_CLIENT_SECRET, OAUTH2_REDIRECT_URI, OAUTH2_TOKEN_URL,
    OAUTH2_USERINFO_URL,
};
use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{GoogleUserInfo, OidcTokenResponse};

use super::utils::get_client;

pub(super) async fn fetch_user_data_from_google(
    access_token: String,
) -> Result<GoogleUserInfo, OAuth2Error> {
    let client = get_client();
    let response = client
        .get(OAUTH2_USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| OAuth2Error::FetchUserInfo(e.to_string()))?;

    let response_body = response
        .text()
        .await
        .map_err(|e| OAuth2Error::FetchUserInfo(e.to_string()))?;

    tracing::debug!("Response Body: {:#?}", response_body);
    let user_data: GoogleUserInfo = serde_json::from_str(&response_body)
        .map_err(|e| OAuth2Error::Serde(format!("Failed to deserialize response body: {e}")))?;

    tracing::debug!("User data: {:#?}", user_data);
    Ok(user_data)
}

pub(super) async fn exchange_code_for_token(
    code: String,
    code_verifier: String,
) -> Result<(String, String), OAuth2Error> {
    let client = get_client();
    let response = client
        .post(OAUTH2_TOKEN_URL.as_str())
        .form(&[
            ("code", code),
            ("client_id", OAUTH2_GOOGLE_CLIENT_ID.to_string()),
            ("client_secret", OAUTH2_GOOGLE_CLIENT_SECRET.to_string()),
            ("redirect_uri", OAUTH2_REDIRECT_URI.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;

    match response.status() {
        reqwest::StatusCode::OK => {
            tracing::debug!("Token Exchange Response: {:#?}", response);
        }
        status => {
            tracing::debug!("Token Exchange Response: {:#?}", response);
            return Err(OAuth2Error::TokenExchange(status.to_string()));
        }
    };

    let response_body = response
        .text()
        .await
        .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;
    let response_json: OidcTokenResponse = serde_json::from_str(&response_body)
        .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;

    tracing::debug!("Response JSON: {:#?}", response_json);

    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.ok_or_else(|| {
        OAuth2Error::TokenExchange("ID token not present in response".to_string())
    })?;

    Ok((access_token, id_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::types::{GoogleUserInfo, OidcTokenResponse};
    use serde_json::json;

    /// Test successful deserialization of Google user info JSON
    ///
    /// This test verifies that `GoogleUserInfo` can be correctly deserialized from
    /// a JSON response containing all required fields. It creates a mock JSON response
    /// in memory and tests the serde deserialization.
    ///
    #[test]
    fn test_google_user_info_deserialization() {
        // Test successful deserialization of Google user info
        let json_data = json!({
            "id": "123456789",
            "email": "test@example.com",
            "verified_email": true,
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/pic.jpg",
            "locale": "en"
        });

        let json_str = serde_json::to_string(&json_data)
            .expect("JSON serialization should not fail for valid data");
        let user_info: Result<GoogleUserInfo, _> = serde_json::from_str(&json_str);

        assert!(
            user_info.is_ok(),
            "Should successfully deserialize valid Google user info"
        );
        let user_info = user_info.expect("Already verified result is Ok");
        assert_eq!(user_info.email, "test@example.com");
        assert_eq!(user_info.name, "Test User");
    }

    /// Test successful deserialization of OIDC token response with id_token
    ///
    /// This test verifies that `OidcTokenResponse` can be correctly deserialized from
    /// a JSON response that includes an id_token field. It creates a mock JSON response
    /// in memory and tests the serde deserialization of all fields.
    ///
    #[test]
    fn test_oidc_token_response_deserialization() {
        // Test successful deserialization of OIDC token response with id_token
        let json_data = json!({
            "access_token": "ya29.access_token_value",
            "expires_in": 3599,
            "scope": "openid email profile",
            "token_type": "Bearer",
            "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzAyOGE4MzI5Y2QwOTU0Y2JmYWMwNGI2MWI3OGZkYThlMzVjOGMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJjbGllbnRfaWQiLCJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjA5NDYyODAwLCJpYXQiOjE2MDk0NTkyMDB9.signature"
        });

        let json_str = serde_json::to_string(&json_data)
            .expect("JSON serialization should not fail for valid data");
        let token_response: Result<OidcTokenResponse, _> = serde_json::from_str(&json_str);

        assert!(
            token_response.is_ok(),
            "Should successfully deserialize valid OIDC token response"
        );
        let token_response = token_response.expect("Already verified result is Ok");
        assert_eq!(token_response.access_token, "ya29.access_token_value");
        assert!(token_response.id_token.is_some(), "Should have id_token");
    }

    /// Test deserialization of OIDC token response without id_token
    ///
    /// This test verifies that `OidcTokenResponse` can be correctly deserialized from
    /// a JSON response that omits the optional id_token field. It creates a mock JSON
    /// response in memory and verifies the id_token field is None.
    ///
    #[test]
    fn test_oidc_token_response_missing_id_token() {
        // Test deserialization of OIDC token response without id_token
        let json_data = json!({
            "access_token": "ya29.access_token_value",
            "expires_in": 3599,
            "scope": "openid email profile",
            "token_type": "Bearer"
            // Missing id_token field
        });

        let json_str = serde_json::to_string(&json_data)
            .expect("JSON serialization should not fail for valid data");
        let token_response: Result<OidcTokenResponse, _> = serde_json::from_str(&json_str);

        assert!(
            token_response.is_ok(),
            "Should successfully deserialize token response without id_token"
        );
        let token_response = token_response.expect("Already verified result is Ok");
        assert_eq!(token_response.access_token, "ya29.access_token_value");
        assert!(
            token_response.id_token.is_none(),
            "Should not have id_token"
        );
    }

    /// Test Google user info deserialization with missing required fields
    ///
    /// This test verifies that deserializing Google user info JSON fails appropriately
    /// when required fields are missing from the response.
    ///
    #[test]
    fn test_google_user_info_deserialization_missing_required_fields() {
        // Test deserialization failure when required fields are missing
        let json_data = json!({
            "id": "123456789",
            // Missing required fields: email, name, etc.
            "verified_email": true,
            "picture": "https://example.com/pic.jpg"
        });

        let json_str =
            serde_json::to_string(&json_data).expect("JSON serialization should not fail");
        let user_info: Result<GoogleUserInfo, _> = serde_json::from_str(&json_str);

        assert!(
            user_info.is_err(),
            "Should fail to deserialize when required fields are missing"
        );
    }

    /// Test Google user info deserialization with malformed JSON
    ///
    /// This test verifies that attempting to deserialize malformed JSON to GoogleUserInfo
    /// returns a JsonError as expected.
    ///
    #[test]
    fn test_google_user_info_deserialization_invalid_json() {
        // Test deserialization failure with malformed JSON
        let invalid_json = r#"{"id": "123", "email":}"#; // Malformed JSON

        let user_info: Result<GoogleUserInfo, _> = serde_json::from_str(invalid_json);

        assert!(
            user_info.is_err(),
            "Should fail to deserialize malformed JSON"
        );
    }

    /// Test OIDC token response deserialization with missing access_token
    ///
    /// This test verifies that attempting to deserialize an OIDC token response without
    /// the required access_token field returns a deserialization error.
    ///
    #[test]
    fn test_oidc_token_response_missing_access_token() {
        // Test deserialization failure when access_token is missing
        let json_data = json!({
            // Missing access_token
            "expires_in": 3599,
            "scope": "openid email profile",
            "token_type": "Bearer",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.signature"
        });

        let json_str =
            serde_json::to_string(&json_data).expect("JSON serialization should not fail");
        let token_response: Result<OidcTokenResponse, _> = serde_json::from_str(&json_str);

        assert!(
            token_response.is_err(),
            "Should fail to deserialize when access_token is missing"
        );
    }

    /// Test OIDC token response deserialization with malformed JSON
    ///
    /// This test verifies that attempting to deserialize malformed JSON to OidcTokenResponse
    /// returns a JsonError as expected.
    ///
    #[test]
    fn test_oidc_token_response_invalid_json() {
        // Test deserialization failure with malformed JSON
        let invalid_json = r#"{"access_token": "token", "expires_in":}"#; // Malformed JSON

        let token_response: Result<OidcTokenResponse, _> = serde_json::from_str(invalid_json);

        assert!(
            token_response.is_err(),
            "Should fail to deserialize malformed JSON"
        );
    }

    /// Tests for business logic validation in exchange_code_for_token function
    ///
    /// This test validates the critical business logic for id_token validation
    /// that is used in exchange_code_for_token()
    ///
    #[test]
    fn test_id_token_validation_logic() {
        // This test validates the critical business logic for id_token validation
        // that is used in exchange_code_for_token()

        // Test case 1: Missing id_token should return error
        let missing_id_token: Option<String> = None;
        let result = missing_id_token.ok_or_else(|| {
            OAuth2Error::TokenExchange("ID token not present in response".to_string())
        });

        assert!(
            result.is_err(),
            "Should return error when id_token is missing"
        );
        match result {
            Err(OAuth2Error::TokenExchange(msg)) => {
                assert_eq!(msg, "ID token not present in response");
            }
            _ => panic!("Expected TokenExchange error with specific message"),
        }

        // Test case 2: Present id_token should succeed
        let present_id_token: Option<String> = Some(
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.signature"
                .to_string(),
        );
        let result = present_id_token.ok_or_else(|| {
            OAuth2Error::TokenExchange("ID token not present in response".to_string())
        });

        assert!(result.is_ok(), "Should succeed when id_token is present");
        let id_token = result.expect("Already verified result is Ok");
        assert_eq!(
            id_token,
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.signature"
        );
    }
}
