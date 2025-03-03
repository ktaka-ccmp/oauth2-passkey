use crate::config::{
    OAUTH2_GOOGLE_CLIENT_ID, OAUTH2_GOOGLE_CLIENT_SECRET, OAUTH2_REDIRECT_URI, OAUTH2_TOKEN_URL,
    OAUTH2_USERINFO_URL,
};
use crate::errors::OAuth2Error;
use crate::types::{GoogleUserInfo, OidcTokenResponse};

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
        .map_err(|e| OAuth2Error::Serde(format!("Failed to deserialize response body: {}", e)))?;

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
    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.clone().unwrap();

    tracing::debug!("Response JSON: {:#?}", response_json);
    Ok((access_token, id_token))
}
