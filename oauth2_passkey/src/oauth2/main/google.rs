use crate::oauth2::config::{
    OAUTH2_GOOGLE_CLIENT_ID, OAUTH2_GOOGLE_CLIENT_SECRET, OAUTH2_REDIRECT_URI, get_userinfo_url,
};
use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{GoogleUserInfo, OidcTokenResponse};

use super::utils::get_client;

pub(super) async fn fetch_user_data_from_google(
    access_token: String,
) -> Result<GoogleUserInfo, OAuth2Error> {
    let client = get_client();
    let userinfo_url = get_userinfo_url().await?;
    let response = client
        .get(&userinfo_url)
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
    let token_url = crate::oauth2::config::get_token_url().await?;
    let response = client
        .post(&token_url)
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
mod tests;
