use reqwest::{Client, Response};
use serde_json::Value;
use std::collections::HashMap;

/// Mock browser client for integration testing
///
/// Simulates a web browser by maintaining cookies, handling redirects,
/// and providing helpers for authentication flows.
pub struct MockBrowser {
    client: Client,
    base_url: String,
    /// Stored cookies from responses (automatically handled by reqwest client)
    #[allow(dead_code)]
    cookies: HashMap<String, String>,
}

impl MockBrowser {
    /// Create a new mock browser instance
    pub fn new(base_url: &str, use_cookies: bool) -> Self {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // Handle redirects manually
            .cookie_store(use_cookies) // Enable/disable automatic cookie handling
            .build()
            .unwrap();

        Self {
            client,
            base_url: base_url.to_string(),
            cookies: HashMap::new(),
        }
    }

    /// Make a GET request to the specified path
    pub async fn get(&self, path: &str) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        self.client.get(&url).send().await
    }

    /// Make a POST request with form data
    #[allow(dead_code)]
    pub async fn post_form(
        &self,
        path: &str,
        form_data: &[(&str, &str)],
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        self.client.post(&url).form(form_data).send().await
    }

    /// Make a POST request with form data and custom headers (for OAuth2 callbacks) - old format
    pub async fn post_form_with_headers_old(
        &self,
        path: &str,
        form_data: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.post(&url).form(form_data);

        for (key, value) in headers {
            request = request.header(*key, *value);
        }

        request.send().await
    }

    /// Make a POST request with form data and custom headers (for OAuth2 callbacks) - HeaderMap format
    pub async fn post_form_with_headers(
        &self,
        path: &str,
        form_data: &[(&str, &str)],
        headers: &reqwest::header::HeaderMap,
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.post(&url).form(form_data);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        request.send().await
    }

    /// Make a POST request with JSON data
    pub async fn post_json(
        &self,
        path: &str,
        json_data: &Value,
    ) -> Result<Response, reqwest::Error> {
        let url = format!("{}{}", self.base_url, path);
        self.client.post(&url).json(json_data).send().await
    }

    /// Follow a redirect response
    #[allow(dead_code)]
    pub async fn follow_redirect(
        &self,
        response: Response,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        if let Some(location) = response.headers().get("location") {
            let redirect_url = location.to_str()?;
            let response = self.client.get(redirect_url).send().await?;
            Ok(response)
        } else {
            Err("No location header found in redirect response".into())
        }
    }

    /// Start OAuth2 authentication flow
    ///
    /// Returns the authorization URL that would be presented to the user
    #[allow(dead_code)]
    pub async fn start_oauth2_flow(
        &self,
        mode: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let path = format!("/oauth2/start?mode={mode}");
        let response = self.get(&path).await?;

        if response.status().is_redirection() {
            if let Some(location) = response.headers().get("location") {
                Ok(location.to_str()?.to_string())
            } else {
                Err("OAuth2 start did not return authorization URL".into())
            }
        } else {
            Err(format!("Unexpected response status: {}", response.status()).into())
        }
    }

    /// Complete OAuth2 callback
    ///
    /// Simulates the user being redirected back from the OAuth2 provider
    #[allow(dead_code)]
    pub async fn complete_oauth2_callback(
        &self,
        code: &str,
        state: &str,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let path = format!("/oauth2/callback?code={code}&state={state}");
        let response = self.get(&path).await?;
        Ok(response)
    }

    /// Start passkey registration
    ///
    /// Returns the registration options that would be used by the WebAuthn client
    pub async fn start_passkey_registration(
        &self,
        username: &str,
        display_name: &str,
        mode: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let request_data = serde_json::json!({
            "username": username,
            "displayname": display_name,
            "mode": mode
        });

        let response = self
            .post_json("/auth/passkey/register/start", &request_data)
            .await?;

        if response.status().is_success() {
            let options: Value = response.json().await?;
            Ok(options)
        } else {
            Err(format!(
                "Failed to start passkey registration: {}",
                response.status()
            )
            .into())
        }
    }

    /// Complete passkey registration
    ///
    /// Simulates the WebAuthn client providing a credential response
    pub async fn complete_passkey_registration(
        &self,
        mock_credential: &Value,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let response = self
            .post_json("/auth/passkey/register/finish", mock_credential)
            .await?;
        Ok(response)
    }

    /// Start passkey authentication
    ///
    /// Returns the authentication options that would be used by the WebAuthn client
    pub async fn start_passkey_authentication(
        &self,
        username: Option<&str>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let request_data = if let Some(username) = username {
            serde_json::json!({ "username": username })
        } else {
            serde_json::json!({})
        };

        let response = self
            .post_json("/auth/passkey/auth/start", &request_data)
            .await?;

        if response.status().is_success() {
            let options: Value = response.json().await?;
            Ok(options)
        } else {
            Err(format!(
                "Failed to start passkey authentication: {}",
                response.status()
            )
            .into())
        }
    }

    /// Complete passkey authentication
    ///
    /// Simulates the WebAuthn client providing an authentication response
    pub async fn complete_passkey_authentication(
        &self,
        mock_assertion: &Value,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let response = self
            .post_json("/auth/passkey/auth/finish", mock_assertion)
            .await?;
        Ok(response)
    }

    /// Check if the browser has an active session
    ///
    /// Attempts to access a protected endpoint to verify authentication status
    pub async fn has_active_session(&self) -> bool {
        match self.get("/auth/user/info").await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Get current user information if authenticated
    pub async fn get_user_info(&self) -> Result<Option<Value>, Box<dyn std::error::Error>> {
        let response = self.get("/auth/user/info").await?;

        if response.status().is_success() {
            let user_info: Value = response.json().await?;
            Ok(Some(user_info))
        } else if response.status() == 401 {
            Ok(None) // Not authenticated
        } else {
            Err(format!("Unexpected response status: {}", response.status()).into())
        }
    }

    /// Complete a full OAuth2 flow (initiate -> callback)
    pub async fn complete_oauth2_flow(
        &self,
        mode: &str,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        // Step 1: Initiate OAuth2 flow
        let init_response = self
            .get(&format!("/auth/oauth2/google?mode={mode}"))
            .await?;

        if !init_response.status().is_redirection() {
            return Ok(init_response);
        }

        // Step 2: Extract state from redirect
        let auth_url = init_response
            .headers()
            .get("location")
            .ok_or("No location header in OAuth2 redirect")?
            .to_str()?
            .to_string();

        let url = url::Url::parse(&auth_url)?;
        let state_param = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string())
            .ok_or("No state parameter found in auth URL")?;

        // Step 3: Complete OAuth2 callback
        let callback_response = self
            .post_form_with_headers_old(
                "/auth/oauth2/authorized",
                &[("code", "mock_authorization_code"), ("state", &state_param)],
                &[
                    ("Origin", &self.base_url),
                    ("Referer", "https://accounts.google.com/oauth2/authorize"),
                ],
            )
            .await?;

        Ok(callback_response)
    }

    /// Logout the current user
    #[allow(dead_code)]
    pub async fn logout(&self) -> Result<Response, Box<dyn std::error::Error>> {
        let response = self.post_form("/auth/logout", &[]).await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::TestServer;

    #[tokio::test]
    async fn test_mock_browser_basic_requests() {
        let server = TestServer::start()
            .await
            .expect("Failed to start test server");
        let browser = MockBrowser::new(&server.base_url, true);

        // Test basic GET request
        let response = browser
            .get("/health")
            .await
            .expect("Failed to make GET request");
        assert!(response.status().is_success());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_mock_browser_session_detection() {
        let server = TestServer::start()
            .await
            .expect("Failed to start test server");
        let browser = MockBrowser::new(&server.base_url, true);

        // Initially should not have active session
        assert!(!browser.has_active_session().await);

        server.shutdown().await;
    }
}
