/// Extensions to MockBrowser for nonce-aware OAuth2 testing
use crate::common::{
    mock_browser::MockBrowser,
    nonce_aware_mock::{NonceStorage, extract_nonce_from_auth_url, store_test_nonce},
};
use reqwest::Response;

impl MockBrowser {
    /// Complete OAuth2 flow with proper nonce handling
    #[allow(dead_code)]
    pub async fn complete_oauth2_flow_with_nonce(
        &self,
        mode: &str,
        nonce_storage: &NonceStorage,
        base_url: &str,
    ) -> Result<Response, reqwest::Error> {
        // Step 1: Start OAuth2 flow
        let response = self
            .get(&format!("/auth/oauth2/google?mode={mode}"))
            .await?;

        // Step 2: Extract the authorization URL from redirect
        assert!(response.status().is_redirection());
        let auth_url = response
            .headers()
            .get("location")
            .expect("No location header in OAuth2 redirect")
            .to_str()
            .expect("Invalid location header")
            .to_string();

        // Step 3: Extract nonce and state from the authorization URL
        let nonce = extract_nonce_from_auth_url(&auth_url)
            .expect("No nonce parameter found in authorization URL");

        let url = url::Url::parse(&auth_url).expect("Failed to parse auth URL");
        let state_param = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string())
            .expect("No state parameter found in auth URL");

        // Step 4: Store the nonce so the mock server can use it
        store_test_nonce(nonce_storage, &nonce);

        // Step 5: Complete OAuth2 callback
        self.post_form_with_headers_old(
            "/auth/oauth2/authorized",
            &[("code", "nonce_aware_auth_code"), ("state", &state_param)],
            &[
                ("Origin", base_url),
                ("Referer", &format!("{base_url}/oauth2/authorize")),
            ],
        )
        .await
    }
}
