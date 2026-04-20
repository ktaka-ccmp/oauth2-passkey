use super::*;
use axum::http::StatusCode;

/// Test the `serve_oauth2_js` function to ensure it returns a valid JavaScript response
///
/// This test checks:
/// 1. The response is Ok
/// 2. The status code is 200 OK
/// 3. The Content-Type header is set to "application/javascript"
///
#[tokio::test]
async fn test_serve_oauth2_js() {
    // Call the function
    let response = serve_oauth2_js().await;

    // Verify the result is Ok
    assert!(response.is_ok());

    if let Ok(response) = response {
        // Verify status code
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type header
        let headers = response.headers();
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .expect("Content-Type header should exist")
                .to_str()
                .expect("Content-Type header should be valid UTF-8"),
            "application/javascript"
        );
    }
}

#[test]
fn display_name_for_known_slugs() {
    assert_eq!(display_name_for("google"), "Google");
    assert_eq!(display_name_for("auth0"), "Auth0");
    assert_eq!(display_name_for("keycloak"), "Keycloak");
    assert_eq!(display_name_for("entra"), "Microsoft");
}

#[test]
fn display_name_for_unknown_slug_passes_through() {
    assert_eq!(display_name_for("okta"), "okta");
    assert_eq!(display_name_for(""), "");
}

#[test]
fn icon_slug_for_known_slugs() {
    assert_eq!(icon_slug_for("google"), "google");
    assert_eq!(icon_slug_for("auth0"), "auth0");
    assert_eq!(icon_slug_for("keycloak"), "keycloak");
    assert_eq!(icon_slug_for("entra"), "entra");
}

#[test]
fn icon_slug_for_unknown_slug_falls_back_to_openid() {
    assert_eq!(icon_slug_for("okta"), "openid");
    assert_eq!(icon_slug_for(""), "openid");
}
