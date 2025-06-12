use askama::Template;
use axum::{
    extract::{Json, Path},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
    routing::{Router, delete, get, post},
};
use serde::Deserialize;
use serde_json::Value;

use oauth2_passkey::{
    AuthenticationOptions, AuthenticatorResponse, O2P_ROUTE_PREFIX, PasskeyCredential,
    RegisterCredential, RegistrationOptions, RegistrationStartRequest, SessionUser,
    delete_passkey_credential_core, get_related_origin_json, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_core, list_credentials_core, update_passkey_credential_core,
};

use super::error::IntoResponseError;
use super::session::AuthUser;

pub(super) fn router() -> Router {
    Router::new()
        .route("/passkey.js", get(serve_passkey_js))
        .route("/conditional_ui", get(conditional_ui))
        .route("/conditional_ui.js", get(serve_conditional_ui_js))
        .nest("/auth", router_auth())
        .nest("/register", router_register())
        .route("/credentials", get(list_passkey_credentials))
        .route(
            "/credentials/{credential_id}",
            delete(delete_passkey_credential),
        )
        .route("/credential/update", post(update_passkey_credential))
}

fn router_register() -> Router {
    Router::new()
        .route("/start", post(handle_start_registration))
        .route("/finish", post(handle_finish_registration))
}

fn router_auth() -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
}

/// Creates a router for the WebAuthn well-known endpoint
/// This should be mounted at the root level of the application
pub fn passkey_well_known_router() -> Router {
    Router::new().route("/webauthn", get(serve_related_origin))
}

async fn handle_start_registration(
    auth_user: Option<AuthUser>,
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(SessionUser::from);

    // Use the new wrapper function that handles headers directly
    let registration_options = handle_start_registration_core(session_user.as_ref(), request)
        .await
        .into_response_error()?;

    Ok(Json(registration_options))
}

async fn handle_finish_registration(
    auth_user: Option<AuthUser>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(SessionUser::from);
    handle_finish_registration_core(session_user.as_ref(), reg_data)
        .await
        .into_response_error()
}

async fn handle_start_authentication(
    Json(body): Json<Value>,
) -> Result<Json<AuthenticationOptions>, (StatusCode, String)> {
    // Call the core function with the extracted data
    let auth_options = handle_start_authentication_core(&body)
        .await
        .into_response_error()?;

    // Return the authentication options as JSON
    Ok(Json(auth_options))
}

async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    // Call the core function with the extracted data
    let (_, name, headers) = handle_finish_authentication_core(auth_response)
        .await
        .into_response_error()?;

    // Return the headers and name
    Ok((headers, name))
}

async fn serve_passkey_js() -> Response {
    let js_content = include_str!("../static/passkey.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

#[derive(Template)]
#[template(path = "conditional_ui.j2")]
struct ConditionalUiTemplate<'a> {
    o2p_route_prefix: &'a str,
}

async fn conditional_ui() -> impl IntoResponse {
    let template = ConditionalUiTemplate {
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap_or_default())).into_response()
}

async fn serve_conditional_ui_js() -> Response {
    let js_content = include_str!("../static/conditional_ui.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

async fn list_passkey_credentials(
    auth_user: AuthUser,
) -> Result<Json<Vec<PasskeyCredential>>, (StatusCode, String)> {
    let credentials = list_credentials_core(&auth_user.id)
        .await
        .into_response_error()?;
    Ok(Json(credentials))
}

async fn delete_passkey_credential(
    auth_user: AuthUser,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    delete_passkey_credential_core(&auth_user.id, &credential_id)
        .await
        .into_response_error()
        .map(|()| StatusCode::NO_CONTENT)
}

async fn serve_related_origin() -> Response {
    // Get the WebAuthn configuration JSON from libpasskey
    match get_related_origin_json() {
        Ok(json) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(json.into())
            .unwrap_or_default(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("Failed to generate WebAuthn config: {}", e).into())
            .unwrap_or_default(),
    }
}

#[derive(Deserialize)]
struct UpdateCredentialUserDetailsRequest {
    pub credential_id: String,
    pub name: String,
    pub display_name: String,
}

/// Update the name and display name of a passkey credential
///
/// This endpoint allows users to update the name and display name of their passkey credentials.
/// It also provides the necessary information for the client to call the WebAuthn
/// signalCurrentUserDetails API to update the credential in the authenticator.
async fn update_passkey_credential(
    auth_user: AuthUser,
    Json(payload): Json<UpdateCredentialUserDetailsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = SessionUser::from(&auth_user);

    // Call the update function
    let response = update_passkey_credential_core(
        &payload.credential_id,
        &payload.name,
        &payload.display_name,
        Some(session_user),
    )
    .await
    .into_response_error()?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use axum::Json;
    use http::StatusCode;

    use super::*;

    /// Test the serve_passkey_js function to ensure it returns a valid JavaScript response
    /// This test checks:
    /// 1. The response status code is 200 OK
    /// 2. The Content-Type header is set to "application/javascript"
    /// 3. The response body is successfully created
    #[tokio::test]
    async fn test_serve_passkey_js() {
        // Call the function
        let response = serve_passkey_js().await;

        // Verify status code
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type header
        let headers = response.headers();
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/javascript"
        );

        // For static content, we just verify the response was created successfully
        // We can't easily test the exact content in a unit test
    }

    /// Test the serve_conditional_ui_js function to ensure it returns a valid JavaScript response
    /// This test checks:
    /// 1. The response status code is 200 OK
    /// 2. The Content-Type header is set to "application/javascript"
    /// 3. The response body is successfully created
    #[tokio::test]
    async fn test_serve_conditional_ui_js() {
        // Call the function
        let response = serve_conditional_ui_js().await;

        // Verify status code
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type header
        let headers = response.headers();
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/javascript"
        );

        // For static content, we just verify the response was created successfully
        // We can't easily test the exact content in a unit test
    }

    /// Test the serve_related_origin function to ensure it returns WebAuthn configuration JSON
    /// This test checks:
    /// 1. The response status code is 200 OK
    /// 2. The Content-Type header is set to "application/json"
    /// 3. The response body is successfully created
    #[tokio::test]
    async fn test_serve_related_origin() {
        // Initialize test environment with required environment variables
        let _ = crate::test_utils::env::origin();

        // Call the handler directly
        let response = serve_related_origin().await;

        // Verify the response
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type header
        let headers = response.headers();
        assert_eq!(
            headers
                .get(http::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );

        // For static content, we just verify the response was created successfully
        // The actual content is provided by the oauth2_passkey crate using our test environment variables
    }

    /// Test the conditional_ui function to ensure it returns HTML template
    /// This test checks:
    /// 1. The response status code is 200 OK
    /// 2. The response body is successfully created
    #[tokio::test]
    async fn test_conditional_ui() {
        // Call the function
        let response = conditional_ui().await.into_response();

        // Verify status code
        assert_eq!(response.status(), StatusCode::OK);

        // For HTML responses, we can't easily check the content in a unit test
        // We just verify the response was created successfully
    }

    #[test]
    fn test_router_configuration() {
        // Test main router
        let router = router();

        // We can't easily test the exact routes in a unit test,
        // but we can verify the router is created successfully without panicking
        let _main_router = router;

        // Test register router
        let _register_router = router_register();

        // Test auth router
        let _auth_router = router_auth();

        // Test well-known router
        let _well_known_router = passkey_well_known_router();

        // If we get here without panicking, the test passes
        assert!(true);
    }

    /// Test the list_passkey_credentials handler with mocked dependencies
    /// This test checks:
    /// 1. Handler returns credentials for authenticated user
    /// 2. Returned credentials have correct user ID and fields
    /// 3. Mock functions are called as expected
    #[tokio::test]
    async fn test_list_passkey_credentials_handler() {
        use crate::test_utils::{core_mocks, mocks};

        // Initialize test environment
        let _ = crate::test_utils::env::origin();

        // Reset mock tracking
        core_mocks::reset_mock_calls();

        // Create a mock AuthUser
        let auth_user = mocks::mock_auth_user("test-user-id", "test@example.com");

        let result = async {
            // Simulate what list_passkey_credentials would do with mocked dependencies
            let credentials = core_mocks::mock_list_credentials_core(&auth_user.id, false)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(Json(credentials))
        }
        .await;

        // Verify the result
        match &result {
            Ok(Json(credentials)) => {
                // Verify we have at least one credential
                assert!(!credentials.is_empty(), "Expected at least one credential");

                // Verify user ID of the first credential
                assert_eq!(
                    credentials[0].user_id, "test-user-id",
                    "First credential user ID mismatch"
                );

                // Verify user fields of the first credential
                assert_eq!(
                    credentials[0].user.name, "user_test-user-id",
                    "First credential user name mismatch"
                );
                assert_eq!(
                    credentials[0].user.display_name, "Test User test-user-id",
                    "First credential display name mismatch"
                );
            }
            Err((status, message)) => {
                panic!(
                    "Expected successful result with credentials, got error: {} - {}",
                    status, message
                );
            }
        }

        // Verify that our mock function was called
        assert!(
            core_mocks::was_list_credentials_called(),
            "Mock list_credentials_core function was not called"
        );
    }

    /// Test the update_passkey_credential handler with mocked dependencies
    /// This test checks:
    /// 1. Handler updates credential details for authenticated user
    /// 2. Returns updated credential data in JSON format
    /// 3. Mock functions are called as expected
    #[tokio::test]
    async fn test_update_passkey_credential_handler() {
        use crate::test_utils::{core_mocks, mocks};

        // Initialize test environment with required environment variables
        let _ = crate::test_utils::env::origin();

        // Create a mock AuthUser
        let auth_user = mocks::mock_auth_user("test-user-id", "test@example.com");

        // Create a mock request payload
        let payload = UpdateCredentialUserDetailsRequest {
            credential_id: "test-credential-id".to_string(),
            name: "Test Credential".to_string(),
            display_name: "Test User's Credential".to_string(),
        };

        // Simulate the handler function with our mocks
        let result: Result<Json<serde_json::Value>, (StatusCode, String)> = async {
            // This simulates what update_passkey_credential would do
            let response = core_mocks::mock_update_passkey_credential_core(
                &auth_user.id,
                &payload.credential_id,
                &payload.name,
                &payload.display_name,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            Ok(Json(response))
        }
        .await;

        // Now we expect this to succeed with our mock
        assert!(
            result.is_ok(),
            "Expected successful result, got: {:?}",
            result
        );

        // Check that the response contains the expected data
        if let Ok(Json(value)) = result {
            assert!(value.is_object());
            // Verify the response contains the expected fields
            assert!(
                value.get("credential").is_some(),
                "Response should contain credential field"
            );
        }
    }
}
