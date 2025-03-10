use askama::Template;
use axum::{
    Json, Router,
    extract::{Form, Query},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, Redirect, Response},
    routing::get,
};
use axum_extra::{TypedHeader, headers};
use chrono::{Duration, Utc};
// use axum_core::response::Response;

// Helper trait for converting errors to a standard response error format
trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

use libuserdb::{User, UserStore};

use liboauth2::{
    AuthResponse, OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_ROUTE_PREFIX, OAuth2Account,
    OAuth2Store, csrf_checks, decode_state, delete_session_and_misc_token_from_store,
    get_idinfo_userinfo, get_uid_from_stored_session_by_state_param, header_set_cookie,
    prepare_oauth2_auth_request, validate_origin,
};

use libsession::{create_session_with_uid, prepare_logout_response};

use crate::AuthUser;

pub fn router() -> Router {
    Router::new()
        .route("/oauth2.js", get(serve_oauth2_js))
        .route("/google", get(google_auth))
        .route("/authorized", get(get_authorized).post(post_authorized))
        .route("/popup_close", get(popup_close))
        .route("/logout", get(logout))
        .route("/accounts", get(list_accounts))
}

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate;

pub(crate) async fn popup_close() -> Result<Html<String>, (StatusCode, String)> {
    let template = PopupCloseTemplate;
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub(crate) async fn serve_oauth2_js() -> Result<Response, (StatusCode, String)> {
    let js_content = include_str!("../../static/oauth2.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .into_response_error()
}

pub(crate) async fn google_auth(
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (auth_url, headers) = prepare_oauth2_auth_request(headers)
        .await
        .into_response_error()?;

    Ok((headers, Redirect::to(&auth_url)))
}

pub async fn logout(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let headers = prepare_logout_response(cookies)
        .await
        .into_response_error()?;
    Ok((headers, Redirect::to("/")))
}

pub async fn post_authorized(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
    Form(form): Form<AuthResponse>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    tracing::debug!(
        "Cookies: {:#?}",
        cookies.get(OAUTH2_CSRF_COOKIE_NAME.as_str())
    );

    validate_origin(&headers, OAUTH2_AUTH_URL.as_str())
        .await
        .into_response_error()?;

    if form.state.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing state parameter".to_string(),
        ));
    }

    authorized(&form).await
}

pub async fn get_authorized(
    Query(query): Query<AuthResponse>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    validate_origin(&headers, OAUTH2_AUTH_URL.as_str())
        .await
        .into_response_error()?;
    csrf_checks(cookies.clone(), &query, headers)
        .await
        .into_response_error()?;

    authorized(&query).await
}

async fn authorized(
    auth_response: &AuthResponse,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (idinfo, userinfo) = get_idinfo_userinfo(auth_response)
        .await
        .into_response_error()?;

    // Convert GoogleUserInfo to DbUser and store it
    static OAUTH2_GOOGLE_USER: &str = "idinfo";

    let mut oauth2_account = match OAUTH2_GOOGLE_USER {
        "idinfo" => OAuth2Account::from(idinfo),
        "userinfo" => OAuth2Account::from(userinfo),
        _ => OAuth2Account::from(idinfo), // Default case
    };

    // Upsert oauth2_account and user
    // 1. Decode the state from the auth response
    // 2. Extract user_id from the stored session if available
    // 3. Check if the OAuth2 account exists

    // Handle user and account linking
    // 4. If user is logged in and account exists, ensure they match
    // 5. If user is logged in but account doesn't exist, link account to user
    // 6. If user is not logged in but account exists, create session for account
    // 7. If neither user is logged in nor account exists, create new user and account

    // Create session with user_id
    // 8. Create a new entry in session store
    // 9. Create a header for the session cookie

    // Decode the state from the auth response
    let state_in_response =
        decode_state(&auth_response.state).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Extract user_id from the stored session if available
    let user_id = get_uid_from_stored_session_by_state_param(&state_in_response)
        .await
        .into_response_error()?;

    // Check if the OAuth2 account exists
    let existing_account = OAuth2Store::get_oauth2_account_by_provider(
        &oauth2_account.provider,
        &oauth2_account.provider_user_id,
    )
    .await
    .into_response_error()?;

    // Match on the combination of auth_user and existing_account
    let mut headers = match (user_id, existing_account) {
        // Case 1: User is logged in and account exists
        (Some(user_id), Some(account)) => {
            if user_id == account.user_id {
                tracing::debug!("OAuth2 account already linked to current user");
                // Nothing to do, account is already properly linked
            } else {
                tracing::debug!("OAuth2 account already linked to different user");
                // return Err((StatusCode::BAD_REQUEST, "This OAuth2 account is already linked to a different user".to_string()));
            }
            delete_session_and_misc_token_from_store(&state_in_response)
                .await
                .into_response_error()?;
            renew_session_header(user_id.to_string()).await?
        }
        // Case 2: User is logged in but account doesn't exist
        (Some(user_id), None) => {
            tracing::debug!("Linking OAuth2 account to user {}", user_id);
            tracing::debug!("Linking OAuth2 account to user {}", user_id);
            oauth2_account.user_id = user_id.clone();
            OAuth2Store::upsert_oauth2_account(oauth2_account)
                .await
                .into_response_error()?;
            delete_session_and_misc_token_from_store(&state_in_response)
                .await
                .into_response_error()?;
            renew_session_header(user_id.to_string()).await?
        }
        // Case 3: User is not logged in but account exists
        (None, Some(account)) => {
            tracing::debug!("Using existing account's user");
            renew_session_header(account.user_id).await?
        }
        // Case 4: User is not logged in and account doesn't exist
        (None, None) => {
            tracing::debug!("Creating new user and account");
            let user_id = create_user_and_oauth2account(oauth2_account).await?;
            renew_session_header(user_id).await?
        }
    };

    let _ = header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )
    .into_response_error()?;

    Ok((
        headers,
        Redirect::to(&format!("{}/popup_close", OAUTH2_ROUTE_PREFIX.as_str())),
    ))
}

async fn renew_session_header(user_id: String) -> Result<HeaderMap, (StatusCode, String)> {
    let headers = create_session_with_uid(&user_id)
        .await
        .into_response_error()?;
    Ok(headers)
}

async fn create_user_and_oauth2account(
    mut oauth2_account: OAuth2Account,
) -> Result<String, (StatusCode, String)> {
    let new_user = User {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let stored_user = UserStore::upsert_user(new_user)
        .await
        .into_response_error()?;
    oauth2_account.user_id = stored_user.id.clone();
    OAuth2Store::upsert_oauth2_account(oauth2_account)
        .await
        .into_response_error()?;
    Ok(stored_user.id)
}

pub async fn list_accounts(
    auth_user: Option<AuthUser>,
) -> Result<Json<Vec<OAuth2Account>>, (StatusCode, String)> {
    match auth_user {
        Some(u) => {
            tracing::debug!("User: {:#?}", u);
            let accounts = OAuth2Store::get_oauth2_accounts(&u.id)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(Json(accounts))
        }
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
    }
}
