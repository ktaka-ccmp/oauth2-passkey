use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
    routing::get,
    Router,
};
use axum_extra::{headers, TypedHeader};

// Helper trait for converting errors to a standard response error format
trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

use liboauth2::oauth2::{
    create_new_session, csrf_checks, delete_session_from_store, get_user_oidc_oauth2,
    prepare_logout_response, prepare_oauth2_auth_request, validate_origin,
};
use liboauth2::types::{AppState, AuthResponse};

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/google", get(google_auth))
        .route("/authorized", get(get_authorized).post(post_authorized))
        .route("/popup_close", get(popup_close))
        .route("/logout", get(logout))
        .with_state(state)
}

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate;

pub(crate) async fn popup_close() -> Result<Html<String>, (StatusCode, String)> {
    let template = PopupCloseTemplate;
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub(crate) async fn google_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (auth_url, headers) = prepare_oauth2_auth_request(state, headers)
        .await
        .into_response_error()?;

    Ok((headers, Redirect::to(&auth_url)))
}

pub async fn logout(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let headers = prepare_logout_response(state, cookies)
        .await
        .into_response_error()?;
    Ok((headers, Redirect::to("/")))
}

pub async fn post_authorized(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
    Form(form): Form<AuthResponse>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    #[cfg(debug_assertions)]
    println!(
        "Cookies: {:#?}",
        cookies.get(&state.session_params.csrf_cookie_name)
    );

    validate_origin(&headers, &state.oauth2_params.auth_url)
        .await
        .into_response_error()?;

    if form.state.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing state parameter".to_string(),
        ));
    }

    authorized(&form, state).await
}

pub async fn get_authorized(
    Query(query): Query<AuthResponse>,
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    validate_origin(&headers, &state.oauth2_params.auth_url)
        .await
        .into_response_error()?;
    csrf_checks(cookies.clone(), &state, &query, headers)
        .await
        .into_response_error()?;

    delete_session_from_store(
        cookies,
        state.session_params.session_cookie_name.to_string(),
        &state,
    )
    .await
    .into_response_error()?;

    authorized(&query, state).await
}

async fn authorized(
    auth_response: &AuthResponse,
    state: AppState,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let user_data = get_user_oidc_oauth2(auth_response, &state)
        .await
        .into_response_error()?;
    let oauth2_root = state.oauth2_params.oauth2_root.to_string();
    let headers = create_new_session(state, user_data)
        .await
        .into_response_error()?;

    Ok((headers, Redirect::to(&format!("{}/popup_close", &oauth2_root))))
}
