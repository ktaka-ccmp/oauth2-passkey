use http::header::{HeaderMap, SET_COOKIE};
use chrono::{DateTime, Duration, Utc};
use headers::Cookie;

use anyhow::Context;
use axum_extra::headers;

// use http::HeaderValue;
// use tower_http::cors::CorsLayer;

use crate::oauth2::User;
use crate::oauth2::{SESSION_COOKIE_NAME, CSRF_COOKIE_NAME, SESSION_COOKIE_MAX_AGE};
use crate::types::{AppState, StoredSession};
use crate::common::{AppError, gen_random_string};

pub async fn create_new_session(state: AppState, user_data: User) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;
    let max_age = SESSION_COOKIE_MAX_AGE as i64;
    let expires_at = Utc::now() + Duration::seconds(max_age);
    let session_id = create_and_store_session(user_data, &state, expires_at).await?;
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        session_id,
        expires_at,
        max_age,
    )?;
    #[cfg(debug_assertions)]
    println!("Headers: {:#?}", headers);
    Ok(headers)
}

async fn create_and_store_session(
    user_data: User,
    state: &AppState,
    expires_at: DateTime<Utc>,
) -> Result<String, AppError> {
    let session_id = gen_random_string(32)?;
    let stored_session = StoredSession {
        user: user_data,
        expires_at,
        ttl: SESSION_COOKIE_MAX_AGE,
    };

    let mut session_store = state.session_store.lock().await;
    session_store.put(&session_id, stored_session).await?;

    Ok(session_id)
}

pub fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, AppError> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );
    Ok(headers)
}

pub async fn delete_session_from_store(
    cookies: Cookie,
    cookie_name: String,
    state: &AppState,
) -> Result<(), AppError> {
    let mut session_store = state.session_store.lock().await;

    if let Some(cookie) = cookies.get(&cookie_name) {
        session_store.remove(cookie).await.map_err(|e| {
            println!("Error removing session: {}", e);
            e
        })?;
    };
    Ok(())
}


