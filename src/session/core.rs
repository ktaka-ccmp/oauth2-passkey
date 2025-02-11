use chrono::{DateTime, Duration, Utc};
use headers::Cookie;
use http::header::HeaderMap;

use crate::common::{gen_random_string, header_set_cookie};
use crate::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME, SESSION_STORE};
use crate::errors::AppError;
use crate::types::{StoredSession, User};

pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;
    delete_session_from_store(cookies, SESSION_COOKIE_NAME.to_string()).await?;
    Ok(headers)
}

pub async fn create_new_session(user_data: User) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    let max_age = *SESSION_COOKIE_MAX_AGE as i64;
    let expires_at = Utc::now() + Duration::seconds(max_age);
    let session_id = create_and_store_session(user_data, expires_at).await?;
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
    expires_at: DateTime<Utc>,
) -> Result<String, AppError> {
    let session_id = gen_random_string(32)?;
    let stored_session = StoredSession {
        user: user_data,
        expires_at,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    let mut store_guard = SESSION_STORE.lock().await;
    store_guard
        .get_store_mut()
        .put(&session_id, stored_session)
        .await?;

    Ok(session_id)
}

pub async fn delete_session_from_store(
    cookies: Cookie,
    cookie_name: String,
) -> Result<(), AppError> {
    let mut store_guard = SESSION_STORE.lock().await;

    if let Some(cookie) = cookies.get(&cookie_name) {
        store_guard
            .get_store_mut()
            .remove(cookie)
            .await
            .map_err(|e| {
                println!("Error removing session: {}", e);
                e
            })?;
    };
    Ok(())
}
