use chrono::{Duration, Utc};
use headers::Cookie;
use http::header::HeaderMap;

use libuserdb::{User as DbUser, UserStore};

use crate::common::{gen_random_string, header_set_cookie};
use crate::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
use crate::errors::SessionError;
use crate::types::{SessionInfo, StoredSession, User as SessionUser};

use libstorage::GENERIC_CACHE_STORE;

/// Get user information from libuserdb for a given session
pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, SessionError> {
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

async fn create_new_session(session_info: SessionInfo) -> Result<HeaderMap, SessionError> {
    let mut headers = HeaderMap::new();
    let expires_at = session_info.expires_at;

    let session_id = create_and_store_session(session_info).await?;
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        session_id,
        expires_at,
        *SESSION_COOKIE_MAX_AGE as i64,
    )?;

    tracing::debug!("Headers: {:#?}", headers);
    Ok(headers)
}

async fn create_and_store_session(session_info: SessionInfo) -> Result<String, SessionError> {
    let session_id = gen_random_string(32)?;
    let stored_session = StoredSession {
        info: session_info,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(
            "session",
            &session_id,
            stored_session.into(),
            *SESSION_COOKIE_MAX_AGE as usize,
        )
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(session_id)
}

pub async fn delete_session_from_store(
    cookies: Cookie,
    cookie_name: String,
) -> Result<(), SessionError> {
    if let Some(cookie) = cookies.get(&cookie_name) {
        GENERIC_CACHE_STORE
            .lock()
            .await
            .remove("session", cookie)
            .await
            .map_err(|e| SessionError::Storage(e.to_string()))?;
    };
    Ok(())
}

pub async fn delete_session_from_store_by_session_id(session_id: &str) -> Result<(), SessionError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(())
}

pub async fn create_session_with_user(user_data: SessionUser) -> Result<HeaderMap, SessionError> {
    let db_user: DbUser = user_data.into_db_user();

    // Store the user in the database
    let user: SessionUser = UserStore::upsert_user(db_user)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .into();

    create_session_with_uid(&user.id).await
}

pub async fn create_session_with_uid(user_id: &str) -> Result<HeaderMap, SessionError> {
    // Create minimal session info
    let session_info = SessionInfo {
        user_id: user_id.to_string(),
        expires_at: Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64),
    };

    create_new_session(session_info).await
}

pub async fn get_user_from_session(session_cookie: &str) -> Result<SessionUser, SessionError> {
    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_cookie)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    let user = UserStore::get_user(&stored_session.info.user_id)
        .await
        .map_err(|_| SessionError::SessionError)?
        .ok_or(SessionError::SessionError)?;

    Ok(SessionUser::from(user))
}
