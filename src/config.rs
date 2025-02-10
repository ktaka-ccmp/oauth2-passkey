use std::{env, sync::Arc};
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::storage::TokenStoreType;
use crate::types::*;
use libsession::SessionState;

static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) static OAUTH2_USERINFO_URL: &str = "https://www.googleapis.com/userinfo/v2/me";

static OAUTH2_QUERY_STRING: &str = "response_type=code\
&scope=openid+email+profile\
&response_mode=form_post\
&access_type=online\
&prompt=consent";
// &response_mode=form_post\
// &response_mode=query\

// Supported parameters:
// response_type: code
// scope: openid+email+profile
// response_mode: form_post, query
// access_type: online, offline(for refresh token)
// prompt: none, consent, select_account

// "__Host-" prefix are added to make cookies "host-only".

// pub(super) static SESSION_COOKIE_NAME: &str = "__Host-SessionId";
// static SESSION_COOKIE_MAX_AGE: u64 = 600; // 10 minutes
pub(crate) static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
pub(crate) static CSRF_COOKIE_MAX_AGE: u64 = 60; // 60 seconds

pub async fn oauth2_state_init(session_state: Arc<SessionState>) -> Result<OAuth2State, AppError> {
    let oauth2_route_prefix =
        env::var("OAUTH2_ROUTE_PREFIX").expect("Missing OAUTH2_ROUTE_PREFIX!");

    let oauth2_params = OAuth2Params {
        client_id: env::var("CLIENT_ID").expect("Missing CLIENT_ID!"),
        client_secret: env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!"),
        redirect_uri: format!(
            "{}{}/authorized",
            env::var("ORIGIN").expect("Missing ORIGIN!"),
            oauth2_route_prefix
        ),
        auth_url: OAUTH2_AUTH_URL.to_string(),
        token_url: OAUTH2_TOKEN_URL.to_string(),
        query_string: OAUTH2_QUERY_STRING.to_string(),
        oauth2_route_prefix,
        csrf_cookie_name: CSRF_COOKIE_NAME.to_string(),
        csrf_cookie_max_age: CSRF_COOKIE_MAX_AGE,
    };

    let token_store = TokenStoreType::from_env()?.create_store().await?;
    token_store.init().await?;

    Ok(OAuth2State {
        token_store: Arc::new(Mutex::new(token_store)),
        oauth2_params,
        session_state,
    })
}
