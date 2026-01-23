use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
};
use dotenvy::dotenv;

use oauth2_passkey_axum::{
    AuthUser, O2P_ROUTE_PREFIX, OAuth2Account, PasskeyCredential, UserId, list_accounts_core,
    list_credentials_core, oauth2_passkey_router,
};

mod server;
use server::{init_tracing, spawn_http_server, spawn_https_server};

// ============================================================================
// Custom Login Page
// ============================================================================

#[derive(Template)]
#[template(path = "login.j2")]
struct LoginTemplate<'a> {
    o2p_route_prefix: &'a str,
}

/// Custom login page - users design this themselves
async fn login(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        // Already logged in - redirect to home
        Some(_) => Redirect::to("/").into_response(),
        // Show custom login page
        None => {
            let template = LoginTemplate {
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
    }
}

// ============================================================================
// Index Page (shows different content based on auth status)
// ============================================================================

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexAnonTemplate {}

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexUserTemplate<'a> {
    user_label: &'a str,
    o2p_route_prefix: &'a str,
}

async fn index(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => {
            let template = IndexUserTemplate {
                user_label: &u.label,
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        None => {
            let template = IndexAnonTemplate {};
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
    }
}

// ============================================================================
// Protected Page (requires authentication)
// ============================================================================

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate<'a> {
    user_account: &'a str,
    o2p_route_prefix: &'a str,
}

/// Protected page - AuthUser extractor redirects to O2P_LOGIN_URL if not authenticated
async fn protected(user: AuthUser) -> impl IntoResponse {
    let template = ProtectedTemplate {
        user_account: &user.account,
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Custom Summary Page
// ============================================================================

/// Template-friendly passkey credential info
struct TemplatePasskey {
    credential_id: String,
    user_name: String,
    user_display_name: String,
    // user_handle: String, // TODO: use in template later
    created_at: String,
}

impl From<&PasskeyCredential> for TemplatePasskey {
    fn from(cred: &PasskeyCredential) -> Self {
        Self {
            credential_id: cred.credential_id.clone(),
            user_name: cred.user.name.clone(),
            user_display_name: cred.user.display_name.clone(),
            // user_handle: cred.user.user_handle.clone(),
            created_at: cred.created_at.format("%Y-%m-%d %H:%M").to_string(),
        }
    }
}

/// Template-friendly OAuth2 account info
struct TemplateOAuth2 {
    provider: String,
    provider_user_id: String,
    email: String,
    name: String,
}

impl From<&OAuth2Account> for TemplateOAuth2 {
    fn from(acc: &OAuth2Account) -> Self {
        Self {
            provider: acc.provider.clone(),
            provider_user_id: acc.provider_user_id.clone(),
            email: acc.email.clone(),
            name: acc.name.clone(),
        }
    }
}

#[derive(Template)]
#[template(path = "summary.j2")]
struct SummaryTemplate<'a> {
    user_id: &'a str,
    user_account: &'a str,
    user_label: &'a str,
    csrf_token: &'a str,
    created_at: String,
    passkeys: Vec<TemplatePasskey>,
    oauth2_accounts: Vec<TemplateOAuth2>,
    o2p_route_prefix: &'a str,
}

/// Custom summary page - shows user info, passkeys, and OAuth2 accounts
async fn summary(user: AuthUser) -> impl IntoResponse {
    let user_id = UserId::new(user.id.clone()).expect("Invalid user ID");

    // Fetch passkey credentials
    let passkeys = match list_credentials_core(user_id.clone()).await {
        Ok(creds) => creds.iter().map(TemplatePasskey::from).collect(),
        Err(_) => vec![],
    };

    // Fetch OAuth2 accounts
    let oauth2_accounts = match list_accounts_core(user_id).await {
        Ok(accs) => accs.iter().map(TemplateOAuth2::from).collect(),
        Err(_) => vec![],
    };

    let template = SummaryTemplate {
        user_id: &user.id,
        user_account: &user.account,
        user_label: &user.label,
        csrf_token: &user.csrf_token,
        created_at: user.created_at.format("%Y-%m-%d %H:%M").to_string(),
        passkeys,
        oauth2_accounts,
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo-custom-login");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login)) // Custom login page
        .route("/protected", get(protected))
        .route("/summary", get(summary)) // Custom summary page
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    let http_server = spawn_http_server(3001, app.clone());
    let https_server = spawn_https_server(3443, app).await;

    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
