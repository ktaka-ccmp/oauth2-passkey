use askama::Template;
use axum::{
    Router,
    extract::Path,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
};
use dotenvy::dotenv;

use oauth2_passkey_axum::{
    AuthUser, O2P_ROUTE_PREFIX, OAuth2Account, PasskeyCredential, SessionId, UserId, get_all_users,
    get_user, list_accounts_core, list_credentials_core, oauth2_passkey_full_router,
};

mod server;
use server::{init_tracing, spawn_http_server};

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
    is_admin: bool,
    o2p_route_prefix: &'a str,
}

async fn index(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => {
            let template = IndexUserTemplate {
                user_label: &u.label,
                is_admin: u.has_admin_privileges(),
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
// Custom Account Page
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
#[template(path = "account.j2")]
struct AccountTemplate<'a> {
    user_id: &'a str,
    user_account: &'a str,
    user_label: &'a str,
    csrf_token: &'a str,
    created_at: String,
    passkeys: Vec<TemplatePasskey>,
    oauth2_accounts: Vec<TemplateOAuth2>,
    is_admin: bool,
    o2p_route_prefix: &'a str,
}

/// Custom account page - shows user info, passkeys, and OAuth2 accounts
async fn account(user: AuthUser) -> impl IntoResponse {
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

    let template = AccountTemplate {
        user_id: &user.id,
        user_account: &user.account,
        user_label: &user.label,
        csrf_token: &user.csrf_token,
        created_at: user.created_at.format("%Y-%m-%d %H:%M").to_string(),
        passkeys,
        oauth2_accounts,
        is_admin: user.has_admin_privileges(),
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ============================================================================
// Custom Admin Pages
// ============================================================================

/// Template-friendly user info for admin list
struct TemplateUserInfo {
    id: String,
    account: String,
    label: String,
    is_admin: bool,
    is_first_user: bool,
    created_at: String,
}

#[derive(Template)]
#[template(path = "admin_index.j2")]
struct AdminIndexTemplate<'a> {
    users: Vec<TemplateUserInfo>,
    csrf_token: &'a str,
    o2p_route_prefix: &'a str,
}

/// Admin index page - shows all users (admin only)
async fn admin_index(user: AuthUser) -> impl IntoResponse {
    // Check admin privileges
    if !user.has_admin_privileges() {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    // Get session ID for admin API calls
    let session_id = match SessionId::new(user.session_id.clone()) {
        Ok(id) => id,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid session").into_response(),
    };

    // Fetch all users
    let users = match get_all_users(session_id).await {
        Ok(users) => users
            .iter()
            .map(|u| TemplateUserInfo {
                id: u.id.clone(),
                account: u.account.clone(),
                label: u.label.clone(),
                is_admin: u.has_admin_privileges(),
                is_first_user: u.sequence_number == Some(1),
                created_at: u.created_at.format("%Y-%m-%d %H:%M").to_string(),
            })
            .collect(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch users: {e}"),
            )
                .into_response();
        }
    };

    let template = AdminIndexTemplate {
        users,
        csrf_token: &user.csrf_token,
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Template)]
#[template(path = "admin_user.j2")]
struct AdminUserTemplate<'a> {
    target_user_id: &'a str,
    target_user_account: &'a str,
    target_user_label: &'a str,
    target_is_admin: bool,
    target_is_first_user: bool,
    target_created_at: String,
    passkeys: Vec<TemplatePasskey>,
    oauth2_accounts: Vec<TemplateOAuth2>,
    csrf_token: &'a str,
    o2p_route_prefix: &'a str,
}

/// Admin user detail page - shows specific user's details (admin only)
async fn admin_user(user: AuthUser, Path(target_id): Path<String>) -> impl IntoResponse {
    // Check admin privileges
    if !user.has_admin_privileges() {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    // Get session ID for admin API calls
    let session_id = match SessionId::new(user.session_id.clone()) {
        Ok(id) => id,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid session").into_response(),
    };

    // Get user ID
    let target_user_id = match UserId::new(target_id.clone()) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid user ID").into_response(),
    };

    // Fetch target user
    let target_user = match get_user(session_id, target_user_id.clone()).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch user: {e}"),
            )
                .into_response();
        }
    };

    // Fetch passkey credentials
    let passkeys = match list_credentials_core(target_user_id.clone()).await {
        Ok(creds) => creds.iter().map(TemplatePasskey::from).collect(),
        Err(_) => vec![],
    };

    // Fetch OAuth2 accounts
    let oauth2_accounts = match list_accounts_core(target_user_id).await {
        Ok(accs) => accs.iter().map(TemplateOAuth2::from).collect(),
        Err(_) => vec![],
    };

    let template = AdminUserTemplate {
        target_user_id: &target_user.id,
        target_user_account: &target_user.account,
        target_user_label: &target_user.label,
        target_is_admin: target_user.has_admin_privileges(),
        target_is_first_user: target_user.sequence_number == Some(1),
        target_created_at: target_user.created_at.format("%Y-%m-%d %H:%M").to_string(),
        passkeys,
        oauth2_accounts,
        csrf_token: &user.csrf_token,
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
    init_tracing("demo-custom-login");

    if std::env::var("DEMO_CUSTOM_LOGIN_SKIP_DOTENV").is_err() {
        dotenv().ok();
    }
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login)) // Custom login page
        .route("/protected", get(protected))
        .route("/account", get(account)) // Custom account page
        .route("/admin", get(admin_index)) // Custom admin index page
        .route("/admin/user/{id}", get(admin_user)) // Custom admin user detail page
        .merge(oauth2_passkey_full_router());

    let port = std::env::var("DEMO_CUSTOM_LOGIN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);
    spawn_http_server(port, app).await?;
    Ok(())
}
