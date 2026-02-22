use askama::Template;
use axum::{
    Router,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{Html, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use oauth2_passkey::{
    AuthenticatorInfo, O2P_ROUTE_PREFIX, UserId, generate_page_session_token,
    get_authenticator_info_batch, list_accounts_core, list_credentials_core,
};

use crate::config::{O2P_CUSTOM_CSS_URL, O2P_DEFAULT_REDIRECT};
use crate::session::AuthUser;

pub(super) fn router() -> Router<()> {
    Router::new()
        .route("/account", get(user_account))
        .route("/account.js", get(serve_account_js))
        .route("/o2p-base.css", get(serve_base_css))
}

// Template-friendly version of StoredCredential for display
#[derive(Debug)]
struct TemplateCredential {
    pub credential_id: String,
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: String,
    pub aaguid: String,
    pub rp_id: String,
    pub counter: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: String,
    pub authenticator_info: Option<AuthenticatorInfo>,
}

// Template-friendly version of OAuth2Account for display
#[derive(Debug)]
struct TemplateAccount {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub name: String,
    pub email: String,
    pub picture: String,
    pub metadata_str: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug)]
struct TemplateAuthUser {
    pub id: String,
    pub is_admin: bool,
    pub account: String,
    pub label: String,
    pub created_at: String,
    pub updated_at: String,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "user_account.j2")]
struct UserAccountTemplate {
    pub user: TemplateAuthUser,
    pub passkey_credentials: Vec<TemplateCredential>,
    pub oauth2_accounts: Vec<TemplateAccount>,
    pub o2p_route_prefix: String,
    pub o2p_default_redirect: String,
    pub page_session_token: String,
    pub custom_css_url: Option<String>,
}

impl UserAccountTemplate {
    fn new(
        user: AuthUser,
        passkey_credentials: Vec<TemplateCredential>,
        oauth2_accounts: Vec<TemplateAccount>,
        o2p_route_prefix: String,
        o2p_default_redirect: String,
        custom_css_url: Option<String>,
    ) -> Self {
        let page_session_token = generate_page_session_token(&user.csrf_token);

        Self {
            user: TemplateAuthUser {
                id: user.id.clone(),
                is_admin: user.has_admin_privileges(),
                account: user.account.clone(),
                label: user.label.clone(),
                created_at: format_date_tz(&user.created_at, "JST"),
                updated_at: format_date_tz(&user.updated_at, "JST"),
                csrf_token: user.csrf_token.clone(),
            },
            passkey_credentials,
            oauth2_accounts,
            o2p_route_prefix,
            o2p_default_redirect,
            page_session_token,
            custom_css_url,
        }
    }
}

/// Display the user account management page with user info, passkey credentials, and OAuth2 accounts
async fn user_account(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser for the core functions
    // let session_user: &SessionUser = &auth_user;
    let user_id = &auth_user.id;

    // Fetch passkey credentials using the public function from libauth
    // let stored_credentials = list_credentials_core(Some(session_user))
    let user_id_enum = UserId::new(user_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid user ID: {e}"),
        )
    })?;
    let stored_credentials = list_credentials_core(user_id_enum).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch credentials: {e:?}"),
        )
    })?;

    let unique_aaguids: HashSet<String> = stored_credentials
        .iter()
        .map(|c| c.aaguid.clone())
        .collect();
    let auth_info_map =
        get_authenticator_info_batch(&unique_aaguids.into_iter().collect::<Vec<_>>())
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to fetch authenticator info: {e:?}"),
                )
            })?;

    // Convert PasskeyCredential to TemplateCredential
    let passkey_credentials = stored_credentials
        .iter()
        .map(|cred| {
            let authenticator_info = auth_info_map
                .get(&cred.aaguid)
                .cloned()
                .or_else(|| Some(AuthenticatorInfo::default()));

            TemplateCredential {
                credential_id: cred.credential_id.clone(),
                user_id: cred.user_id.clone(),
                user_name: cred.user.name.clone(),
                user_display_name: cred.user.display_name.clone(),
                user_handle: cred.user.user_handle.clone(),
                aaguid: cred.aaguid.clone(),
                rp_id: cred.rp_id.clone(),
                counter: cred.counter.to_string(),
                created_at: format_date_tz(&cred.created_at, "JST"),
                updated_at: format_date_tz(&cred.updated_at, "JST"),
                last_used_at: format_date_tz(&cred.last_used_at, "JST"),
                authenticator_info,
            }
        })
        .collect::<Vec<_>>();

    // Fetch OAuth2 accounts using the public function from libauth
    // let oauth2_accounts = list_accounts_core(Some(session_user)).await.map_err(|e| {
    let user_id_enum2 = UserId::new(user_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid user ID: {e}"),
        )
    })?;
    let oauth2_accounts = list_accounts_core(user_id_enum2).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch accounts: {e:?}"),
        )
    })?;

    // Convert OAuth2Account to TemplateAccount
    let oauth2_accounts = oauth2_accounts
        .into_iter()
        .map(|account| {
            TemplateAccount {
                id: account.id,
                user_id: account.user_id,
                provider: account.provider,
                provider_user_id: account.provider_user_id,
                name: account.name,
                email: account.email,
                picture: account.picture.unwrap_or_default(),
                metadata_str: account.metadata.to_string(), // Convert metadata Value to string
                created_at: format_date_tz(&account.created_at, "JST"),
                updated_at: format_date_tz(&account.updated_at, "JST"),
            }
        })
        .collect();

    // Create template with all data
    // Create the route strings first

    let template = UserAccountTemplate::new(
        auth_user,
        passkey_credentials,
        oauth2_accounts,
        // Pass owned String values to the template
        O2P_ROUTE_PREFIX.to_string(),
        O2P_DEFAULT_REDIRECT.to_string(),
        O2P_CUSTOM_CSS_URL.clone(),
    );

    // Render the template
    let html = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template rendering error: {e:?}"),
        )
    })?;

    Ok(Html(html))
}

async fn serve_account_js() -> Response {
    let js_content = include_str!("../../static/account.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap_or_else(|_| Response::new("Failed to build response".into()))
}

async fn serve_base_css() -> Response {
    let css_content = include_str!("../../static/o2p-base.css");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css")
        .body(css_content.to_string().into())
        .unwrap_or_else(|_| Response::new("Failed to build response".into()))
}

static TIMEZONE_MAP: LazyLock<HashMap<&'static str, Tz>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    // These timezone strings are hardcoded and should always be valid
    map.insert(
        "JST",
        "Asia/Tokyo".parse::<Tz>().expect("Valid timezone string"),
    );
    map.insert(
        "EST",
        "America/New_York"
            .parse::<Tz>()
            .expect("Valid timezone string"),
    );
    map.insert(
        "CST",
        "America/Chicago"
            .parse::<Tz>()
            .expect("Valid timezone string"),
    );
    map.insert(
        "MST",
        "America/Denver"
            .parse::<Tz>()
            .expect("Valid timezone string"),
    );
    map.insert(
        "PST",
        "America/Los_Angeles"
            .parse::<Tz>()
            .expect("Valid timezone string"),
    );
    map.insert(
        "CET",
        "Europe/Paris".parse::<Tz>().expect("Valid timezone string"),
    );
    map.insert(
        "EET",
        "Europe/Helsinki"
            .parse::<Tz>()
            .expect("Valid timezone string"),
    );
    map.insert(
        "UTC",
        "Etc/UTC".parse::<Tz>().expect("Valid timezone string"),
    );
    map
});

/// Helper function to format DateTime<Utc> to a specific timezone format (YYYY-MM-DD HH:MM TZ)
///
/// # Arguments
/// * `date` - The UTC datetime to format
/// * `timezone_name` - The name of the timezone to display (e.g., "JST", "UTC", "EST")
fn format_date_tz(date: &DateTime<Utc>, timezone_name: &str) -> String {
    let timezone = TIMEZONE_MAP.get(timezone_name).unwrap_or(&Tz::UTC);

    // Convert to the target timezone
    let local_time = date.with_timezone(timezone);

    // Format as YYYY-MM-DD HH:MM TZ
    // Use the original timezone_name for display to keep it consistent with the user's request
    format!("{} {}", local_time.format("%Y-%m-%d %H:%M"), timezone_name)
}

#[cfg(test)]
mod tests;
