use askama::Template;
use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;

use oauth2_passkey::{
    AuthenticatorInfo, DbUser, O2P_ROUTE_PREFIX, get_authenticator_info, get_user,
    list_accounts_core, list_credentials_core, obfuscate_user_id,
};

use crate::{O2P_ADMIN_URL, session::AuthUser};

pub(crate) fn router() -> Router<()> {
    Router::new()
        .route("/user/{user_id}", get(user_summary))
        .route("/admin_summary.js", get(serve_summary_js))
        .route("/admin_summary.css", get(serve_summary_css))
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
    pub _provider: String,
    pub provider_user_id: String,
    pub name: String,
    pub email: String,
    pub picture: String,
    pub metadata_str: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug)]
struct TemplateUser {
    pub id: String,
    pub account: String,
    pub label: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Template)]
#[template(path = "admin_user.j2")]
struct UserSummaryTemplate {
    pub user: TemplateUser,
    pub passkey_credentials: Vec<TemplateCredential>,
    pub oauth2_accounts: Vec<TemplateAccount>,
    pub o2p_route_prefix: String,
    pub obfuscated_user_id: String,
}

impl UserSummaryTemplate {
    fn new(
        user: DbUser,
        passkey_credentials: Vec<TemplateCredential>,
        oauth2_accounts: Vec<TemplateAccount>,
        o2p_route_prefix: String,
    ) -> Self {
        let obfuscated_user_id = obfuscate_user_id(&user.id);

        Self {
            user: TemplateUser {
                id: user.id.clone(),
                account: user.account.clone(),
                label: user.label.clone(),
                created_at: format_date_tz(&user.created_at, "JST"),
                updated_at: format_date_tz(&user.updated_at, "JST"),
            },
            passkey_credentials,
            oauth2_accounts,
            o2p_route_prefix,
            obfuscated_user_id,
        }
    }
}

/// Display a comprehensive summary page with user info, passkey credentials, and OAuth2 accounts
async fn user_summary(auth_user: AuthUser, user_id: Path<String>) -> impl IntoResponse {
    // ) -> Result<Html<String>, (StatusCode, String)> {
    if !auth_user.is_admin {
        tracing::warn!(
            "User {} is not authorized to view user summary",
            auth_user.id
        );
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let user = match get_user(&user_id).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to fetch user: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch user: {:?}", e),
            ));
        }
    };
    let user = match user {
        Some(user) => user,
        None => {
            tracing::error!("User {:?} not found", &user_id);
            // return Redirect::to(O2P_REDIRECT_ANON.as_str()).into_response();
            // return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
            return Ok(Redirect::to(O2P_ADMIN_URL.as_str()).into_response());
        }
    };

    // Fetch passkey credentials using the public function from libauth
    let stored_credentials = list_credentials_core(&user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch credentials: {:?}", e),
        )
    })?;

    // Convert PasskeyCredential to TemplateCredential
    let passkey_credentials = stored_credentials
        .iter()
        .map(|cred| {
            let aaguid = cred.aaguid.clone();
            // tracing::debug!("aaguid: {}", aaguid);
            async move {
                let authenticator_info =
                    match get_authenticator_info(&aaguid).await.unwrap_or_default() {
                        Some(a) => Some(a),
                        None => Some(AuthenticatorInfo::default()),
                    };

                // tracing::debug!("Authenticator_info: {:#?}", authenticator_info);
                TemplateCredential {
                    credential_id: cred.credential_id.clone(),
                    user_id: cred.user_id.clone(),
                    user_name: cred.user.name.clone(),
                    user_display_name: cred.user.display_name.clone(),
                    user_handle: cred.user.user_handle.clone(),
                    aaguid: cred.aaguid.clone(),
                    created_at: format_date_tz(&cred.created_at, "JST"),
                    updated_at: format_date_tz(&cred.updated_at, "JST"),
                    last_used_at: format_date_tz(&cred.last_used_at, "JST"),
                    authenticator_info,
                }
            }
        })
        .collect::<Vec<_>>();

    // Wait for all async operations to complete
    let passkey_credentials = futures::future::join_all(passkey_credentials)
        .await
        .into_iter()
        .collect();

    // Fetch OAuth2 accounts using the public function from libauth
    // let oauth2_accounts = list_accounts_core(Some(session_user)).await.map_err(|e| {
    let oauth2_accounts = list_accounts_core(&user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch accounts: {:?}", e),
        )
    })?;

    // Convert OAuth2Account to TemplateAccount
    let oauth2_accounts = oauth2_accounts
        .into_iter()
        .map(|account| {
            TemplateAccount {
                id: account.id,
                user_id: account.user_id,
                _provider: account.provider,
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

    let template = UserSummaryTemplate::new(
        user,
        passkey_credentials,
        oauth2_accounts,
        O2P_ROUTE_PREFIX.to_string(),
    );

    // Render the template
    let html = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template rendering error: {:?}", e),
        )
    })?;

    Ok(Html(html).into_response())
}

async fn serve_summary_js() -> Response {
    let js_content = include_str!("../../static/admin_summary.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

async fn serve_summary_css() -> Response {
    let css_content = include_str!("../../static/admin_summary.css");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css")
        .body(css_content.to_string().into())
        .unwrap()
}

/// Helper function to format DateTime<Utc> to a specific timezone format (YYYY-MM-DD HH:MM TZ)
///
/// # Arguments
/// * `date` - The UTC datetime to format
/// * `timezone_name` - The name of the timezone to display (e.g., "JST", "UTC", "EST")
fn format_date_tz(date: &DateTime<Utc>, timezone_name: &str) -> String {
    // Map common abbreviations to full timezone names
    let tz_name = match timezone_name {
        "JST" => "Asia/Tokyo",
        "EST" => "America/New_York",
        "CST" => "America/Chicago",
        "MST" => "America/Denver",
        "PST" => "America/Los_Angeles",
        "CET" => "Europe/Paris",
        "EET" => "Europe/Helsinki",
        "UTC" | "GMT" => "Etc/UTC",
        _ => timezone_name, // Use as-is if it's already a full timezone name
    };

    // Parse the timezone string
    let timezone = match tz_name.parse::<Tz>() {
        Ok(tz) => tz,
        Err(_) => {
            tracing::error!("Failed to parse timezone: {}", tz_name);
            // Fallback to UTC if timezone parsing fails
            return format!("{} {}", date.format("%Y-%m-%d %H:%M"), "UTC");
        }
    };

    // Convert to the target timezone
    let local_time = date.with_timezone(&timezone);

    // Format as YYYY-MM-DD HH:MM TZ
    // Use the original timezone_name for display to keep it consistent with the user's request
    format!("{} {}", local_time.format("%Y-%m-%d %H:%M"), timezone_name)
}
