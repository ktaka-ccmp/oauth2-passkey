use askama::Template;
use axum::{
    Router,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;

use serde_json::{Value, json};

use oauth2_passkey::{
    AuthenticatorInfo, O2P_ROUTE_PREFIX, get_authenticator_info, list_accounts_core,
    list_credentials_core, obfuscate_user_id,
};

use crate::config::O2P_REDIRECT_ANON;
use crate::session::AuthUser;

pub(crate) fn router() -> Router<()> {
    Router::new()
        .route("/info", get(user_info))
        .route("/login", get(login))
        .route("/summary", get(summary))
        .route("/summary.js", get(serve_summary_js))
        .route("/summary.css", get(serve_summary_css))
}

#[derive(Template)]
#[template(path = "login.j2")]
struct LoginTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'a str,
}

async fn login(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => Ok(Redirect::to(O2P_REDIRECT_ANON.as_str()).into_response()),
        None => {
            let template = LoginTemplate {
                message: "Passkey/OAuth2 Login Page!",
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html.into_response())
        }
    }
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
    pub account: String,
    pub label: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Template)]
#[template(path = "summary.j2")]
struct UserSummaryTemplate {
    pub user: TemplateAuthUser,
    pub passkey_credentials: Vec<TemplateCredential>,
    pub oauth2_accounts: Vec<TemplateAccount>,
    pub o2p_route_prefix: String,
    pub o2p_redirect_anon: String,
    pub obfuscated_user_id: String,
}

impl UserSummaryTemplate {
    fn new(
        user: AuthUser,
        passkey_credentials: Vec<TemplateCredential>,
        oauth2_accounts: Vec<TemplateAccount>,
        o2p_route_prefix: String,
        o2p_redirect_anon: String,
    ) -> Self {
        let obfuscated_user_id = obfuscate_user_id(&user.id);

        Self {
            user: TemplateAuthUser {
                id: user.id.clone(),
                account: user.account.clone(),
                label: user.label.clone(),
                created_at: format_date_tz(&user.created_at, "JST"),
                updated_at: format_date_tz(&user.updated_at, "JST"),
            },
            passkey_credentials,
            oauth2_accounts,
            o2p_route_prefix,
            o2p_redirect_anon,
            obfuscated_user_id,
        }
    }
}

/// Return basic user information as JSON for the client-side JavaScript
///
/// This endpoint provides the authenticated user's basic information (id, name, display_name)
/// to be used by client-side JavaScript for pre-filling forms or displaying user information.
async fn user_info(auth_user: Option<AuthUser>) -> Result<Json<Value>, (StatusCode, String)> {
    match auth_user {
        Some(user) => {
            // Get passkey credentials count for the user
            // let stored_credentials = list_credentials_core(Some(&user)).await.map_err(|e| {
            let stored_credentials = list_credentials_core(&user.id).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to fetch credentials: {:?}", e),
                )
            })?;

            // Return user information as JSON
            let user_data = json!({
                "id": user.id,
                "account": user.account,
                "label": user.label,
                "passkey_count": stored_credentials.len()
            });

            Ok(Json(user_data))
        }
        None => {
            // Return a 401 Unauthorized if no user is authenticated
            Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))
        }
    }
}

/// Display a comprehensive summary page with user info, passkey credentials, and OAuth2 accounts
async fn summary(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser for the core functions
    // let session_user: &SessionUser = &auth_user;
    let user_id = &auth_user.id;

    // Fetch passkey credentials using the public function from libauth
    // let stored_credentials = list_credentials_core(Some(session_user))
    let stored_credentials = list_credentials_core(user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch credentials: {:?}", e),
        )
    })?;

    // Convert StoredCredential to TemplateCredential
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
                    counter: cred.counter.to_string(),
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
    let oauth2_accounts = list_accounts_core(user_id).await.map_err(|e| {
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

    let template = UserSummaryTemplate::new(
        auth_user,
        passkey_credentials,
        oauth2_accounts,
        // Pass owned String values to the template
        O2P_ROUTE_PREFIX.to_string(),
        O2P_REDIRECT_ANON.to_string(),
    );

    // Render the template
    let html = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template rendering error: {:?}", e),
        )
    })?;

    Ok(Html(html))
}

async fn serve_summary_js() -> Response {
    let js_content = include_str!("../../static/summary.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

async fn serve_summary_css() -> Response {
    let css_content = include_str!("../../static/summary.css");
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
