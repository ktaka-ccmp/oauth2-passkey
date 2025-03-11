use crate::AuthUser;
use askama::Template;

// Template-friendly version of StoredCredential for display
#[derive(Debug)]
pub struct TemplateCredential {
    pub credential_id_base64: String,
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: String,
    pub counter: String,
    pub created_at: String,
    pub updated_at: String,
}

// Template-friendly version of OAuth2Account for display
#[derive(Debug)]
pub struct TemplateAccount {
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

#[derive(Template)]
#[template(path = "user_summary.j2")]
pub struct UserSummaryTemplate {
    pub user: AuthUser,
    pub passkey_credentials: Vec<TemplateCredential>,
    pub oauth2_accounts: Vec<TemplateAccount>,
    pub auth_route_prefix: &'static str,
    pub passkey_route_prefix: &'static str,
}
