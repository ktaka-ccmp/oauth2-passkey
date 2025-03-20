use crate::AuthUser;
use askama::Template;

use oauth2_passkey::obfuscate_user_id;
// Template-friendly version of StoredCredential for display
#[derive(Debug)]
pub struct TemplateCredential {
    pub credential_id: String,
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
    pub oauth_route_prefix: &'static str,
    pub passkey_route_prefix: &'static str,
    pub obfuscated_user_id: String,
}

impl UserSummaryTemplate {
    pub fn new(
        user: AuthUser,
        passkey_credentials: Vec<TemplateCredential>,
        oauth2_accounts: Vec<TemplateAccount>,
        oauth_route_prefix: &'static str,
        passkey_route_prefix: &'static str,
    ) -> Self {
        let obfuscated_user_id = obfuscate_user_id(&user.id);

        Self {
            user,
            passkey_credentials,
            oauth2_accounts,
            oauth_route_prefix,
            passkey_route_prefix,
            obfuscated_user_id,
        }
    }
}
