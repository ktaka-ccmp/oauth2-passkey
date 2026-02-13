//! Data masking utilities for demo mode
//!
//! When `O2P_DEMO_MODE` is enabled, these functions mask sensitive user data
//! in admin API responses. Each user can see their own data in full, but other
//! users' data is masked to protect privacy on public demo sites.

use oauth2_passkey::DbUser;

/// Mask an email address: "user@example.com" -> "u***@***"
///
/// Hides the entire domain (including TLD) to prevent domain-based identification.
fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, _domain)) => {
            format!("{}@***", mask_prefix(local))
        }
        None => mask_prefix(email),
    }
}

/// Mask a name string: "John Smith" -> "J*** S***"
fn mask_name(s: &str) -> String {
    s.split_whitespace()
        .map(mask_prefix)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Keep the first character, replace the rest with "***"
fn mask_prefix(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => format!("{first}***"),
        None => String::new(),
    }
}

/// Mask an IP address: "192.168.1.1" -> "192.168.*.*"
fn mask_ip(ip: &str) -> String {
    // Handle IPv4
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        return format!("{}.{}.*.*", parts[0], parts[1]);
    }
    // Handle IPv6 or other formats: just show first segment
    mask_prefix(ip)
}

/// Mask a credential or provider ID: "abc123def456" -> "abc1***"
fn mask_id(id: &str) -> String {
    if id.len() <= 4 {
        return mask_prefix(id);
    }
    let visible: String = id.chars().take(4).collect();
    format!("{visible}***")
}

/// Mask a user-agent string: show only browser family
fn mask_user_agent(ua: &str) -> String {
    // Show a generic description instead of the full UA
    if ua.contains("Chrome") {
        "Chrome/***".to_string()
    } else if ua.contains("Firefox") {
        "Firefox/***".to_string()
    } else if ua.contains("Safari") {
        "Safari/***".to_string()
    } else if ua.contains("Edge") {
        "Edge/***".to_string()
    } else {
        "***".to_string()
    }
}

/// Mask a list of users for admin views, keeping the current user's data unmasked.
///
/// Also filters out the demo placeholder user (sequence_number=1) which should
/// never appear in admin views.
pub(crate) fn mask_users(users: Vec<DbUser>, current_user_id: &str) -> Vec<DbUser> {
    users
        .into_iter()
        .filter(|user| user.id != oauth2_passkey::DEMO_PLACEHOLDER_USER_ID)
        .map(|user| {
            if user.id == current_user_id {
                user
            } else {
                DbUser {
                    account: mask_email(&user.account),
                    label: mask_name(&user.label),
                    ..user
                }
            }
        })
        .collect()
}

/// Mask sensitive fields on a single user for the admin user detail page
pub(crate) fn mask_user(user: DbUser) -> DbUser {
    DbUser {
        account: mask_email(&user.account),
        label: mask_name(&user.label),
        ..user
    }
}

/// Mask fields on an OAuth2 account (for admin user detail page)
pub(crate) fn mask_oauth2_email(email: &str) -> String {
    mask_email(email)
}

/// Mask a provider user ID (for admin user detail page)
pub(crate) fn mask_provider_user_id(id: &str) -> String {
    mask_id(id)
}

/// Mask a name field (for OAuth2 account name on admin detail page)
pub(crate) fn mask_account_name(name: &str) -> String {
    mask_name(name)
}

/// Mask a credential ID (for admin user detail page)
pub(crate) fn mask_credential_id(id: &str) -> String {
    mask_id(id)
}

/// Mask an IP address (for audit log)
pub(crate) fn mask_ip_address(ip: &str) -> String {
    mask_ip(ip)
}

/// Mask a user-agent string (for audit log)
pub(crate) fn mask_user_agent_string(ua: &str) -> String {
    mask_user_agent(ua)
}

/// Mask a user ID (internal UUID, for credential/account sub-items and audit log)
pub(crate) fn mask_user_id(id: &str) -> String {
    mask_id(id)
}

/// Mask a WebAuthn user handle (for passkey credential details)
pub(crate) fn mask_user_handle(handle: &str) -> String {
    mask_id(handle)
}

#[cfg(test)]
mod tests;
