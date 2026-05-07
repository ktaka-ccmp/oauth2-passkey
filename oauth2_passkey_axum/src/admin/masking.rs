//! Data masking utilities for demo mode
//!
//! When `O2P_DEMO_MODE` is enabled, the [`Masker`] struct masks sensitive user data
//! in admin API responses. Each user can see their own data in full, but other
//! users' data is masked to protect privacy on public demo sites.
//!
//! When `O2P_DEMO_MODE` is disabled, all `Masker` methods return input unchanged.

use oauth2_passkey::DbUser;

/// Handles data masking for admin views.
///
/// When `active` is true, field methods mask sensitive data.
/// When `active` is false, all methods return input unchanged (no-op).
pub(crate) struct Masker {
    active: bool,
}

impl Masker {
    /// Create a masker for list views (admin index, get_all_users API).
    ///
    /// Active when `O2P_DEMO_MODE` is enabled.
    pub fn for_list() -> Self {
        Self {
            active: *oauth2_passkey::O2P_DEMO_MODE,
        }
    }

    /// Create an always-active masker (for testing).
    #[cfg(test)]
    pub fn always_active() -> Self {
        Self { active: true }
    }

    /// Create an always-inactive masker (for testing).
    #[cfg(test)]
    pub fn inactive() -> Self {
        Self { active: false }
    }

    /// Create a masker for detail views (admin user page, login history).
    ///
    /// Active when `O2P_DEMO_MODE` is enabled AND viewing another user's data.
    pub fn for_detail(viewer_id: &str, target_id: &str) -> Self {
        Self {
            active: *oauth2_passkey::O2P_DEMO_MODE && viewer_id != target_id,
        }
    }

    /// Whether masking is currently active. Used by callers that need to gate
    /// behavior (e.g. disabling destructive UI actions on masked resource IDs).
    pub fn is_active(&self) -> bool {
        self.active
    }

    // -- Collection-level masking --

    /// Mask a list of users for admin views.
    ///
    /// When active: filters out the demo placeholder user and masks other users'
    /// account/label fields. The viewer's own data is kept unmasked.
    /// When inactive: returns the list unchanged.
    pub fn mask_users(&self, users: Vec<DbUser>, viewer_id: &str) -> Vec<DbUser> {
        if !self.active {
            return users;
        }
        users
            .into_iter()
            .filter(|user| user.id != oauth2_passkey::DEMO_PLACEHOLDER_USER_ID)
            .map(|user| {
                if user.id == viewer_id {
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

    /// Mask a single user's account and label fields.
    ///
    /// When inactive: returns the user unchanged.
    pub fn mask_user(&self, user: DbUser) -> DbUser {
        if !self.active {
            return user;
        }
        DbUser {
            account: mask_email(&user.account),
            label: mask_name(&user.label),
            ..user
        }
    }

    // -- Field-level masking --

    /// Mask an email address. No-op when inactive.
    pub fn email(&self, val: &str) -> String {
        if self.active {
            mask_email(val)
        } else {
            val.to_string()
        }
    }

    /// Mask a name string. No-op when inactive.
    pub fn name(&self, val: &str) -> String {
        if self.active {
            mask_name(val)
        } else {
            val.to_string()
        }
    }

    /// Mask an ID string (credential, user, provider). No-op when inactive.
    pub fn id(&self, val: &str) -> String {
        if self.active {
            mask_id(val)
        } else {
            val.to_string()
        }
    }

    /// Mask an IP address. No-op when inactive.
    pub fn ip(&self, val: &str) -> String {
        if self.active {
            mask_ip(val)
        } else {
            val.to_string()
        }
    }

    /// Mask a user-agent string. No-op when inactive.
    pub fn user_agent(&self, val: &str) -> String {
        if self.active {
            mask_user_agent(val)
        } else {
            val.to_string()
        }
    }

    /// Redact a field entirely (returns empty string). No-op when inactive.
    ///
    /// Use for fields like profile pictures where any non-empty value would
    /// be rendered by the template (e.g., `{% if picture != "" %}`).
    pub fn redact(&self, val: &str) -> String {
        if self.active {
            String::new()
        } else {
            val.to_string()
        }
    }

    /// Mask metadata (replaces entirely with "***"). No-op when inactive.
    pub fn metadata(&self, val: &str) -> String {
        if self.active {
            "***".to_string()
        } else {
            val.to_string()
        }
    }
}

// -- Private helper functions --

/// Mask an email address: "user@example.com" -> "***"
fn mask_email(_email: &str) -> String {
    "***".to_string()
}

/// Mask a name string: "John Smith" -> "***"
fn mask_name(_s: &str) -> String {
    "***".to_string()
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
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        return format!("{}.{}.*.*", parts[0], parts[1]);
    }
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

#[cfg(test)]
mod tests;
