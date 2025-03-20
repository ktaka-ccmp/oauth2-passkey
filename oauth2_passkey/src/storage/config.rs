//! Database table configuration

use std::env;
use std::sync::LazyLock;

/// Table prefix from environment variable
pub static TABLE_PREFIX: LazyLock<String> =
    LazyLock::new(|| env::var("DB_TABLE_PREFIX").unwrap_or_else(|_| "o2p_".to_string()));

/// Users table name
pub static DB_TABLE_USERS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_USERS").unwrap_or_else(|_| format!("{}{}", *TABLE_PREFIX, "users"))
});

/// Passkey credentials table name
pub static DB_TABLE_PASSKEY_CREDENTIALS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_PASSKEY_CREDENTIALS")
        .unwrap_or_else(|_| format!("{}{}", *TABLE_PREFIX, "passkey_credentials"))
});

/// OAuth2 accounts table name
pub static DB_TABLE_OAUTH2_ACCOUNTS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_OAUTH2_ACCOUNTS")
        .unwrap_or_else(|_| format!("{}{}", *TABLE_PREFIX, "oauth2_accounts"))
});
