//! Storage layer for login history

mod config;
mod mysql;
mod postgres;
mod sqlite;
mod store_type;

// Re-export only the specific items needed
pub(super) use config::O2P_LOGIN_HISTORY_RETENTION_DAYS;
pub(crate) use store_type::LoginHistoryStore;
