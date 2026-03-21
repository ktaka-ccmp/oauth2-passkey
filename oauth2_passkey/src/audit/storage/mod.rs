//! Storage layer for login history

mod config;
mod mysql;
mod postgres;
mod sqlite;
mod store_type;

// Re-export only the specific items needed for the public API
pub(crate) use store_type::LoginHistoryStore;
