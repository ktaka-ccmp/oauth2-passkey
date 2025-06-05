mod config;
mod memory;
mod redis;
mod types;

pub use config::GENERIC_CACHE_STORE;
pub(crate) use types::CacheStore;
// InMemoryCacheStore is only exported for tests
#[cfg(test)]
pub(crate) use types::InMemoryCacheStore;
