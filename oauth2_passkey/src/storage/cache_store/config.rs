use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use super::types::{CacheStore, InMemoryCacheStore, RedisCacheStore};

pub static GENERIC_CACHE_STORE_TYPE: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_CACHE_STORE_TYPE").expect("GENERIC_CACHE_STORE_TYPE must be set")
});

pub static GENERIC_CACHE_STORE_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_CACHE_STORE_URL").expect("GENERIC_CACHE_STORE_URL must be set")
});

pub static GENERIC_CACHE_STORE: LazyLock<Mutex<Box<dyn CacheStore>>> = LazyLock::new(|| {
    let store_type = GENERIC_CACHE_STORE_TYPE.as_str();
    let store_url = GENERIC_CACHE_STORE_URL.as_str();

    tracing::info!(
        "Initializing cache store with type: {}, url: {}",
        store_type,
        store_url
    );

    let store: Box<dyn CacheStore> = match store_type {
        "memory" => Box::new(InMemoryCacheStore::new()),
        "redis" => {
            let client = match redis::Client::open(store_url) {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!("Failed to create Redis client: {}", e);
                    panic!("Failed to create Redis client: {e}");
                }
            };
            // Create the store and verify the connection immediately
            let store = RedisCacheStore { client };
            // Try to connect to verify the Redis server is available
            if let Err(e) = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async { store.init().await })
            }) {
                tracing::error!("Failed to connect to Redis: {}", e);
                panic!("Failed to connect to Redis: {e}");
            }
            Box::new(store)
        }
        t => panic!("Unsupported cache store type: {t}. Supported types are 'memory' and 'redis'"),
    };

    tracing::info!(
        "Connected to cache store: type={}, url={}",
        store_type,
        store_url
    );

    Mutex::new(store)
});
