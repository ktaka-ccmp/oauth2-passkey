use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use super::{
    traits::CacheStore,
    types::{InMemoryCacheStore, RedisCacheStore},
};

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
            let client = redis::Client::open(store_url).expect("Failed to create Redis client");
            // Create the store but don't try to verify the connection yet
            // The connection will be established when the store is first used
            Box::new(RedisCacheStore { client })
        }
        t => panic!(
            "Unsupported cache store type: {}. Supported types are 'memory' and 'redis'",
            t
        ),
    };

    tracing::info!(
        "Connected to cache store: type={}, url={}",
        store_type,
        store_url
    );

    Mutex::new(store)
});
