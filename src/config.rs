use std::sync::LazyLock;
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::storage::InMemorySessionStore;
use crate::types::SessionStoreType;

pub static SESSION_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-SessionId".to_string())
});
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600) // Default to 10 minutes if not set or invalid
});

/// Global singleton for session storage. This follows a pattern where:
/// 1. We initialize with a safe default (InMemorySessionStore) when the library is first loaded
/// 2. The actual implementation (Memory or Redis) is determined at runtime in init_session_store()
/// 3. We use Box<dyn CacheStoreSession> to allow switching implementations through the same interface
///
/// Type structure:
/// ```text
/// static SESSION_STORE: LazyLock<Mutex<Box<dyn CacheStoreSession>>>
///     |                  |      |    |
///     |                  |      |    +-- Trait object (can be InMemorySessionStore or RedisSessionStore)
///     |                  |      +------- Heap allocation (Box)
///     |                  +-------------- Thread-safe interior mutability (Mutex)
///     +---------------------------------- Lazy initialization (LazyLock)
/// ```
///
/// Note on mutability:
/// - The LazyLock, Mutex, and Box themselves cannot be replaced (they're part of the static)
/// - However, we can change what the Box points to (the actual store implementation)
/// - When we do '*SESSION_STORE.lock().await = store', we're changing the contents at the
///   memory location the Box points to, not the Box or static itself
/// - The Mutex ensures this change happens safely across threads
pub(crate) static SESSION_STORE: LazyLock<Mutex<Box<dyn crate::storage::CacheStoreSession>>> =
    LazyLock::new(|| Mutex::new(Box::new(InMemorySessionStore::new())));

/// Initialize the session store based on environment configuration.
/// This will:
/// 1. Check environment variables for store configuration (OAUTH2_SESSION_STORE, OAUTH2_SESSION_REDIS_URL)
/// 2. Create the appropriate store implementation (Memory or Redis)
/// 3. Replace the default in-memory store in SESSION_STORE with the configured implementation
pub async fn init_session_store() -> Result<(), AppError> {
    let store_type = SessionStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize session store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        SessionStoreType::Memory
    });

    tracing::info!("Initializing session store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    *SESSION_STORE.lock().await = store;
    tracing::info!("Session store initialized successfully");
    Ok(())
}
