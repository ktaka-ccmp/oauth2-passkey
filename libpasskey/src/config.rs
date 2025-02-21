use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use crate::errors::PasskeyError;
use crate::storage::{
    CacheStore, CacheStoreType, ChallengeStore, ChallengeStoreType, CredentialStore,
    CredentialStoreType, InMemoryCacheStore, InMemoryChallengeStore, InMemoryCredentialStore,
};

pub(crate) struct SingletonChallengeStore {
    store: Box<dyn ChallengeStore>,
    initialized: bool,
}

impl SingletonChallengeStore {
    fn new(store: Box<dyn ChallengeStore>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    fn set_store(&mut self, new_store: Box<dyn ChallengeStore>) -> Result<(), PasskeyError> {
        if self.initialized {
            return Err(PasskeyError::Storage(
                "Challenge store has already been initialized".to_string(),
            ));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    pub(crate) fn get_store(&self) -> &dyn ChallengeStore {
        &*self.store
    }

    pub(crate) fn get_store_mut(&mut self) -> &mut Box<dyn ChallengeStore> {
        &mut self.store
    }
}

pub(crate) static PASSKEY_CHALLENGE_STORE: LazyLock<Mutex<SingletonChallengeStore>> =
    LazyLock::new(|| {
        Mutex::new(SingletonChallengeStore::new(Box::new(
            InMemoryChallengeStore::new(),
        )))
    });

pub(crate) async fn init_challenge_store() -> Result<(), PasskeyError> {
    let store_type = ChallengeStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize token store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        ChallengeStoreType::Memory
    });

    tracing::info!("Initializing token store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    PASSKEY_CHALLENGE_STORE.lock().await.set_store(store)?;
    tracing::info!("Token store initialized successfully");
    Ok(())
}

pub(crate) struct SingletonCredentialStore {
    store: Box<dyn CredentialStore>,
    initialized: bool,
}

impl SingletonCredentialStore {
    fn new(store: Box<dyn CredentialStore>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    fn set_store(&mut self, new_store: Box<dyn CredentialStore>) -> Result<(), PasskeyError> {
        if self.initialized {
            return Err(PasskeyError::Storage(
                "Credential store has already been initialized".to_string(),
            ));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    pub(crate) fn get_store(&self) -> &dyn CredentialStore {
        &*self.store
    }

    pub(crate) fn get_store_mut(&mut self) -> &mut Box<dyn CredentialStore> {
        &mut self.store
    }
}

pub(crate) static PASSKEY_CREDENTIAL_STORE: LazyLock<Mutex<SingletonCredentialStore>> =
    LazyLock::new(|| {
        Mutex::new(SingletonCredentialStore::new(Box::new(
            InMemoryCredentialStore::new(),
        )))
    });

pub(crate) async fn init_credential_store() -> Result<(), PasskeyError> {
    let store_type = CredentialStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize token store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        CredentialStoreType::Memory
    });

    tracing::info!("Initializing token store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    PASSKEY_CREDENTIAL_STORE.lock().await.set_store(store)?;
    tracing::info!("Token store initialized successfully");
    Ok(())
}

pub(crate) static PASSKEY_CACHE_STORE: LazyLock<Mutex<SingletonCacheStore>> = LazyLock::new(|| {
    Mutex::new(SingletonCacheStore::new(
        Box::new(InMemoryCacheStore::new()),
    ))
});

pub(crate) async fn init_cache_store() -> Result<(), PasskeyError> {
    let store_type = CacheStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize token store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        CacheStoreType::Memory
    });

    tracing::info!("Initializing cache store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    PASSKEY_CACHE_STORE.lock().await.set_store(store)?;
    tracing::info!("Cache store initialized successfully");
    Ok(())
}

pub(crate) struct SingletonCacheStore {
    store: Box<dyn CacheStore>,
    initialized: bool,
}

impl SingletonCacheStore {
    fn new(store: Box<dyn CacheStore>) -> Self {
        Self {
            store,
            initialized: false,
        }
    }

    fn set_store(&mut self, new_store: Box<dyn CacheStore>) -> Result<(), PasskeyError> {
        if self.initialized {
            return Err(PasskeyError::Storage(
                "Cache store has already been initialized".to_string(),
            ));
        }
        self.store = new_store;
        self.initialized = true;
        Ok(())
    }

    pub(crate) fn get_store(&self) -> &dyn CacheStore {
        &*self.store
    }

    pub(crate) fn get_store_mut(&mut self) -> &mut Box<dyn CacheStore> {
        &mut self.store
    }
}

pub static PASSKEY_ROUTE_PREFIX: LazyLock<String> = LazyLock::new(|| {
    std::env::var("PASSKEY_ROUTE_PREFIX")
        .ok()
        .unwrap_or("/passkey".to_string())
});

pub(crate) static ORIGIN: LazyLock<String> =
    LazyLock::new(|| std::env::var("ORIGIN").expect("ORIGIN must be set"));

pub(crate) static PASSKEY_RP_ID: LazyLock<String> = LazyLock::new(|| {
    ORIGIN
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .map(|s| s.to_string())
        .expect("Could not extract RP ID from ORIGIN")
});

pub(crate) static PASSKEY_RP_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("PASSKEY_RP_NAME").ok().unwrap_or(ORIGIN.clone()));

pub(crate) static PASSKEY_TIMEOUT: LazyLock<u32> = LazyLock::new(|| {
    env::var("PASSKEY_TIMEOUT")
        .map(|v| v.parse::<u32>().unwrap_or(60))
        .unwrap_or(60)
});

pub(crate) static PASSKEY_CHALLENGE_TIMEOUT: LazyLock<u32> = LazyLock::new(|| {
    env::var("PASSKEY_CHALLENGE_TIMEOUT")
        .map(|v| v.parse::<u32>().unwrap_or(60))
        .unwrap_or(60)
});

pub(crate) static PASSKEY_AUTHENTICATOR_ATTACHMENT: LazyLock<String> = LazyLock::new(|| {
    match env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT").ok() {
        None => "platform".to_string(),
        Some(v) => match v.to_lowercase().as_str() {
            "platform" => "platform".to_string(),
            "cross-platform" => "cross-platform".to_string(),
            "none" => "None".to_string(), // Ensure "None" is capitalized
            invalid => {
                tracing::warn!(
                    "Invalid authenticator attachment: {}. Using default 'platform'",
                    invalid
                );
                "platform".to_string()
            }
        },
    }
});

pub(crate) static PASSKEY_RESIDENT_KEY: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_RESIDENT_KEY").map_or(
        "required".to_string(), // Default to required
        |v| match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => {
                tracing::warn!("Invalid user verification: {}. Using default 'required'", v);
                "required".to_string()
            }
        },
    )
});

pub(crate) static PASSKEY_REQUIRE_RESIDENT_KEY: LazyLock<bool> = LazyLock::new(|| {
    env::var("PASSKEY_REQUIRE_RESIDENT_KEY").map_or(
        true, // Default to true
        |v| match v.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            invalid => {
                tracing::warn!(
                    "Invalid require_resident_key: {}. Using default 'true'",
                    invalid
                );
                true
            }
        },
    )
});

pub(crate) static PASSKEY_USER_VERIFICATION: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_USER_VERIFICATION").map_or(
        "discouraged".to_string(), // Default to discouraged
        |v| match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => {
                tracing::warn!(
                    "Invalid user verification: {}. Using default 'discouraged'",
                    v
                );
                "discouraged".to_string()
            }
        },
    )
});
