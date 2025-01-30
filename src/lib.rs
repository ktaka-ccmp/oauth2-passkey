pub mod config;
pub mod errors;
pub mod passkey;
pub mod storage;

pub use passkey::{auth, register, AppState};
pub use storage::{
    ChallengeStore,
    ChallengeStoreType,
    CredentialStore,
    CredentialStoreType,
    InMemoryChallengeStore,
    InMemoryCredentialStore,
    // PostgresChallengeStore,
    // PostgresCredentialStore, SqliteChallengeStore, SqliteCredentialStore,
};
