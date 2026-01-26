# Storage Pattern: Singleton vs Axum State

This document explains the design decision to use a singleton pattern instead of Axum's standard State pattern for managing shared resources.

## Background: Axum's State Pattern

In typical Axum applications, shared resources like database connection pools, caches, and configuration are passed to handlers using the **State pattern**:

```rust,ignore
// 1. Define a struct holding shared resources
#[derive(Clone)]
struct AppState {
    db_pool: PgPool,
    cache: RedisPool,
    config: AppConfig,
}

// 2. Attach state to the router
let state = AppState { db_pool, cache, config };
let app = Router::new()
    .route("/users", get(list_users))
    .route("/users/:id", get(get_user))
    .with_state(state);

// 3. Extract state in each handler
async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    let users = sqlx::query("SELECT * FROM users")
        .fetch_all(&state.db_pool)
        .await?;
    Json(users)
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> impl IntoResponse {
    let user = sqlx::query("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db_pool)
        .await?;
    Json(user)
}
```

This pattern is explicit, testable, and follows Rust's ownership principles.

## This Library's Approach: Singleton Pattern

This library takes a different approach using global static storage:

```rust,ignore
// 1. Initialize once at startup
oauth2_passkey_axum::init().await?;

// 2. Router doesn't need state - just merge it
let app = Router::new()
    .route("/", get(home))
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

// Internally, the library accesses global stores directly
// No State<T> extractor needed in handlers
```

### Internal Implementation

The library uses `OnceLock` (or `LazyLock`) to hold storage instances:

```rust,ignore
// Simplified internal structure
static DATA_STORE: OnceLock<Box<dyn DataStore>> = OnceLock::new();
static CACHE_STORE: OnceLock<Box<dyn CacheStore>> = OnceLock::new();

// init() populates these based on environment variables
pub async fn init() -> Result<(), Error> {
    let db = match env::var("DB_TYPE")? {
        "sqlite" => SqliteStore::new().await?,
        "postgresql" => PostgresStore::new().await?,
    };
    DATA_STORE.set(Box::new(db))?;
    // ...
}

// Internal functions access stores globally
pub(crate) fn get_data_store() -> &'static dyn DataStore {
    DATA_STORE.get().expect("Call init() first")
}
```

## Why We Chose Singleton

| Reason | Explanation |
| --- | --- |
| **Simpler API** | Users just call `init()` once. No need to create `AppState`, understand `State<T>`, or manage lifetimes. |
| **Easy Router Integration** | `oauth2_passkey_router()` returns a stateless router. Users can simply `.nest()` or `.merge()` it with their app. |
| **Internal Module Sharing** | The coordination layer accesses oauth2, passkey, session, and userdb stores. Global access avoids threading state through many internal layers. |
| **Environment Configuration** | Storage backends (SQLite/PostgreSQL, Memory/Redis) are selected via environment variables, making the singleton pattern a natural fit. |

### If We Used State Pattern Instead

The library API would become more complex:

```rust,ignore
// Hypothetical State-based API (NOT how this library works)
let auth_state = oauth2_passkey::create_state().await?;

let app = Router::new()
    .route("/", get(home))
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
    .with_state(auth_state);  // Users must manage this

// Problem: How to combine with user's own state?
// This creates friction and complexity
```

## Trade-offs

The singleton pattern has limitations:

| Trade-off | Impact | Mitigation |
| --- | --- | --- |
| **Testing** | Harder to inject mock implementations | Use separate test databases; integration tests work well |
| **Multiple Instances** | Cannot run independent instances in same process | Rarely needed for authentication systems |
| **Global State** | Less explicit dependencies | Well-documented `init()` requirement |

## When State Pattern Is Better

Consider using Axum's State pattern in your own application code when:

- You need to inject different implementations for testing
- You're building a library that others will embed
- You want explicit, compile-time dependency tracking
- You need multiple independent instances

## Conclusion

For this library's use case - a plug-and-play authentication system - the singleton approach provides a cleaner developer experience:

1. **Minimal boilerplate**: Just `init().await?` and `.nest()` the router
2. **No state management**: Users don't need to understand `State<T>`
3. **Environment-driven**: Configuration via `.env` files works naturally

The trade-offs are acceptable because most applications need only one authentication system, and the simpler API reduces the learning curve significantly.
