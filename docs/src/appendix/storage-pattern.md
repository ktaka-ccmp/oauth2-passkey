# Storage Pattern: Why Singleton Instead of Axum State

## The Problem with State in a Library

Axum applications typically manage shared resources (database pools, caches) through the **State pattern**, where a struct is attached to the router and extracted in each handler. This works well for application code, but creates friction when used inside a library.

### Users must initialize and manage library state

With State, the library would expose its internal state struct (containing database pools, caches, etc.) and require the user to construct and attach it to the router. Since Axum allows only one state type per router, a user who already has their own application state must merge the two into a single combined type using Axum's state composition mechanisms (`FromRef`, wrapper structs). Adding login should not require restructuring the application's state types.

### Internal state threading is burdensome

Authentication flows pass through multiple layers. For example, an OAuth2 login traverses:

```text
google_auth()           [HTTP handler]
  -> authorized_core()  [coordination layer]
    -> OAuth2Store::get_account()  [storage abstraction]
      -> database query            [SQLite or PostgreSQL]
```

With State, every function in this chain needs a state parameter -- even the intermediate layers that do not access the database themselves. The coordination layer must accept and forward state simply because a storage function three levels down needs it. When writing a handler's signature, you must already know that a function deep in the call chain requires database access. Adding a new storage call at the bottom of the chain forces signature changes through every layer above it. In this library, that would affect roughly 80-100 function signatures across the coordination, session, storage, and audit layers -- a substantial maintenance burden for a change that adds no functionality.

### State prevents environment-variable-only configuration

This library supports multiple storage backends (SQLite/PostgreSQL, Memory/Redis). The preferable user experience is to set `DB_TYPE=postgresql` in `.env` and let the library handle backend construction internally. With State, this is not possible -- the user must construct the correct backend objects and pass them into the state struct, because State requires the application to provide its contents explicitly.

## The Solution: Global Static Storage

Instead of State, this library uses `LazyLock` globals initialized once at startup:

```rust,ignore
// Simplified internal structure
static DATA_STORE: LazyLock<Mutex<Box<dyn DataStore>>> = LazyLock::new(|| {
    // Reads DB_TYPE from environment, creates appropriate backend
});
static CACHE_STORE: LazyLock<Mutex<Box<dyn CacheStore>>> = LazyLock::new(|| {
    // Reads CACHE_TYPE from environment, creates appropriate backend
});
```

For the user, integration is two lines:

```rust,ignore
oauth2_passkey_axum::init().await?;  // Force-initialize global stores
let app = Router::new().route("/", get(home)).merge(oauth2_passkey_full_router());
```

No state structs, no type composition, no Axum-specific boilerplate. Internally, any function in the library can access storage directly through the globals, regardless of where it sits in the call chain and without requiring callers to pass state down:

```rust,ignore
// Any function can read/write storage directly -- no state parameter needed
let store = GENERIC_DATA_STORE.lock().await;
let user = store.get_user(&user_id).await?;

GENERIC_CACHE_STORE.lock().await.put(prefix, key, data, ttl).await?;
```

## Limitations and How They Are Handled

### Parallel Test Isolation

This is the most significant practical cost. All tests in a process share the same `LazyLock`-initialized database, so parallel tests can interfere with each other's data.

The library addresses this through multiple mechanisms:

- **Selective serialization**: Tests that modify database state use `#[serial]` (from the `serial_test` crate). Read-only tests run in parallel without restriction.
- **Unique ID generation**: Tests generate per-test identifiers using timestamps, thread IDs, and atomic counters to avoid collisions even when running in parallel.
- **Lock-holding deletion**: `delete_user_atomically()` holds the `GENERIC_DATA_STORE` mutex lock during the entire delete sequence (OAuth2 accounts -> passkey credentials -> user) to prevent foreign key constraint violations from interleaved operations.

This approach was developed iteratively -- foreign key constraint errors in parallel tests led to the lock-holding deletion pattern. It works, but requires discipline: any new test that mutates shared state must use `#[serial]` or unique IDs.

### Implicit Global Dependencies

Function signatures do not reveal their dependency on global storage. A function like `get_user_from_session()` internally accesses `GENERIC_CACHE_STORE` and `GENERIC_DATA_STORE`, but this is invisible to the caller and not enforced by the compiler.

The practical risk is that forgetting to call `init()` causes a runtime panic on first access rather than a compile-time error. This has not been an issue in practice because `init()` is always called in `main()` and `init_test_environment()` in tests, but the compiler cannot help catch initialization ordering mistakes during refactoring.

### Single Instance Per Process

Running independent authentication instances in the same process is not possible. Global statics enforce a single configuration. This has not been a limitation in practice -- authentication systems typically need only one instance.

## Summary

This library uses `LazyLock` globals to manage storage, making database and cache access available from any function without state parameters. This approach has known costs -- parallel tests share a single database, global dependencies are invisible to the compiler, and only one instance per process is possible. However, compared to Axum's State pattern, it eliminates user-facing state composition boilerplate, avoids threading state through 80-100 internal function signatures, and enables configuration through environment variables alone -- resulting in a simpler integration experience for users.
