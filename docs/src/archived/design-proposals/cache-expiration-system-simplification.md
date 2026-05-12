# Cache Expiration System Simplification

## Problem Analysis

The current codebase implements **two conflicting expiration mechanisms** for cache data:

1. **Redis native TTL** (via `EXPIRE` commands from `put_with_ttl()`)
2. **Application-level `expires_at` field** with custom Lua script validation

This architectural duplication creates unnecessary complexity, potential race conditions, and maintenance burden.

## Current Implementation Issues

### Dual Expiration Logic

```rust,ignore
// Session creation in oauth2_passkey/src/session/main/session.rs:47-61
let expires_at = Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64);
// ...
put_with_ttl(/* ... */, *SESSION_COOKIE_MAX_AGE)  // Redis native TTL

// CacheData structure with redundant field
pub struct CacheData {
    pub value: String,
    pub expires_at: DateTime<Utc>,  // Application-level expiration
}
```

### Complex Atomic Lua Script

The current Redis Lua script (`oauth2_passkey/src/storage/cache_store/redis.rs:115-198`) performs:
- JSON parsing and validation (40+ lines)
- Custom timestamp comparison logic
- Conditional deletion based on application-level expiration
- Error handling for corrupted data

**This entire script exists solely to validate the redundant `expires_at` field.**

### Race Conditions and Complexity

- Redis TTL might expire slightly before/after application `expires_at` timestamp
- Two systems must be kept in perfect sync
- Complex error handling for edge cases where systems disagree
- Maintenance burden of dual expiration logic

## Proposed Solution: Eliminate Application-Level Expiration

### Phase 1: Structural Changes

1. **Remove `expires_at` field** from `CacheData` struct
2. **Eliminate `get_and_delete_if_expired()`** method entirely
3. **Replace with simple `get()`** calls - if Redis returns data, it's valid by definition
4. **Remove the complex Lua script** (40+ lines of atomic logic becomes unnecessary)

### Phase 2: Update Callers

1. **Session management**: Replace `get_and_delete_if_expired()` calls with `get()`
2. **Update tests**: Remove expiration-specific test logic
3. **Simplify error handling**: No more "expired but not yet deleted" edge cases

### Code Changes Required

#### Before (Complex)
```rust,ignore
async fn get_and_delete_if_expired(
    &mut self,
    prefix: CachePrefix,
    key: CacheKey,
) -> Result<Option<CacheData>, StorageError> {
    // 40+ lines of Lua script execution
    // JSON parsing, timestamp validation, conditional deletion
}
```

#### After (Simple)
```rust,ignore
// Just use the existing get() method
async fn get(
    &self,
    prefix: CachePrefix,
    key: CacheKey,
) -> Result<Option<CacheData>, StorageError> {
    // If Redis returns data, it's valid (not expired)
    // Redis TTL handles expiration automatically
}
```

#### CacheData Structure Simplification

```rust,ignore
// Before
pub struct CacheData {
    pub value: String,
    pub expires_at: DateTime<Utc>,  // Remove this field
}

// After
pub struct CacheData {
    pub value: String,
    // expires_at field removed - Redis TTL handles expiration
}
```

## Benefits

### Technical Benefits
- ✅ **True atomicity**: Redis TTL is inherently atomic, no custom Lua scripts needed
- ✅ **Simplified architecture**: Single source of truth for expiration
- ✅ **Better performance**: No JSON parsing or timestamp comparisons
- ✅ **No race conditions**: Redis handles expiration consistently
- ✅ **Native optimization**: Leverages Redis's efficient built-in expiration

### Code Quality Benefits
- ✅ **Reduced complexity**: ~100+ lines of expiration logic eliminated
- ✅ **Easier maintenance**: Single expiration mechanism to maintain
- ✅ **Cleaner API**: Simpler cache operations
- ✅ **Better testability**: Fewer edge cases and race conditions to test

### Performance Benefits
- ✅ **Fewer network round-trips**: No complex Lua script execution
- ✅ **Reduced CPU overhead**: No JSON parsing for expiration checks
- ✅ **Lower memory usage**: Smaller CacheData structures
- ✅ **Redis optimization**: Native expiration is highly optimized

## Implementation Strategy

### Step 1: Prepare Migration
1. Audit all callers of `get_and_delete_if_expired()`
2. Identify test cases that depend on dual expiration logic
3. Create migration plan for data compatibility

### Step 2: Update Data Structure
1. Remove `expires_at` field from `CacheData`
2. Update serialization/deserialization to handle legacy data
3. Implement backward-compatible JSON parsing during transition

### Step 3: Replace Method Calls
1. Replace `get_and_delete_if_expired()` with `get()` calls
2. Update session management logic
3. Simplify error handling paths

### Step 4: Remove Dead Code
1. Delete `get_and_delete_if_expired()` method implementations
2. Remove complex Lua script
3. Clean up related test code
4. Update documentation

## Risk Assessment

### Risk Level: Medium
- **Impact**: Moderate - changes core caching behavior
- **Complexity**: Medium - requires careful testing of session flows
- **Compatibility**: Low risk - Redis TTL already handles expiration correctly

### Mitigation Strategies
- **Comprehensive testing**: Test all session flows thoroughly
- **Gradual rollout**: Implement changes incrementally with rollback capability
- **Monitoring**: Add logging to verify TTL behavior matches expectations
- **Backward compatibility**: Handle legacy data during transition period

## Testing Strategy

### Unit Tests
- Verify `get()` returns data for non-expired keys
- Verify `get()` returns `None` for expired keys (after TTL)
- Test session creation and retrieval flows

### Integration Tests
- Test full authentication flows with session expiration
- Verify Redis TTL behavior matches application expectations
- Test edge cases around expiration timing

### Performance Tests
- Measure performance improvement from simplified cache operations
- Verify reduced network overhead from eliminated Lua scripts

## Migration Path

### Phase 1: Preparation (Low Risk)
- Add comprehensive logging around expiration behavior
- Create compatibility shims for testing
- Document current expiration patterns

### Phase 2: Structure Changes (Medium Risk)
- Remove `expires_at` field with backward-compatible parsing
- Update `CacheData` serialization to handle old format
- Test data compatibility extensively

### Phase 3: Method Replacement (Medium Risk)
- Replace method calls incrementally
- Test each module's session behavior individually
- Monitor for any behavioral changes

### Phase 4: Cleanup (Low Risk)
- Remove dead code and complex Lua scripts
- Clean up tests and documentation
- Verify performance improvements

## Conclusion

Eliminating the redundant application-level expiration system will significantly simplify the codebase while maintaining identical functionality. The current Redis TTL mechanism already provides all necessary expiration behavior, making the custom `expires_at` validation unnecessary.

**This change represents a clear architectural improvement with measurable benefits and manageable implementation risk.**
