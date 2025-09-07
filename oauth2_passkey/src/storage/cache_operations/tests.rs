use super::*;
use crate::storage::CacheData;
use crate::test_utils::init_test_environment;

#[derive(Debug, PartialEq)]
pub struct TestError(String);

impl CacheErrorConversion<TestError> for TestError {
    fn convert_storage_error(error: StorageError) -> TestError {
        TestError(error.to_string())
    }
}

impl TryFrom<CacheData> for String {
    type Error = TestError;

    fn try_from(cache_data: CacheData) -> Result<Self, Self::Error> {
        Ok(cache_data.value)
    }
}

impl From<String> for CacheData {
    fn from(value: String) -> Self {
        CacheData { value }
    }
}

#[tokio::test]
async fn test_store_cache_keyed_legacy_compatibility() {
    init_test_environment().await;

    let test_data = "test_value".to_string();
    let prefix = CachePrefix::new("data".to_string()).unwrap();
    let key = CacheKey::new("test_key".to_string()).unwrap();

    let result =
        store_cache_keyed::<_, TestError>(prefix.clone(), key.clone(), test_data.clone(), 3600)
            .await;
    assert!(result.is_ok());

    // Verify data can be retrieved
    let retrieved = get_data::<String, TestError>(prefix, key).await;
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), Some(test_data));
}

#[tokio::test]
async fn test_store_cache_auto_legacy_compatibility() {
    init_test_environment().await;

    let test_data = "test_value".to_string();
    let prefix = CachePrefix::new("data".to_string()).unwrap();

    let result = store_cache_auto::<_, TestError>(prefix.clone(), test_data.clone(), 3600).await;
    assert!(result.is_ok());
    let generated_key = result.unwrap();

    // Verify data can be retrieved with the generated key
    let retrieved = get_data::<String, TestError>(prefix, generated_key).await;
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), Some(test_data));
}

#[tokio::test]
async fn test_remove_data() {
    init_test_environment().await;

    let test_data = "test_value".to_string();
    let prefix = CachePrefix::new("data".to_string()).unwrap();
    let key = CacheKey::new("test_key".to_string()).unwrap();

    // Store data using simplified API
    store_cache_keyed::<_, TestError>(prefix.clone(), key.clone(), test_data.clone(), 3600)
        .await
        .unwrap();

    // Verify it exists using simplified API
    let retrieved = get_data::<String, TestError>(prefix.clone(), key.clone()).await;
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), Some(test_data));

    // Remove data using simplified API
    let result = remove_data::<TestError>(prefix.clone(), key.clone()).await;
    assert!(result.is_ok());

    // Verify it's gone using simplified API
    let retrieved = get_data::<String, TestError>(prefix, key).await;
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), None);
}

#[tokio::test]
async fn test_truly_unified_cache_operations_with_validation() {
    init_test_environment().await;

    // Test that we have truly unified cache operations:
    // 1. All operations use the same typed interface
    // 2. Validation happens at caller boundary
    // 3. No validation inside wrappers

    // Valid typed arguments should work for all operations
    let prefix = CachePrefix::session();
    let key = CacheKey::new("test_unified_key".to_string()).unwrap();
    let data = "unified_test_data".to_string();

    // Store using typed arguments with simplified API
    let store_result =
        store_cache_keyed::<_, TestError>(prefix.clone(), key.clone(), data.clone(), 300).await;
    assert!(store_result.is_ok());

    // Retrieve using same typed arguments
    let get_result = get_data::<String, TestError>(prefix.clone(), key.clone()).await;
    assert!(get_result.is_ok());
    assert_eq!(get_result.unwrap(), Some(data));

    // Remove using same typed arguments
    let remove_result = remove_data::<TestError>(prefix.clone(), key.clone()).await;
    assert!(remove_result.is_ok());

    // Verify removal
    let verify_result = get_data::<String, TestError>(prefix, key).await;
    assert!(verify_result.is_ok());
    assert_eq!(verify_result.unwrap(), None);

    // Test validation at caller boundary - malicious inputs should be rejected
    // BEFORE reaching any cache operations
    let malicious_key_result = CacheKey::new("malicious\nSET attack".to_string());
    assert!(
        malicious_key_result.is_err(),
        "Malicious key should be rejected at construction"
    );

    let malicious_prefix_result = CachePrefix::new("SET attack".to_string());
    assert!(
        malicious_prefix_result.is_err(),
        "Malicious prefix should be rejected at construction"
    );

    // This proves we have truly unified cache operations with validation at the right boundary
}

#[tokio::test]
async fn test_store_cache_auto_simple_api() {
    init_test_environment().await;

    let test_data = "auto_generated_test_data".to_string();
    let prefix = CachePrefix::new("test_auto".to_string()).unwrap();

    // Store with auto-generated key
    let result = store_cache_auto::<_, TestError>(prefix.clone(), test_data.clone(), 300).await;
    assert!(result.is_ok());

    let generated_key = result.unwrap();

    // Retrieve using the generated key
    let retrieved = get_data::<String, TestError>(prefix.clone(), generated_key.clone()).await;
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), Some(test_data));

    // Clean up
    let remove_result = remove_data::<TestError>(prefix, generated_key).await;
    assert!(remove_result.is_ok());
}

#[tokio::test]
async fn test_store_cache_keyed_simple_api() {
    init_test_environment().await;

    let test_data = "meaningful_key_test_data".to_string();
    let prefix = CachePrefix::new("test_keyed".to_string()).unwrap();
    let meaningful_key = CacheKey::new("aaguid_12345678".to_string()).unwrap();

    // Store with meaningful key
    let result = store_cache_keyed::<_, TestError>(
        prefix.clone(),
        meaningful_key.clone(),
        test_data.clone(),
        300,
    )
    .await;
    assert!(result.is_ok());

    // Retrieve using the meaningful key
    let retrieved = get_data::<String, TestError>(prefix.clone(), meaningful_key.clone()).await;
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), Some(test_data));

    // Clean up
    let remove_result = remove_data::<TestError>(prefix, meaningful_key).await;
    assert!(remove_result.is_ok());
}

#[tokio::test]
async fn test_simplified_api_demonstration() {
    init_test_environment().await;

    // This test demonstrates the simplified cache API design

    let test_data = "api_demo_test_data".to_string();
    let prefix = CachePrefix::new("api_demo".to_string()).unwrap();

    // SIMPLE AUTO-GENERATED KEY API (most common case - 90% of usage)
    let auto_result =
        store_cache_auto::<_, TestError>(prefix.clone(), test_data.clone(), 300).await;
    assert!(auto_result.is_ok());
    let generated_key: CacheKey = auto_result.unwrap(); // Type inference works!

    // SIMPLE MEANINGFUL KEY API (less common case - 10% of usage)
    let meaningful_key = CacheKey::new("meaningful_identifier".to_string()).unwrap();
    let keyed_result = store_cache_keyed::<_, TestError>(
        prefix.clone(),
        meaningful_key.clone(),
        test_data.clone(),
        300,
    )
    .await;
    assert!(keyed_result.is_ok());

    // Verify both approaches work correctly
    let auto_retrieved = get_data::<String, TestError>(prefix.clone(), generated_key).await;
    let keyed_retrieved = get_data::<String, TestError>(prefix, meaningful_key).await;

    assert!(auto_retrieved.is_ok());
    assert!(keyed_retrieved.is_ok());
    assert_eq!(auto_retrieved.unwrap(), Some(test_data.clone()));
    assert_eq!(keyed_retrieved.unwrap(), Some(test_data));
}
