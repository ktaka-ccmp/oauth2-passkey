use serde::{Deserialize, Serialize};

/// Data stored in the cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_data_serialization() {
        // Given a CacheData instance
        let data = CacheData {
            value: "test value".to_string(),
        };

        // When serializing to JSON
        let json = serde_json::to_string(&data).expect("Failed to serialize CacheData");

        // Then it should produce valid JSON with the expected structure
        assert_eq!(json, "{\"value\":\"test value\"}");
    }

    #[test]
    fn test_cache_data_deserialization() {
        // Given a JSON string representing CacheData
        let json = "{\"value\":\"test value\"}";

        // When deserializing from JSON
        let data: CacheData = serde_json::from_str(json).expect("Failed to deserialize CacheData");

        // Then it should produce a CacheData instance with the expected value
        assert_eq!(data.value, "test value");
    }

    #[test]
    fn test_cache_data_clone() {
        // Given a CacheData instance
        let data = CacheData {
            value: "original value".to_string(),
        };

        // When cloning it
        let cloned_data = data.clone();

        // Then the clone should have the same value
        assert_eq!(cloned_data.value, data.value);

        // And modifying the clone should not affect the original
        let mut mutable_clone = data.clone();
        mutable_clone.value = "modified value".to_string();
        assert_eq!(data.value, "original value");
        assert_eq!(mutable_clone.value, "modified value");
    }

    #[test]
    fn test_cache_data_debug() {
        // Given a CacheData instance
        let data = CacheData {
            value: "test value".to_string(),
        };

        // When formatting with Debug
        let debug_string = format!("{:?}", data);

        // Then it should include the value
        assert!(debug_string.contains("test value"));
    }
}
