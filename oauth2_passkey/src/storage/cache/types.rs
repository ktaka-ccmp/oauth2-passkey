use crate::storage::types::CacheData;
use std::collections::HashMap;

pub(crate) struct InMemoryCacheStore {
    pub(super) entry: HashMap<String, CacheData>,
}

pub(crate) struct RedisCacheStore {
    pub(super) client: redis::Client,
}
