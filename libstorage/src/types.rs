use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CacheData {
    pub value: Vec<u8>,
    pub ttl: usize,
}
