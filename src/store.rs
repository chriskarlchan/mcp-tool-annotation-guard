// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! The shared catalog store on top of the PDK cache.

use guard_core::catalog::{Store, StoreError};
use pdk::cache::Cache;

/// Adapts a PDK [`Cache`] to the guard-core [`Store`] trait. The cache is
/// global across the workers of one policy instance and offers no atomic
/// operations; guard-core's write-verify loop accounts for that.
pub struct CacheStore {
    cache: Box<dyn Cache>,
}

impl CacheStore {
    pub fn new(cache: impl Cache + 'static) -> CacheStore {
        CacheStore {
            cache: Box::new(cache),
        }
    }
}

impl Store for CacheStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.cache.get(key)
    }

    fn save(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.cache.save(key, value).map_err(|_| StoreError)
    }
}
