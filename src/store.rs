// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! The shared catalog store on top of PDK local Data Storage.

use std::future::Future;
use std::task::{Context, Poll, Waker};

use guard_core::catalog::{Expect, Store, StoreError, Version};
use pdk::data_storage::{DataStorage, DataStorageError, LocalDataStorage, StoreMode};

/// Adapts PDK [`LocalDataStorage`] to the guard-core [`Store`] trait. Local
/// Data Storage is shared by the workers of one gateway and saves with
/// compare-and-swap, so no worker's save can silently replace another's.
pub struct LocalStore {
    storage: LocalDataStorage,
}

impl LocalStore {
    pub fn new(storage: LocalDataStorage) -> LocalStore {
        LocalStore { storage }
    }
}

/// Runs a local Data Storage operation. They complete without waiting, so
/// one poll gives the result; anything still pending counts as a failure.
fn now<T>(future: impl Future<Output = Result<T, DataStorageError>>) -> Result<T, StoreError> {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(value)) => Ok(value),
        Poll::Ready(Err(DataStorageError::CasMismatch)) => Err(StoreError::Conflict),
        Poll::Ready(Err(_)) | Poll::Pending => Err(StoreError::Failed),
    }
}

impl Store for LocalStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
        let stored = now(self.storage.get::<Vec<u8>>(key))?;
        Ok(stored.map(|(value, cas)| (value, Version(cas))))
    }

    fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
        let mode = match expected {
            Expect::Absent => StoreMode::Absent,
            Expect::Version(version) => StoreMode::Cas(version.0.clone()),
        };
        now(self.storage.store(key, &mode, &value))
    }

    fn keys(&self) -> Vec<String> {
        now(self.storage.get_keys()).unwrap_or_default()
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        now(self.storage.delete(key))
    }
}
