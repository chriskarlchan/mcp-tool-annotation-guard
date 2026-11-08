// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! The shared catalog store on top of PDK local Data Storage.

use std::fmt;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use guard_core::catalog::{Expect, Store, StoreError, Version};
use pdk::data_storage::{DataStorage, DataStorageError, LocalDataStorage, StoreMode};
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

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

/// A stored value, written as one byte string. Data Storage's format writes a
/// byte string and a `Vec<u8>` the same way, a length and then the bytes, but
/// handles a `Vec<u8>` one byte at a time: for a large catalog that cost every
/// call close to a millisecond.
struct Raw<'a>(&'a [u8]);

impl Serialize for Raw<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// A stored value, read as one byte string (see [`Raw`]).
struct Owned(Vec<u8>);

impl<'de> Deserialize<'de> for Owned {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Owned, D::Error> {
        deserializer.deserialize_byte_buf(OwnedVisitor)
    }
}

struct OwnedVisitor;

impl<'de> Visitor<'de> for OwnedVisitor {
    type Value = Owned;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a byte string")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Owned, E> {
        Ok(Owned(bytes.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Owned, E> {
        Ok(Owned(bytes))
    }
}

impl Store for LocalStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
        let stored = now(self.storage.get::<Owned>(key))?;
        Ok(stored.map(|(Owned(value), cas)| (value, Version(cas))))
    }

    fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
        let mode = match expected {
            Expect::Absent => StoreMode::Absent,
            Expect::Version(version) => StoreMode::Cas(version.0.clone()),
        };
        now(self.storage.store(key, &mode, &Raw(&value)))
    }

    fn keys(&self) -> Vec<String> {
        now(self.storage.get_keys()).unwrap_or_default()
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        now(self.storage.delete(key))
    }
}

#[cfg(test)]
mod tests {
    use super::{Owned, Raw};

    /// Values saved before were written as a `Vec<u8>`; they read back the
    /// same, and new values are written byte for byte as they were.
    #[test]
    fn a_value_is_stored_as_it_always_was() {
        let value: Vec<u8> = (0..=255).chain(0..=255).collect();
        let Ok(before) = serde_fixint::to_vec(&value) else {
            unreachable!()
        };
        let Ok(now) = serde_fixint::to_vec(&Raw(&value)) else {
            unreachable!()
        };
        assert_eq!(now, before, "written the same way");
        let Ok(Owned(read)) = serde_fixint::from_slice::<Owned>(&before) else {
            unreachable!()
        };
        assert_eq!(read, value, "read back the same");
        let Ok(Owned(empty)) = serde_fixint::from_slice::<Owned>(&[0; 8]) else {
            unreachable!()
        };
        assert!(empty.is_empty());
        assert!(serde_fixint::from_slice::<Owned>(&before[..before.len() - 1]).is_err());
    }
}
