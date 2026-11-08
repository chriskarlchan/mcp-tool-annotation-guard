// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Monotonic pins and the catalog store behind a `Store` trait.
//!
//! A [`Catalog`] maps tool names to pins plus two freshness timestamps, and
//! records for each tool the last success whose list showed it.
//! [`Catalogs`] keeps a shared copy of each catalog in a [`Store`] (local
//! Data Storage in the policy crate) and a worker-local copy. Merging is a
//! per-tool `max` (of the pin and of the time it was listed), a union of
//! tools and a `max` of each timestamp, so it is
//! commutative, associative and idempotent below capacity, and repeated
//! merges converge.
//!
//! Design choices:
//! - Every write to the shared copy is a compare-and-swap of a merge with
//!   the current shared copy, so a write only ever adds to it: no pin and no
//!   failure is lost to a concurrent write.
//! - Nothing is evicted. A shared index lists the catalogs of one API
//!   instance and configuration; once it holds `limits.maxCatalogs`
//!   catalogs, a new catalog is refused and its tools stay unknown.
//! - Capacity also applies when merging copies: tools already in the copy
//!   being merged into are kept, and the other copy's new tools are added in
//!   name order until a limit is reached (existing pins are never evicted).
//!   At capacity, merging is therefore no longer commutative. The shared
//!   copy is always the copy merged into, so every worker keeps the same
//!   pins.
//! - A shared copy that cannot be read completely (another encoding) is
//!   never overwritten. A copy in the previous encoding, which has no listing
//!   times, is read with none: its pins are kept, and each is trusted again
//!   once a list shows its tool.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::classify::Source;
use crate::config::{Class, Classification, Config};
use crate::decide::CatalogView;
use crate::freshness::Freshness;

/// The most restrictive candidate class observed for a tool.
///
/// Ordered by class first, so `max` keeps the most restrictive pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pin {
    pub class: Class,
    pub source: Source,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogLimits {
    /// `limits.maxCachedTools`.
    pub max_cached_tools: usize,
    /// `limits.maxCatalogBytes`.
    pub max_catalog_bytes: usize,
}

/// Which limit stopped a tool from being pinned (logged as `pin_capacity_exhausted.limit`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityLimit {
    MaxCachedTools,
    MaxCatalogBytes,
    /// The catalog itself was refused.
    MaxCatalogs,
}

impl CapacityLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            CapacityLimit::MaxCachedTools => "maxCachedTools",
            CapacityLimit::MaxCatalogBytes => "maxCatalogBytes",
            CapacityLimit::MaxCatalogs => "maxCatalogs",
        }
    }
}

/// What observing a candidate did to the catalog (it is also logged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinChange {
    /// First sighting: `tool_classified`.
    New(Pin),
    /// `classification_upgraded`.
    Upgraded {
        from: Class,
        to: Class,
    },
    /// `classification_downgrade_ignored`: the pin is kept.
    DowngradeIgnored {
        pinned: Class,
        observed: Class,
    },
    Unchanged,
    /// `pin_capacity_exhausted`: the tool stays unknown.
    NotPinned(CapacityLimit),
}

/// One tool in a catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    pin: Pin,
    /// The last success whose list showed the tool.
    listed_at: Option<u64>,
}

/// One catalog: pins and freshness (the stored catalog value).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    tools: BTreeMap<String, Entry>,
    freshness: Freshness,
    /// Bytes the tools add to the encoding (an upper bound).
    tools_len: usize,
}

/// Version of the encoding stored in the shared store.
const ENCODING_VERSION: u8 = 2;
/// The previous encoding (pins without listing times), still read.
const PINS_ONLY_VERSION: u8 = 1;
/// Version of the catalog index encoding.
const INDEX_VERSION: u8 = 1;
/// Upper bound for the encoding without tools:
/// `{"v":2,"s":<20 digits>,"f":<20 digits>,"t":{}}` is 63 bytes.
const BASE_LEN: usize = 64;

/// Upper bound for one tool in the encoding:
/// `"<escaped name>":["xy",<20 digits>],`.
fn entry_len(name: &str) -> usize {
    serde_json::to_string(name).map_or(name.len() * 6 + 2, |quoted| quoted.len()) + 29
}

impl Catalog {
    /// The tool's pin, also while it must not be trusted (see [`Catalog::view`]).
    pub fn pin(&self, name: &str) -> Option<Pin> {
        self.tools.get(name).map(|entry| entry.pin)
    }

    /// What a decision about `name` may use: its pin, and whether the pin
    /// must not be trusted. A pin is trusted only if a list the guard
    /// inspected showed the tool after the catalog's last failure (and
    /// within `catalog.maxAgeSeconds`), so a success for a list without the
    /// tool, such as a later page, does not make it trusted again.
    pub fn view(&self, name: &str, now_ms: u64, max_age_seconds: u64) -> CatalogView {
        let entry = self.tools.get(name);
        CatalogView {
            pin: entry.map(|entry| entry.pin),
            stale: !entry.is_some_and(|entry| {
                self.freshness
                    .trusts(entry.listed_at, now_ms, max_age_seconds)
            }),
        }
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    pub fn freshness(&self) -> Freshness {
        self.freshness
    }

    pub fn is_stale(&self, now_ms: u64, max_age_seconds: u64) -> bool {
        self.freshness.is_stale(now_ms, max_age_seconds)
    }

    /// An upper bound for `encode().len()`, used for `limits.maxCatalogBytes`.
    pub fn encoded_len_bound(&self) -> usize {
        BASE_LEN + self.tools_len
    }

    pub fn mark_success(&mut self, now_ms: u64) {
        self.freshness.mark_success(now_ms);
    }

    pub fn mark_failure(&mut self, now_ms: u64) {
        self.freshness.mark_failure(now_ms);
    }

    /// Records that the list of the last success showed these tools. Call it
    /// right after [`Catalog::mark_success`].
    pub fn mark_listed<'n>(&mut self, names: impl IntoIterator<Item = &'n str>) {
        let listed_at = self.freshness.last_success_at;
        for name in names {
            if let Some(entry) = self.tools.get_mut(name) {
                entry.listed_at = entry.listed_at.max(listed_at);
            }
        }
    }

    /// Merges one candidate into the pins: raise, keep, or add if there is room.
    pub fn observe(&mut self, name: &str, candidate: Pin, limits: CatalogLimits) -> PinChange {
        if let Some(entry) = self.tools.get_mut(name) {
            let previous = entry.pin;
            entry.pin = previous.max(candidate);
            return match candidate.class.cmp(&previous.class) {
                Ordering::Greater => PinChange::Upgraded {
                    from: previous.class,
                    to: candidate.class,
                },
                Ordering::Less => PinChange::DowngradeIgnored {
                    pinned: previous.class,
                    observed: candidate.class,
                },
                Ordering::Equal => PinChange::Unchanged,
            };
        }
        if self.tools.len() >= limits.max_cached_tools {
            return PinChange::NotPinned(CapacityLimit::MaxCachedTools);
        }
        let added = entry_len(name);
        if BASE_LEN + self.tools_len + added > limits.max_catalog_bytes {
            return PinChange::NotPinned(CapacityLimit::MaxCatalogBytes);
        }
        self.tools.insert(
            name.to_owned(),
            Entry {
                pin: candidate,
                listed_at: None,
            },
        );
        self.tools_len += added;
        PinChange::New(candidate)
    }

    /// Merges another copy into this one. Returns the limit that kept
    /// some of `other`'s tools out, if any.
    pub fn merge(&mut self, other: &Catalog, limits: CatalogLimits) -> Option<CapacityLimit> {
        let mut refused = None;
        for (name, theirs) in &other.tools {
            if let PinChange::NotPinned(limit) = self.observe(name, theirs.pin, limits) {
                refused.get_or_insert(limit);
            } else if let Some(mine) = self.tools.get_mut(name) {
                mine.listed_at = mine.listed_at.max(theirs.listed_at);
            }
        }
        self.freshness.merge(&other.freshness);
        refused
    }

    /// `true` when this copy has every pin of `other` at least as high, and
    /// no timestamp lower (the write-verify check).
    pub fn contains(&self, other: &Catalog) -> bool {
        self.freshness.contains(&other.freshness)
            && other.tools.iter().all(|(name, theirs)| {
                self.tools.get(name).is_some_and(|mine| {
                    mine.pin >= theirs.pin && mine.listed_at >= theirs.listed_at
                })
            })
    }

    /// Compact JSON for the shared store.
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireOut {
            v: ENCODING_VERSION,
            s: self.freshness.last_success_at,
            f: self.freshness.last_failure_at,
            t: self
                .tools
                .iter()
                .map(|(name, entry)| (name.as_str(), (pin_code(entry.pin), entry.listed_at)))
                .collect(),
        };
        serde_json::to_vec(&wire).unwrap_or_default()
    }

    /// Reads [`Catalog::encode`] output, and the previous encoding (whose
    /// tools were never listed, as far as this copy knows). Anything
    /// unreadable, or another encoding version, is `None` (treated as no
    /// shared copy). Entries with an unknown pin code are skipped.
    pub fn decode(bytes: &[u8]) -> Option<Catalog> {
        Catalog::decode_with(bytes, false)
    }

    /// Like [`Catalog::decode`], but `None` when any entry is unreadable:
    /// only a copy read completely may be rewritten.
    fn decode_complete(bytes: &[u8]) -> Option<Catalog> {
        Catalog::decode_with(bytes, true)
    }

    fn decode_with(bytes: &[u8], complete: bool) -> Option<Catalog> {
        let wire: WireIn = serde_json::from_slice(bytes).ok()?;
        if wire.v != ENCODING_VERSION && wire.v != PINS_ONLY_VERSION {
            return None;
        }
        let mut catalog = Catalog {
            freshness: Freshness {
                last_success_at: wire.s,
                last_failure_at: wire.f,
            },
            ..Catalog::default()
        };
        for (name, entry) in wire.t {
            let (code, listed_at) = match (wire.v, entry) {
                (PINS_ONLY_VERSION, WireEntry::Pin(code)) => (code, None),
                (ENCODING_VERSION, WireEntry::Listed(code, listed_at)) => (code, listed_at),
                _ if complete => return None,
                _ => continue,
            };
            match pin_from_code(&code) {
                Some(pin) => {
                    catalog.tools_len += entry_len(&name);
                    catalog.tools.insert(name, Entry { pin, listed_at });
                }
                None if complete => return None,
                None => {}
            }
        }
        Some(catalog)
    }
}

#[derive(Serialize)]
struct WireOut<'a> {
    v: u8,
    s: Option<u64>,
    f: Option<u64>,
    /// Pin code and listing time.
    t: BTreeMap<&'a str, (&'static str, Option<u64>)>,
}

#[derive(Deserialize)]
struct WireIn {
    v: u8,
    s: Option<u64>,
    f: Option<u64>,
    t: BTreeMap<String, WireEntry>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireEntry {
    /// The previous encoding: a pin code.
    Pin(String),
    /// A pin code and its listing time.
    Listed(String, Option<u64>),
}

const PIN_CODES: [(Class, Source, &str); 9] = [
    (Class::Read, Source::Annotations, "ra"),
    (Class::Read, Source::NameRule, "rn"),
    (Class::Read, Source::Default, "rd"),
    (Class::Write, Source::Annotations, "wa"),
    (Class::Write, Source::NameRule, "wn"),
    (Class::Write, Source::Default, "wd"),
    (Class::Destructive, Source::Annotations, "da"),
    (Class::Destructive, Source::NameRule, "dn"),
    (Class::Destructive, Source::Default, "dd"),
];

fn pin_code(pin: Pin) -> &'static str {
    PIN_CODES
        .iter()
        .find(|(class, source, _)| *class == pin.class && *source == pin.source)
        .map_or("dd", |(_, _, code)| code)
}

fn pin_from_code(code: &str) -> Option<Pin> {
    PIN_CODES
        .iter()
        .find(|(_, _, c)| *c == code)
        .map(|(class, source, _)| Pin {
            class: *class,
            source: *source,
        })
}

// --- catalog keys ------------------------------------------------------

/// The first 16 bytes of a digest as lowercase hex.
fn hex16(digest: &[u8]) -> String {
    let mut out = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Hash of the classification-relevant configuration (`unannotatedAs`,
/// `nameRules`, `strictContradictions`). A change starts fresh catalogs.
pub fn classification_fingerprint(classification: &Classification) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-tool-annotation-guard/classification/v1\n");
    hasher.update(classification.unannotated_as.as_str());
    hasher.update(if classification.strict_contradictions {
        "\nstrict\n"
    } else {
        "\nlenient\n"
    });
    for rule in &classification.name_rules {
        // Length-prefixed, so no pattern can imitate a rule boundary.
        hasher.update(rule.pattern.len().to_string());
        hasher.update(":");
        hasher.update(&rule.pattern);
        hasher.update(":");
        hasher.update(rule.class.as_str());
        hasher.update("\n");
    }
    hex16(&hasher.finalize())
}

/// `catalogPartition` is set but gave no usable string for this request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionUnavailable;

/// The partition key for a request: empty when `catalogPartition` is
/// unset; otherwise SHA-256 of the evaluated non-empty string, truncated to
/// 16 bytes, as hex. `value` is the evaluated expression, if it was a string.
pub fn partition_key(config: &Config, value: Option<&str>) -> Result<String, PartitionUnavailable> {
    if !config.has_catalog_partition {
        return Ok(String::new());
    }
    match value {
        Some(value) if !value.is_empty() => Ok(hex16(&Sha256::digest(value.as_bytes()))),
        _ => Err(PartitionUnavailable),
    }
}

/// Prefix of every key the guard stores.
const KEY_PREFIX: &str = "mtag1:";

/// The store key for `(apiInstanceKey, configFingerprint, partitionKey)`.
/// The two hashes have fixed lengths and come first, so the free-form API
/// instance key cannot make two keys collide.
pub fn catalog_key(api_instance: &str, fingerprint: &str, partition: &str) -> String {
    format!("{KEY_PREFIX}{fingerprint}:{partition}:{api_instance}")
}

/// The key of the index that lists the catalogs of one API instance and
/// configuration. A catalog key's partition is empty or 32 hex digits, so an
/// index key is never a catalog key.
pub fn index_key(api_instance: &str, fingerprint: &str) -> String {
    format!("{KEY_PREFIX}{fingerprint}:index:{api_instance}")
}

/// `true` for a catalog or index key of `api_instance` under another
/// configuration fingerprint.
fn is_other_configuration(key: &str, api_instance: &str, fingerprint: &str) -> bool {
    let Some((key_fingerprint, rest)) = key
        .strip_prefix(KEY_PREFIX)
        .and_then(|rest| rest.split_once(':'))
    else {
        return false;
    };
    let Some((_, key_api_instance)) = rest.split_once(':') else {
        return false;
    };
    key_fingerprint != fingerprint && key_api_instance == api_instance
}

/// Deletes the catalogs and the index that an earlier configuration of
/// `api_instance` left in the store. Best effort: returns how many keys were
/// deleted.
pub fn remove_other_configurations<S: Store>(
    store: &S,
    api_instance: &str,
    fingerprint: &str,
) -> usize {
    store
        .keys()
        .iter()
        .filter(|key| is_other_configuration(key, api_instance, fingerprint))
        .filter(|key| store.delete(key).is_ok())
        .count()
}

#[derive(Serialize)]
struct IndexOut<'a> {
    v: u8,
    k: &'a BTreeSet<String>,
}

#[derive(Deserialize)]
struct IndexIn {
    v: u8,
    k: BTreeSet<String>,
}

fn encode_index(keys: &BTreeSet<String>) -> Vec<u8> {
    serde_json::to_vec(&IndexOut {
        v: INDEX_VERSION,
        k: keys,
    })
    .unwrap_or_default()
}

fn decode_index(bytes: &[u8]) -> Option<BTreeSet<String>> {
    let wire: IndexIn = serde_json::from_slice(bytes).ok()?;
    (wire.v == INDEX_VERSION).then_some(wire.k)
}

// --- stores -----------------------------------------------------------------------

/// The version of a stored value, for compare-and-swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version(pub String);

/// What a save expects to replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect<'a> {
    /// No value is stored.
    Absent,
    /// The value read at this version, unchanged since.
    Version(&'a Version),
}

/// An operation the store did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The stored value is not the one the save expected.
    Conflict,
    /// Any other failure.
    Failed,
}

/// The shared store (local Data Storage in the policy crate). Every save is
/// a compare-and-swap.
pub trait Store {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError>;
    fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError>;
    /// Every key in the store, best effort (empty if unknown).
    fn keys(&self) -> Vec<String>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

impl<T: Store + ?Sized> Store for Rc<T> {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
        (**self).get(key)
    }

    fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
        (**self).save(key, value, expected)
    }

    fn keys(&self) -> Vec<String> {
        (**self).keys()
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        (**self).delete(key)
    }
}

/// An in-memory [`Store`] for tests and host-side tools. Like the gateway's
/// shared data, it only checks a version against a stored value: a save with
/// a version to a key that was deleted since stores it again.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: RefCell<HashMap<String, (Vec<u8>, u64)>>,
    last_version: Cell<u64>,
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
        Ok(self
            .entries
            .borrow()
            .get(key)
            .map(|(value, version)| (value.clone(), Version(version.to_string()))))
    }

    fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
        let mut entries = self.entries.borrow_mut();
        let current = entries.get(key).map(|(_, version)| version.to_string());
        let matches = match expected {
            Expect::Absent => current.is_none(),
            Expect::Version(version) => current
                .as_deref()
                .is_none_or(|current| current == version.0.as_str()),
        };
        if !matches {
            return Err(StoreError::Conflict);
        }
        let version = self.last_version.get().saturating_add(1);
        self.last_version.set(version);
        entries.insert(key.to_owned(), (value, version));
        Ok(())
    }

    fn keys(&self) -> Vec<String> {
        self.entries.borrow().keys().cloned().collect()
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.entries.borrow_mut().remove(key);
        Ok(())
    }
}

// --- local + shared copies --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogSettings {
    pub limits: CatalogLimits,
    /// `catalog.maxAgeSeconds`.
    pub max_age_seconds: u64,
    /// `limits.maxCatalogs`: catalogs per API instance and configuration.
    pub max_catalogs: usize,
}

impl CatalogSettings {
    pub fn from_config(config: &Config) -> CatalogSettings {
        CatalogSettings {
            limits: CatalogLimits {
                max_cached_tools: config.limits.max_cached_tools,
                max_catalog_bytes: config.limits.max_catalog_bytes,
            },
            max_age_seconds: config.catalog_max_age_seconds,
            max_catalogs: config.limits.max_catalogs,
        }
    }
}

/// Attempts of each compare-and-swap loop.
pub const WRITE_ATTEMPTS: usize = 8;

/// What a write did, for logging.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// One entry per observation, in order.
    pub changes: Vec<PinChange>,
    /// Set if any tool could not be pinned (`pin_capacity_exhausted`).
    pub capacity: Option<CapacityLimit>,
    /// `catalog_stale`: the catalog was fresh before this write and is stale now.
    pub became_stale: bool,
    /// `catalog_fresh`: the catalog was stale before this write and is fresh now.
    pub became_fresh: bool,
    /// `catalog_merge_retry_exhausted`: the write is kept by this worker only.
    pub retry_exhausted: bool,
}

/// The shared copy of a catalog, as read.
enum Shared {
    Absent,
    Present(Catalog, Version),
    /// The read failed, or the copy could not be read (completely, when
    /// writing). It is never overwritten.
    Unusable,
}

/// The index's answer to a new catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Admitted,
    /// `limits.maxCatalogs` reached.
    Full,
    /// The index could not be read or updated.
    Failed,
}

/// Worker-local copies plus the shared store (two layers).
pub struct Catalogs<S> {
    store: S,
    settings: CatalogSettings,
    /// See [`index_key`].
    index_key: String,
    /// Never evicted. Holds catalogs from the shared store, which the index
    /// bounds, plus at most `limits.maxCatalogs` copies the store did not
    /// accept.
    local: HashMap<String, Catalog>,
    /// Keys of local copies taken from, or saved to, the shared store.
    from_shared: HashSet<String>,
    /// The shared copy, as stored, that was last merged into a local copy by
    /// [`Catalogs::read`]. While the store holds these exact bytes, the local
    /// copy already contains everything in them. Dropped whenever the local
    /// copy changes another way.
    merged: HashMap<String, Vec<u8>>,
    /// Returned for a catalog that does not exist.
    empty: Catalog,
}

impl<S: Store> Catalogs<S> {
    pub fn new(store: S, settings: CatalogSettings, index_key: String) -> Catalogs<S> {
        Catalogs {
            store,
            settings,
            index_key,
            local: HashMap::new(),
            from_shared: HashSet::new(),
            merged: HashMap::new(),
            empty: Catalog::default(),
        }
    }

    pub fn settings(&self) -> CatalogSettings {
        self.settings
    }

    /// Read path (`tools/call`): the shared copy, with this worker's copy
    /// merged into it. This worker's copy is replaced by the result, so it
    /// only ever gains knowledge. A shared copy whose bytes were already
    /// merged is not decoded again: a large catalog would otherwise cost
    /// every call a full decode.
    pub fn read(&mut self, key: &str) -> &Catalog {
        let limits = self.settings.limits;
        let fetched = self.store.get(key);
        let unchanged = matches!(&fetched, Ok(Some((bytes, _)))
            if self.merged.get(key).is_some_and(|merged| merged == bytes));
        if unchanged && self.local.contains_key(key) {
            return self.local.get(key).unwrap_or(&self.empty);
        }
        self.merged.remove(key);
        let (shared, bytes) = match fetched {
            Ok(None) => (Shared::Absent, None),
            Ok(Some((bytes, version))) => match Catalog::decode(&bytes) {
                Some(catalog) => (Shared::Present(catalog, version), Some(bytes)),
                None => (Shared::Unusable, None),
            },
            Err(_) => (Shared::Unusable, None),
        };
        self.note_shared(key, &shared);
        if let (Shared::Present(mut view, _), Some(bytes)) = (shared, bytes) {
            self.merged.insert(key.to_owned(), bytes);
            let local = self.local.entry(key.to_owned()).or_default();
            view.merge(local, limits);
            *local = view;
            return local;
        }
        self.local.get(key).unwrap_or(&self.empty)
    }

    /// A shared copy disappears only when a configuration change removes it.
    /// A local copy taken from it is then dropped as well, so this worker
    /// starts over like every other worker instead of deciding with pins
    /// older than the ones they saw.
    fn note_shared(&mut self, key: &str, shared: &Shared) {
        match shared {
            Shared::Present(..) => {
                if !self.from_shared.contains(key) {
                    self.from_shared.insert(key.to_owned());
                }
            }
            Shared::Absent => {
                self.merged.remove(key);
                if self.from_shared.remove(key) {
                    self.local.remove(key);
                }
            }
            Shared::Unusable => {}
        }
    }

    /// Write path after a list response was fully validated and processed:
    /// merge the candidates, set `lastSuccessAt`, then write to the shared copy.
    pub fn record_success(
        &mut self,
        key: &str,
        now_ms: u64,
        observations: &[(&str, Pin)],
    ) -> WriteReport {
        self.write(key, now_ms, observations, |catalog| {
            catalog.mark_success(now_ms);
            catalog.mark_listed(observations.iter().map(|(name, _)| *name));
        })
    }

    /// Write path for a stream whose list was processed and was then followed
    /// by `notifications/tools/list_changed`: the pins are merged and
    /// `lastSuccessAt` set, but the change came after the list, so the
    /// catalog ends stale (the failure is recorded after the success, see
    /// [`Freshness::mark_failure`](crate::freshness::Freshness::mark_failure)).
    pub fn record_success_then_changed(
        &mut self,
        key: &str,
        now_ms: u64,
        observations: &[(&str, Pin)],
    ) -> WriteReport {
        self.write(key, now_ms, observations, |catalog| {
            catalog.mark_success(now_ms);
            catalog.mark_listed(observations.iter().map(|(name, _)| *name));
            catalog.mark_failure(now_ms);
        })
    }

    /// Write path after a list response could not be inspected.
    pub fn record_failure(&mut self, key: &str, now_ms: u64) -> WriteReport {
        self.write(key, now_ms, &[], |catalog| {
            catalog.mark_failure(now_ms);
        })
    }

    fn write(
        &mut self,
        key: &str,
        now_ms: u64,
        observations: &[(&str, Pin)],
        mark: impl FnOnce(&mut Catalog),
    ) -> WriteReport {
        let settings = self.settings;
        let shared = self.load(key, Catalog::decode_complete);
        self.note_shared(key, &shared);
        let mut admitted = false;
        let mut save_shared = true;
        if !matches!(shared, Shared::Present(..)) {
            let admission = match shared {
                Shared::Absent => self.admit(key),
                _ => Admission::Failed,
            };
            admitted = admission == Admission::Admitted;
            let has_local = self.local.contains_key(key);
            let local_only_full = !has_local && self.local.len() >= settings.max_catalogs;
            if admission == Admission::Full || (admission == Admission::Failed && local_only_full) {
                if !has_local {
                    // Refused: no catalog is created and its tools stay unknown.
                    return WriteReport {
                        changes: observations
                            .iter()
                            .map(|_| PinChange::NotPinned(CapacityLimit::MaxCatalogs))
                            .collect(),
                        capacity: Some(CapacityLimit::MaxCatalogs),
                        ..WriteReport::default()
                    };
                }
                // This worker already decides with a copy the store never
                // accepted: keep it current here, so its pins still rise and
                // its failures still count.
                save_shared = false;
            }
        }

        let mut view = match &shared {
            Shared::Present(catalog, _) => catalog.clone(),
            Shared::Absent | Shared::Unusable => Catalog::default(),
        };
        if let Some(local) = self.local.get(key) {
            view.merge(local, settings.limits);
        }
        let was_stale = view.is_stale(now_ms, settings.max_age_seconds);
        let mut changes: Vec<PinChange> = observations
            .iter()
            .map(|(name, pin)| view.observe(name, *pin, settings.limits))
            .collect();
        mark(&mut view);
        let mut capacity = changes.iter().find_map(|change| match change {
            PinChange::NotPinned(limit) => Some(*limit),
            _ => None,
        });

        let mut retry_exhausted = false;
        let kept = if !save_shared {
            capacity = capacity.or(Some(CapacityLimit::MaxCatalogs));
            retry_exhausted = true;
            view
        } else {
            match self.commit(key, &view, shared, admitted) {
                Some((catalog, refused)) => {
                    if !self.from_shared.contains(key) {
                        self.from_shared.insert(key.to_owned());
                    }
                    capacity = capacity.or(refused);
                    catalog
                }
                None => {
                    retry_exhausted = true;
                    view
                }
            }
        };

        // Report on the copy that is kept, which may hold other workers'
        // changes and may lack tools the shared copy had no room for.
        if let Some(limit) = capacity {
            for ((name, _), change) in observations.iter().zip(changes.iter_mut()) {
                if kept.pin(name).is_none() {
                    *change = PinChange::NotPinned(limit);
                }
            }
        }
        let is_stale = kept.is_stale(now_ms, settings.max_age_seconds);
        self.merged.remove(key);
        self.local.insert(key.to_owned(), kept);
        WriteReport {
            changes,
            capacity,
            became_stale: !was_stale && is_stale,
            became_fresh: was_stale && !is_stale,
            retry_exhausted,
        }
    }

    /// Compare-and-swap loop: merges `wanted` into the shared copy. Returns
    /// the saved copy and the limit that kept some of `wanted` out of it, or
    /// `None` if the shared copy could not be written.
    fn commit(
        &self,
        key: &str,
        wanted: &Catalog,
        first: Shared,
        mut admitted: bool,
    ) -> Option<(Catalog, Option<CapacityLimit>)> {
        let limits = self.settings.limits;
        let mut first = Some(first);
        for _ in 0..WRITE_ATTEMPTS {
            let shared = first
                .take()
                .unwrap_or_else(|| self.load(key, Catalog::decode_complete));
            let (base, version) = match shared {
                Shared::Unusable => return None,
                Shared::Absent => {
                    if !admitted && self.admit(key) != Admission::Admitted {
                        return None;
                    }
                    admitted = true;
                    (Catalog::default(), None)
                }
                Shared::Present(catalog, version) => (catalog, Some(version)),
            };
            if base.contains(wanted) {
                return Some((base, None));
            }
            let mut merged = base;
            let refused = merged.merge(wanted, limits);
            let expected = version.as_ref().map_or(Expect::Absent, Expect::Version);
            match self.store.save(key, merged.encode(), expected) {
                Ok(()) => return Some((merged, refused)),
                Err(StoreError::Conflict) => {}
                Err(StoreError::Failed) => return None,
            }
        }
        None
    }

    /// Adds `key` to the index unless the index is full (compare-and-swap).
    fn admit(&self, key: &str) -> Admission {
        for _ in 0..WRITE_ATTEMPTS {
            let (mut keys, version) = match self.store.get(&self.index_key) {
                Err(_) => return Admission::Failed,
                Ok(None) => (BTreeSet::new(), None),
                Ok(Some((bytes, version))) => match decode_index(&bytes) {
                    Some(keys) => (keys, Some(version)),
                    None => return Admission::Failed,
                },
            };
            if keys.contains(key) {
                return Admission::Admitted;
            }
            if keys.len() >= self.settings.max_catalogs {
                return Admission::Full;
            }
            keys.insert(key.to_owned());
            let expected = version.as_ref().map_or(Expect::Absent, Expect::Version);
            match self
                .store
                .save(&self.index_key, encode_index(&keys), expected)
            {
                Ok(()) => return Admission::Admitted,
                Err(StoreError::Conflict) => {}
                Err(StoreError::Failed) => return Admission::Failed,
            }
        }
        Admission::Failed
    }

    fn load(&self, key: &str, decode: fn(&[u8]) -> Option<Catalog>) -> Shared {
        match self.store.get(key) {
            Ok(None) => Shared::Absent,
            Ok(Some((bytes, version))) => match decode(&bytes) {
                Some(catalog) => Shared::Present(catalog, version),
                None => Shared::Unusable,
            },
            Err(_) => Shared::Unusable,
        }
    }

    /// The local copy, if this worker has one (for tests and diagnostics).
    pub fn local_copy(&self, key: &str) -> Option<&Catalog> {
        self.local.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    const BIG: CatalogLimits = CatalogLimits {
        max_cached_tools: 1000,
        max_catalog_bytes: 1 << 20,
    };

    const SETTINGS: CatalogSettings = CatalogSettings {
        limits: BIG,
        max_age_seconds: 0,
        max_catalogs: 10,
    };

    fn pin(class: Class) -> Pin {
        Pin {
            class,
            source: Source::Annotations,
        }
    }

    fn catalog(tools: &[(&str, Class)], success: Option<u64>, failure: Option<u64>) -> Catalog {
        let mut c = Catalog::default();
        for (name, class) in tools {
            c.observe(name, pin(*class), BIG);
        }
        c.freshness = Freshness {
            last_success_at: success,
            last_failure_at: failure,
        };
        c
    }

    fn merged(a: &Catalog, b: &Catalog) -> Catalog {
        let mut out = a.clone();
        out.merge(b, BIG);
        out
    }

    fn config(value: serde_json::Value) -> Config {
        Config::from_json(value.to_string().as_bytes()).unwrap_or_else(|err| unreachable!("{err}"))
    }

    // --- pins -------------------------------------------------------------------

    #[test]
    fn pins_only_go_up() {
        let mut c = Catalog::default();
        assert_eq!(
            c.observe("t", pin(Class::Write), BIG),
            PinChange::New(pin(Class::Write))
        );
        assert_eq!(
            c.observe("t", pin(Class::Destructive), BIG),
            PinChange::Upgraded {
                from: Class::Write,
                to: Class::Destructive
            }
        );
        assert_eq!(
            c.observe("t", pin(Class::Read), BIG),
            PinChange::DowngradeIgnored {
                pinned: Class::Destructive,
                observed: Class::Read
            }
        );
        assert_eq!(
            c.observe("t", pin(Class::Destructive), BIG),
            PinChange::Unchanged
        );
        assert_eq!(c.pin("t").map(|p| p.class), Some(Class::Destructive));
    }

    #[test]
    fn capacity_by_count_fails_closed_without_evicting() {
        let limits = CatalogLimits {
            max_cached_tools: 2,
            max_catalog_bytes: 1 << 20,
        };
        let mut c = Catalog::default();
        c.observe("a", pin(Class::Read), limits);
        c.observe("b", pin(Class::Read), limits);
        assert_eq!(
            c.observe("c", pin(Class::Read), limits),
            PinChange::NotPinned(CapacityLimit::MaxCachedTools)
        );
        assert_eq!(c.pin("c"), None, "the new tool stays unknown");
        assert!(
            c.pin("a").is_some() && c.pin("b").is_some(),
            "existing pins are kept"
        );
        // Existing pins can still be raised at capacity.
        assert!(matches!(
            c.observe("a", pin(Class::Write), limits),
            PinChange::Upgraded { .. }
        ));
    }

    #[test]
    fn capacity_by_bytes_keeps_the_encoding_within_the_limit() {
        let limits = CatalogLimits {
            max_cached_tools: 10_000,
            max_catalog_bytes: 4096,
        };
        let mut c = Catalog::default();
        let mut refused = None;
        for i in 0..1000 {
            if let PinChange::NotPinned(limit) =
                c.observe(&format!("tool_{i:04}"), pin(Class::Read), limits)
            {
                refused = Some(limit);
                break;
            }
        }
        assert_eq!(refused, Some(CapacityLimit::MaxCatalogBytes));
        c.mark_success(u64::MAX);
        let names: Vec<String> = (0..1000).map(|i| format!("tool_{i:04}")).collect();
        c.mark_listed(names.iter().map(String::as_str));
        c.mark_failure(u64::MAX);
        let encoded = c.encode();
        assert!(
            String::from_utf8_lossy(&encoded).contains(&format!(",{}]", u64::MAX)),
            "listing times are stored"
        );
        assert!(encoded.len() <= 4096, "{} bytes", encoded.len());
        assert!(encoded.len() <= c.encoded_len_bound());
    }

    #[test]
    fn escaped_names_are_counted_at_their_encoded_size() {
        let mut c = Catalog::default();
        c.observe("quote\"and\\control\u{1}", pin(Class::Read), BIG);
        c.observe("é", pin(Class::Read), BIG);
        assert!(c.encode().len() <= c.encoded_len_bound());
    }

    // --- merge ------------------------------------------------------------------

    fn samples() -> [Catalog; 3] {
        [
            catalog(
                &[("a", Class::Read), ("b", Class::Destructive)],
                Some(10),
                None,
            ),
            catalog(&[("a", Class::Write), ("c", Class::Read)], Some(5), Some(7)),
            catalog(&[("b", Class::Read), ("d", Class::Write)], None, Some(12)),
        ]
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let [a, b, c] = samples();
        assert_eq!(merged(&a, &b), merged(&b, &a));
        assert_eq!(merged(&merged(&a, &b), &c), merged(&a, &merged(&b, &c)));
        assert_eq!(merged(&a, &a), a);
        let all = merged(&merged(&a, &b), &c);
        assert_eq!(all.pin("a").map(|p| p.class), Some(Class::Write));
        assert_eq!(all.pin("b").map(|p| p.class), Some(Class::Destructive));
        assert_eq!(all.len(), 4);
        assert_eq!(
            all.freshness(),
            Freshness {
                last_success_at: Some(10),
                last_failure_at: Some(12)
            }
        );
    }

    #[test]
    fn contains_checks_pins_and_timestamps() {
        let [a, b, _] = samples();
        let ab = merged(&a, &b);
        assert!(ab.contains(&a) && ab.contains(&b));
        assert!(!a.contains(&ab));
        let lower = catalog(&[("a", Class::Read), ("c", Class::Read)], Some(5), Some(7));
        assert!(!lower.contains(&b), "a lower pin is not contained");
    }

    #[test]
    fn listing_times_merge_by_max_and_are_checked_by_contains() {
        let mut a = catalog(&[("t", Class::Read), ("u", Class::Read)], None, None);
        a.mark_success(10);
        a.mark_listed(["t"]);
        let mut b = catalog(&[("t", Class::Read)], None, None);
        b.mark_success(20);
        b.mark_listed(["t"]);
        let ab = merged(&a, &b);
        assert_eq!(ab, merged(&b, &a));
        assert!(!ab.view("t", 20, 0).stale);
        assert!(ab.view("u", 20, 0).stale, "never listed");
        assert!(ab.contains(&a) && ab.contains(&b));
        assert!(!a.contains(&b), "an earlier listing time is not contained");

        // A failure on another worker after both listings untrusts t.
        let mut failed = catalog(&[], None, None);
        failed.freshness = ab.freshness();
        failed.mark_failure(15);
        let all = merged(&ab, &failed);
        assert!(all.view("t", 30, 0).stale);
        assert_eq!(all.pin("t").map(|p| p.class), Some(Class::Read));
    }

    #[test]
    fn a_success_trusts_only_the_tools_its_list_showed() {
        let mut c = catalog(&[("old", Class::Read)], None, None);
        c.mark_success(10);
        c.mark_listed(["old"]);
        c.mark_failure(20);
        c.observe("new", pin(Class::Read), BIG);
        c.mark_success(30);
        c.mark_listed(["new", "not_pinned"]);
        assert!(
            c.view("old", 30, 0).stale,
            "old was listed before the failure"
        );
        assert!(!c.view("new", 30, 0).stale);
        assert!(c.view("not_pinned", 30, 0).stale);
        assert_eq!(c.view("not_pinned", 30, 0).pin, None);
        assert!(!c.is_stale(30, 0), "the catalog as a whole is fresh again");
    }

    #[test]
    fn merge_reports_capacity() {
        let limits = CatalogLimits {
            max_cached_tools: 2,
            max_catalog_bytes: 1 << 20,
        };
        let [a, b, _] = samples();
        let mut out = a.clone();
        assert_eq!(out.merge(&b, limits), Some(CapacityLimit::MaxCachedTools));
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.pin("a").map(|p| p.class),
            Some(Class::Write),
            "existing pins still rise"
        );
    }

    // --- encoding -----------------------------------------------------------------

    #[test]
    fn encoding_round_trips() {
        let mut c = Catalog::default();
        for (i, (class, source, _)) in PIN_CODES.iter().enumerate() {
            c.observe(
                &format!("t{i}"),
                Pin {
                    class: *class,
                    source: *source,
                },
                BIG,
            );
        }
        c.mark_success(123);
        c.mark_listed(["t0", "t3"]);
        c.mark_failure(45);
        assert_eq!(Catalog::decode(&c.encode()), Some(c.clone()));
        assert!(c.encode().len() <= c.encoded_len_bound(), "the bound holds");
        assert_eq!(
            Catalog::decode(&Catalog::default().encode()),
            Some(Catalog::default())
        );
    }

    #[test]
    fn unreadable_or_other_versions_decode_to_nothing() {
        assert_eq!(Catalog::decode(b"garbage"), None);
        assert_eq!(
            Catalog::decode(br#"{"v":3,"s":null,"f":null,"t":{}}"#),
            None
        );
        let skipped =
            Catalog::decode(br#"{"v":2,"s":1,"f":null,"t":{"ok":["ra",1],"bad":["zz",1]}}"#);
        assert_eq!(skipped.map(|c| c.len()), Some(1));
        assert_eq!(
            Catalog::decode(br#"{"v":2,"s":1,"f":null,"t":{"old":"ra"}}"#).map(|c| c.len()),
            Some(0),
            "an entry in the other version's shape is skipped"
        );
    }

    #[test]
    fn the_previous_encoding_is_read_with_no_listing_times() {
        let Some(old) = Catalog::decode(br#"{"v":1,"s":5,"f":null,"t":{"wipe":"dd","bad":"zz"}}"#)
        else {
            unreachable!("the previous encoding is still read")
        };
        assert_eq!(
            old.pin("wipe"),
            Some(Pin {
                class: Class::Destructive,
                source: Source::Default,
            })
        );
        assert_eq!(old.len(), 1);
        assert!(
            old.view("wipe", 10, 0).stale,
            "kept, but not trusted until a list shows it"
        );
        assert!(Catalog::decode_complete(br#"{"v":1,"s":5,"f":null,"t":{"wipe":"dd"}}"#).is_some());
        assert!(
            Catalog::decode_complete(br#"{"v":1,"s":5,"f":null,"t":{"wipe":["dd",5]}}"#).is_none()
        );
    }

    // --- keys ---------------------------------------------------------------------

    #[test]
    fn fingerprint_follows_classification_settings_only() {
        let base = classification_fingerprint(&config(json!({})).classification);
        assert_eq!(base.len(), 32);
        assert_eq!(
            base,
            classification_fingerprint(&config(json!({})).classification)
        );
        let unrelated = config(
            json!({"grants": [{"attribute": "x", "level": "write"}], "blockedTools": ["y"]}),
        );
        assert_eq!(base, classification_fingerprint(&unrelated.classification));
        for changed in [
            json!({"unannotatedAs": "write"}),
            json!({"strictContradictions": true}),
            json!({"nameRules": [{"pattern": "^get", "class": "read"}]}),
        ] {
            assert_ne!(
                base,
                classification_fingerprint(&config(changed.clone()).classification),
                "{changed}"
            );
        }
        let one = config(
            json!({"nameRules": [{"pattern": "a", "class": "read"}, {"pattern": "b", "class": "read"}]}),
        );
        let other = config(
            json!({"nameRules": [{"pattern": "b", "class": "read"}, {"pattern": "a", "class": "read"}]}),
        );
        assert_ne!(
            classification_fingerprint(&one.classification),
            classification_fingerprint(&other.classification),
            "rule order matters"
        );
    }

    #[test]
    fn partition_key_fails_closed_when_set_but_unavailable() {
        let unset = config(json!({}));
        assert_eq!(partition_key(&unset, None), Ok(String::new()));
        assert_eq!(partition_key(&unset, Some("tenant")), Ok(String::new()));

        let set = config(json!({"catalogPartition": "#[authentication.properties.claims.tid]"}));
        assert_eq!(partition_key(&set, None), Err(PartitionUnavailable));
        assert_eq!(partition_key(&set, Some("")), Err(PartitionUnavailable));
        let a = partition_key(&set, Some("tenant-a"));
        assert_eq!(a.as_ref().map(String::len), Ok(32));
        assert_eq!(a, partition_key(&set, Some("tenant-a")));
        assert_ne!(a, partition_key(&set, Some("tenant-b")));
    }

    #[test]
    fn catalog_keys_differ_by_each_part() {
        let k = catalog_key("api-1", "f", "p");
        assert_ne!(k, catalog_key("api-2", "f", "p"));
        assert_ne!(k, catalog_key("api-1", "g", "p"));
        assert_ne!(k, catalog_key("api-1", "f", "q"));
    }

    // --- local + shared -----------------------------------------------------------

    const INDEX: &str = "index";

    fn worker<S: Store>(store: S) -> Catalogs<S> {
        Catalogs::new(store, SETTINGS, INDEX.to_owned())
    }

    fn worker_with<S: Store>(store: S, settings: CatalogSettings) -> Catalogs<S> {
        Catalogs::new(store, settings, INDEX.to_owned())
    }

    fn shared<S: Store>(store: &S, key: &str) -> Option<Catalog> {
        let (bytes, _) = store.get(key).ok().flatten()?;
        Catalog::decode(&bytes)
    }

    fn raw<S: Store>(store: &S, key: &str) -> Option<Vec<u8>> {
        store.get(key).ok().flatten().map(|(bytes, _)| bytes)
    }

    /// Writes `value` whatever is stored (another worker's committed save).
    fn put(store: &MemoryStore, key: &str, value: Vec<u8>) {
        let current = store.get(key).ok().flatten().map(|(_, version)| version);
        let expected = current.as_ref().map_or(Expect::Absent, Expect::Version);
        let saved = store.save(key, value, expected);
        assert_eq!(saved, Ok(()));
    }

    type OtherWrite = Box<dyn Fn(Option<Vec<u8>>) -> Vec<u8>>;

    /// Simulates other workers: right before our next save to a queued key,
    /// another worker commits its own save there, computed from the value
    /// stored at that moment. Our save, which read the earlier version, then
    /// conflicts.
    #[derive(Default)]
    struct RacingStore {
        inner: MemoryStore,
        others: RefCell<VecDeque<(String, OtherWrite)>>,
        before: RefCell<Option<(String, BeforeSave)>>,
    }

    type BeforeSave = Box<dyn FnOnce(&MemoryStore)>;

    impl RacingStore {
        /// Runs `action` right before our next save to `key`, for example a
        /// configuration change on another worker.
        fn before_save(&self, key: &str, action: impl FnOnce(&MemoryStore) + 'static) {
            *self.before.borrow_mut() = Some((key.to_owned(), Box::new(action)));
        }

        fn race(&self, key: &str, other: impl Fn(Option<Vec<u8>>) -> Vec<u8> + 'static) {
            self.others
                .borrow_mut()
                .push_back((key.to_owned(), Box::new(other)));
        }

        /// Another worker merging `delta` into the catalog at `key`.
        fn race_merge(&self, key: &str, delta: Catalog) {
            self.race(key, move |current| {
                let mut catalog = current
                    .and_then(|bytes| Catalog::decode(&bytes))
                    .unwrap_or_default();
                catalog.merge(&delta, BIG);
                catalog.encode()
            });
        }
    }

    impl Store for RacingStore {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
            self.inner.get(key)
        }

        fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
            let next = {
                let mut others = self.others.borrow_mut();
                match others.front() {
                    Some((other_key, _)) if other_key == key => others.pop_front(),
                    _ => None,
                }
            };
            if let Some((other_key, other)) = next {
                put(&self.inner, &other_key, other(raw(&self.inner, &other_key)));
            }
            let before = {
                let mut before = self.before.borrow_mut();
                match before.as_ref() {
                    Some((before_key, _)) if before_key == key => before.take(),
                    _ => None,
                }
            };
            if let Some((_, action)) = before {
                action(&self.inner);
            }
            self.inner.save(key, value, expected)
        }

        fn keys(&self) -> Vec<String> {
            self.inner.keys()
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.delete(key)
        }
    }

    /// Every operation fails while `failing` is set.
    #[derive(Default)]
    struct FlakyStore {
        inner: MemoryStore,
        failing: Cell<bool>,
    }

    impl Store for FlakyStore {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
            if self.failing.get() {
                return Err(StoreError::Failed);
            }
            self.inner.get(key)
        }

        fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
            if self.failing.get() {
                return Err(StoreError::Failed);
            }
            self.inner.save(key, value, expected)
        }

        fn keys(&self) -> Vec<String> {
            if self.failing.get() {
                return Vec::new();
            }
            self.inner.keys()
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            if self.failing.get() {
                return Err(StoreError::Failed);
            }
            self.inner.delete(key)
        }
    }

    fn failing_store() -> FlakyStore {
        let store = FlakyStore::default();
        store.failing.set(true);
        store
    }

    fn observations() -> Vec<(&'static str, Pin)> {
        vec![
            ("search", pin(Class::Read)),
            ("drop", pin(Class::Destructive)),
        ]
    }

    fn class_of(catalog: Option<&Catalog>, tool: &str) -> Option<Class> {
        catalog.and_then(|c| c.pin(tool)).map(|p| p.class)
    }

    #[test]
    fn the_memory_store_is_compare_and_swap() {
        let store = MemoryStore::default();
        assert_eq!(store.save("k", b"1".to_vec(), Expect::Absent), Ok(()));
        assert_eq!(
            store.save("k", b"2".to_vec(), Expect::Absent),
            Err(StoreError::Conflict)
        );
        let version = store.get("k").ok().flatten().map(|(_, v)| v);
        let version = version.unwrap_or_else(|| unreachable!());
        assert_eq!(
            store.save("k", b"2".to_vec(), Expect::Version(&version)),
            Ok(())
        );
        assert_eq!(
            store.save("k", b"3".to_vec(), Expect::Version(&version)),
            Err(StoreError::Conflict),
            "the version changed"
        );
        assert_eq!(raw(&store, "k"), Some(b"2".to_vec()));
        // Like the gateway, a version is only checked against a stored value.
        assert_eq!(store.delete("k"), Ok(()));
        assert_eq!(
            store.save("k", b"4".to_vec(), Expect::Version(&version)),
            Ok(())
        );
        assert_eq!(raw(&store, "k"), Some(b"4".to_vec()));
    }

    #[test]
    fn success_writes_local_and_shared_copies() {
        let store = Rc::new(MemoryStore::default());
        let mut w = worker(Rc::clone(&store));
        let report = w.record_success("k", 100, &observations());
        assert_eq!(
            report.changes,
            vec![
                PinChange::New(pin(Class::Read)),
                PinChange::New(pin(Class::Destructive))
            ]
        );
        assert!(!report.retry_exhausted);
        let copy = shared(&*store, "k");
        assert_eq!(class_of(copy.as_ref(), "drop"), Some(Class::Destructive));
        assert_eq!(copy.map(|c| c.freshness().last_success_at), Some(Some(100)));
        assert_eq!(
            raw(&*store, INDEX).and_then(|bytes| decode_index(&bytes)),
            Some(BTreeSet::from(["k".to_owned()]))
        );
    }

    #[test]
    fn partitions_with_the_same_tool_name_stay_separate() {
        let c = config(json!({"catalogPartition": "#[authentication.properties.claims.tid]"}));
        let fp = classification_fingerprint(&c.classification);
        let key = |tenant: &str| {
            let pk = partition_key(&c, Some(tenant)).unwrap_or_else(|_| unreachable!());
            catalog_key("api-1", &fp, &pk)
        };
        let (a, b) = (key("tenant-a"), key("tenant-b"));
        let store = Rc::new(MemoryStore::default());
        let mut w = worker(Rc::clone(&store));
        w.record_success(&a, 100, &[("operate", pin(Class::Read))]);
        w.record_success(&b, 100, &[("operate", pin(Class::Destructive))]);
        assert_eq!(class_of(Some(w.read(&a)), "operate"), Some(Class::Read));
        assert_eq!(
            class_of(Some(w.read(&b)), "operate"),
            Some(Class::Destructive)
        );
        let mut other = worker(Rc::clone(&store));
        assert_eq!(class_of(Some(other.read(&a)), "operate"), Some(Class::Read));
    }

    #[test]
    fn another_worker_reads_pins_from_the_shared_copy() {
        let store = Rc::new(MemoryStore::default());
        let mut first = worker(Rc::clone(&store));
        let mut second = worker(Rc::clone(&store));
        first.record_success("k", 100, &observations());
        assert_eq!(
            class_of(Some(second.read("k")), "drop"),
            Some(Class::Destructive)
        );
    }

    #[test]
    fn concurrent_writers_converge() {
        let store = Rc::new(MemoryStore::default());
        let mut first = worker(Rc::clone(&store));
        let mut second = worker(Rc::clone(&store));
        first.record_success("k", 100, &[("a", pin(Class::Read))]);
        second.record_success(
            "k",
            101,
            &[("b", pin(Class::Write)), ("a", pin(Class::Write))],
        );
        let copy = shared(&*store, "k");
        assert_eq!(class_of(copy.as_ref(), "a"), Some(Class::Write));
        assert_eq!(class_of(copy.as_ref(), "b"), Some(Class::Write));
        assert_eq!(class_of(Some(first.read("k")), "b"), Some(Class::Write));
    }

    #[test]
    fn a_concurrent_upgrade_is_never_overwritten() {
        let store = Rc::new(RacingStore::default());
        let mut w = worker(Rc::clone(&store));
        w.record_success("k", 100, &[("other", pin(Class::Read))]);
        // Between our read and our save, another worker upgrades "other".
        store.race_merge("k", catalog(&[("other", Class::Destructive)], None, None));
        let report = w.record_success("k", 200, &observations());
        assert!(!report.retry_exhausted, "the retry merges both");
        let copy = shared(&*store, "k");
        assert_eq!(
            class_of(copy.as_ref(), "other"),
            Some(Class::Destructive),
            "the upgrade survives our save"
        );
        assert_eq!(class_of(copy.as_ref(), "drop"), Some(Class::Destructive));
        assert_eq!(
            class_of(w.local_copy("k"), "other"),
            Some(Class::Destructive),
            "and this worker learns it"
        );
    }

    /// Lets a worker use the store another worker is saving to.
    struct Borrowed<'a>(&'a MemoryStore);

    impl Store for Borrowed<'_> {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
            self.0.get(key)
        }

        fn save(&self, key: &str, value: Vec<u8>, expected: Expect<'_>) -> Result<(), StoreError> {
            self.0.save(key, value, expected)
        }

        fn keys(&self) -> Vec<String> {
            self.0.keys()
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.0.delete(key)
        }
    }

    #[test]
    fn a_save_prepared_before_another_workers_verified_upgrade_cannot_lower_it() {
        let store = Rc::new(RacingStore::default());
        let mut b = worker(Rc::clone(&store));
        b.record_success("k", 100, &[("operate", pin(Class::Read))]);
        // B prepares another "read" save. Right before it is stored, worker A
        // sees "destructive", saves it, reads it back and finishes.
        store.before_save("k", |inner| {
            let mut a = worker(Borrowed(inner));
            let report = a.record_success("k", 150, &[("operate", pin(Class::Destructive))]);
            assert!(!report.retry_exhausted);
            let mut check = worker(Borrowed(inner));
            assert_eq!(
                class_of(Some(check.read("k")), "operate"),
                Some(Class::Destructive),
                "A's upgrade is stored"
            );
        });
        let report = b.record_success("k", 200, &[("operate", pin(Class::Read))]);
        assert!(!report.retry_exhausted);
        assert_eq!(
            class_of(shared(&*store, "k").as_ref(), "operate"),
            Some(Class::Destructive),
            "B's stale save does not lower it"
        );
        assert_eq!(
            class_of(Some(b.read("k")), "operate"),
            Some(Class::Destructive)
        );
        let mut fresh = worker(Rc::clone(&store));
        assert_eq!(
            class_of(Some(fresh.read("k")), "operate"),
            Some(Class::Destructive)
        );
    }

    #[test]
    fn a_partition_revisited_after_others_keeps_its_pins() {
        let settings = CatalogSettings {
            max_catalogs: 1,
            ..SETTINGS
        };
        let store = Rc::new(MemoryStore::default());
        let mut w = worker_with(Rc::clone(&store), settings);
        w.record_success("a", 1, &[("operate", pin(Class::Destructive))]);
        let refused = w.record_success("b", 2, &[("other", pin(Class::Read))]);
        assert_eq!(refused.capacity, Some(CapacityLimit::MaxCatalogs));
        let back = w.record_success("a", 3, &[("operate", pin(Class::Read))]);
        assert_eq!(
            back.changes,
            vec![PinChange::DowngradeIgnored {
                pinned: Class::Destructive,
                observed: Class::Read
            }]
        );
        assert_eq!(
            class_of(Some(w.read("a")), "operate"),
            Some(Class::Destructive)
        );
        let mut fresh = worker_with(Rc::clone(&store), settings);
        assert_eq!(
            class_of(Some(fresh.read("a")), "operate"),
            Some(Class::Destructive)
        );
    }

    #[test]
    fn a_concurrent_failure_is_never_erased() {
        let store = Rc::new(RacingStore::default());
        let mut w = worker(Rc::clone(&store));
        w.record_success("k", 100, &observations());
        // Another worker could not inspect a list at 150; our success was read before.
        store.race_merge("k", catalog(&[], None, Some(150)));
        let report = w.record_success("k", 120, &[]);
        assert!(!report.retry_exhausted);
        let copy = shared(&*store, "k");
        assert_eq!(copy.map(|c| c.freshness().last_failure_at), Some(Some(150)));
        assert!(w.read("k").is_stale(200, 0), "the catalog stays stale");
        let mut other = worker(Rc::clone(&store));
        assert!(other.read("k").is_stale(200, 0));
    }

    #[test]
    fn retries_are_bounded() {
        let store = Rc::new(RacingStore::default());
        let mut w = worker(Rc::clone(&store));
        w.record_success("k", 100, &[]);
        for i in 0..WRITE_ATTEMPTS {
            let name = format!("other{i}");
            store.race_merge("k", catalog(&[(&name, Class::Read)], None, None));
        }
        let report = w.record_success("k", 200, &observations());
        assert!(report.retry_exhausted);
        assert_eq!(
            class_of(Some(w.read("k")), "drop"),
            Some(Class::Destructive),
            "local pins stay"
        );
        assert!(
            shared(&*store, "k").is_some_and(|c| c.pin("other0").is_some()),
            "the other worker's saves are kept"
        );
    }

    #[test]
    fn a_failing_store_keeps_local_pins() {
        let mut w = worker(failing_store());
        let report = w.record_success("k", 100, &observations());
        assert!(report.retry_exhausted);
        assert_eq!(report.capacity, None);
        assert!(w.read("k").pin("drop").is_some());
    }

    #[test]
    fn copies_the_store_did_not_accept_are_bounded_and_kept() {
        let settings = CatalogSettings {
            max_catalogs: 2,
            ..SETTINGS
        };
        let mut w = worker_with(failing_store(), settings);
        w.record_success("a", 1, &observations());
        w.record_success("b", 2, &observations());
        let refused = w.record_success("c", 3, &observations());
        assert_eq!(refused.capacity, Some(CapacityLimit::MaxCatalogs));
        assert_eq!(
            refused.changes,
            vec![PinChange::NotPinned(CapacityLimit::MaxCatalogs); 2]
        );
        assert!(w.local_copy("c").is_none());
        assert!(w.read("c").pin("drop").is_none(), "its tools stay unknown");
        assert!(w.local_copy("a").is_some() && w.local_copy("b").is_some());
        // An existing copy still updates.
        let update = w.record_success("a", 4, &[("new", pin(Class::Write))]);
        assert_eq!(update.capacity, None);
        assert!(w.read("a").pin("new").is_some());
    }

    #[test]
    fn nothing_is_evicted_and_new_catalogs_are_refused_at_max_catalogs() {
        let settings = CatalogSettings {
            max_catalogs: 1,
            ..SETTINGS
        };
        let store = Rc::new(MemoryStore::default());
        let mut w = worker_with(Rc::clone(&store), settings);
        w.record_success("a", 1, &observations());
        let refused = w.record_success("b", 2, &observations());
        assert_eq!(refused.capacity, Some(CapacityLimit::MaxCatalogs));
        assert!(refused
            .changes
            .iter()
            .all(|c| *c == PinChange::NotPinned(CapacityLimit::MaxCatalogs)));
        assert!(!refused.retry_exhausted);
        assert_eq!(raw(&*store, "b"), None, "no shared copy");
        assert!(w.local_copy("b").is_none(), "no local copy");
        assert!(w.read("b").pin("drop").is_none());
        assert!(w.local_copy("b").is_none(), "reading creates none either");
        assert!(w.record_failure("b", 3).capacity.is_some());
        assert_eq!(
            class_of(Some(w.read("a")), "drop"),
            Some(Class::Destructive),
            "the first catalog is kept"
        );
        let mut other = worker_with(Rc::clone(&store), settings);
        assert_eq!(
            other.record_success("b", 4, &observations()).capacity,
            Some(CapacityLimit::MaxCatalogs),
            "every worker refuses it"
        );
        assert_eq!(
            other.record_success("a", 5, &[("more", pin(Class::Read))]),
            WriteReport {
                changes: vec![PinChange::New(pin(Class::Read))],
                ..WriteReport::default()
            }
        );
    }

    #[test]
    fn the_index_is_exact_under_concurrent_admission() {
        let settings = CatalogSettings {
            max_catalogs: 1,
            ..SETTINGS
        };
        // Another worker admits a different catalog first: ours is refused.
        let store = Rc::new(RacingStore::default());
        store.race(INDEX, |_| {
            encode_index(&BTreeSet::from(["other".to_owned()]))
        });
        let mut w = worker_with(Rc::clone(&store), settings);
        let report = w.record_success("k", 1, &observations());
        assert_eq!(report.capacity, Some(CapacityLimit::MaxCatalogs));
        assert_eq!(
            raw(&*store, INDEX).and_then(|bytes| decode_index(&bytes)),
            Some(BTreeSet::from(["other".to_owned()]))
        );
        assert_eq!(raw(&*store, "k"), None);

        // Another worker admits the same catalog first: ours is admitted too.
        let store = Rc::new(RacingStore::default());
        store.race(INDEX, |_| encode_index(&BTreeSet::from(["k".to_owned()])));
        let mut w = worker_with(Rc::clone(&store), settings);
        let report = w.record_success("k", 1, &observations());
        assert_eq!(report.capacity, None);
        assert!(!report.retry_exhausted);
        assert!(shared(&*store, "k").is_some_and(|c| c.pin("drop").is_some()));
    }

    #[test]
    fn an_unreadable_index_is_never_overwritten() {
        let store = Rc::new(MemoryStore::default());
        put(&store, INDEX, br#"{"v":2,"k":[]}"#.to_vec());
        let mut w = worker(Rc::clone(&store));
        let report = w.record_success("k", 1, &observations());
        assert!(report.retry_exhausted, "kept by this worker only");
        assert!(w.read("k").pin("drop").is_some());
        assert_eq!(raw(&*store, "k"), None);
        assert_eq!(raw(&*store, INDEX), Some(br#"{"v":2,"k":[]}"#.to_vec()));
    }

    #[test]
    fn merging_at_capacity_keeps_the_shared_pins() {
        let settings = CatalogSettings {
            limits: CatalogLimits {
                max_cached_tools: 1,
                max_catalog_bytes: 1 << 20,
            },
            ..SETTINGS
        };
        let store = Rc::new(FlakyStore::default());
        let mut first = worker_with(Rc::clone(&store), settings);
        let mut second = worker_with(Rc::clone(&store), settings);
        // The store is down while the second worker learns "b".
        store.failing.set(true);
        assert!(
            second
                .record_success("k", 1, &[("b", pin(Class::Read))])
                .retry_exhausted
        );
        store.failing.set(false);
        first.record_success("k", 2, &[("a", pin(Class::Destructive))]);
        // The second worker now has two copies that do not fit together.
        assert_eq!(
            class_of(Some(second.read("k")), "a"),
            Some(Class::Destructive),
            "the shared pin wins"
        );
        assert_eq!(second.read("k").pin("b"), None);
        let report = second.record_success("k", 3, &[("b", pin(Class::Read))]);
        assert_eq!(report.capacity, Some(CapacityLimit::MaxCachedTools));
        assert_eq!(
            shared(&store.inner, "k").map(|c| c.len()),
            Some(1),
            "the shared copy keeps its pin"
        );
        assert_eq!(second.read("k"), first.read("k"), "both workers agree");
    }

    #[test]
    fn an_unreadable_shared_copy_is_never_overwritten() {
        let partly = br#"{"v":1,"s":1,"f":null,"t":{"ok":"da","future":"zz"}}"#.to_vec();
        let other_version = br#"{"v":3,"s":1,"f":null,"t":{}}"#.to_vec();
        for stored in [partly, other_version] {
            let store = Rc::new(MemoryStore::default());
            put(&store, "k", stored.clone());
            let mut w = worker(Rc::clone(&store));
            let report = w.record_success("k", 100, &observations());
            assert!(report.retry_exhausted);
            assert_eq!(raw(&*store, "k"), Some(stored), "left as it is");
            assert!(w.read("k").pin("drop").is_some(), "kept by this worker");
        }
        // Reading skips only the entries it does not know.
        let store = Rc::new(MemoryStore::default());
        put(
            &store,
            "k",
            br#"{"v":1,"s":1,"f":null,"t":{"ok":"da","future":"zz"}}"#.to_vec(),
        );
        assert_eq!(
            class_of(Some(worker(Rc::clone(&store)).read("k")), "ok"),
            Some(Class::Destructive)
        );
    }

    #[test]
    fn other_configurations_are_removed() {
        let store = MemoryStore::default();
        let (ours, old) = ("a".repeat(32), "b".repeat(32));
        let partition = "c".repeat(32);
        let keep = [
            catalog_key("api-1", &ours, ""),
            catalog_key("api-1", &ours, &partition),
            index_key("api-1", &ours),
            catalog_key("api-2", &old, ""),
            index_key("api-2", &old),
            catalog_key("api-1:x", &old, ""),
            "unrelated:key".to_owned(),
        ];
        let remove = [
            catalog_key("api-1", &old, ""),
            catalog_key("api-1", &old, &partition),
            index_key("api-1", &old),
        ];
        for key in keep.iter().chain(&remove) {
            put(&store, key, b"x".to_vec());
        }
        assert_eq!(remove_other_configurations(&store, "api-1", &ours), 3);
        let mut left = store.keys();
        left.sort();
        let mut expected = keep.to_vec();
        expected.sort();
        assert_eq!(left, expected);
        assert_eq!(
            remove_other_configurations(&failing_store(), "api-1", &ours),
            0
        );
    }

    #[test]
    fn freshness_transitions_are_reported() {
        let mut w = worker(MemoryStore::default());
        assert!(!w.record_success("k", 100, &observations()).became_fresh);
        let failure = w.record_failure("k", 200);
        assert!(failure.became_stale && !failure.became_fresh);
        assert!(w.read("k").is_stale(250, 0));
        assert!(!w.record_failure("k", 300).became_stale, "already stale");
        let success = w.record_success("k", 400, &[]);
        assert!(success.became_fresh);
        assert!(w.read("k").pin("drop").is_some(), "pins survive staleness");
    }

    #[test]
    fn a_change_after_the_list_learns_pins_and_ends_stale() {
        let mut w = worker(MemoryStore::default());
        let report = w.record_success_then_changed("k", 100, &observations());
        assert!(report.became_stale && !report.became_fresh);
        assert!(w.read("k").is_stale(100, 0));
        assert!(w.read("k").pin("drop").is_some());
        // The next processed list clears it once the clock has moved on.
        assert!(w.record_success("k", 101, &[]).became_fresh);
    }

    #[test]
    fn capacity_is_reported_by_writes() {
        let settings = CatalogSettings {
            limits: CatalogLimits {
                max_cached_tools: 1,
                max_catalog_bytes: 1 << 20,
            },
            ..SETTINGS
        };
        let mut w = worker_with(MemoryStore::default(), settings);
        let report = w.record_success("k", 1, &observations());
        assert_eq!(report.capacity, Some(CapacityLimit::MaxCachedTools));
        assert_eq!(
            report.changes.get(1),
            Some(&PinChange::NotPinned(CapacityLimit::MaxCachedTools))
        );
    }

    #[test]
    fn a_copy_kept_by_one_worker_still_learns_once_max_catalogs_is_reached() {
        let settings = CatalogSettings {
            max_catalogs: 20,
            ..SETTINGS
        };
        let store = Rc::new(RacingStore::default());
        // Other workers admit their own catalogs during each of our index saves.
        for i in 0..(2 * WRITE_ATTEMPTS) {
            let name = format!("other{i}");
            store.race(INDEX, move |current| {
                let mut keys = current.and_then(|b| decode_index(&b)).unwrap_or_default();
                keys.insert(name.clone());
                encode_index(&keys)
            });
        }
        let mut w = worker_with(Rc::clone(&store), settings);
        assert!(
            w.record_success("k", 100, &[("x", pin(Class::Read))])
                .retry_exhausted
        );
        assert_eq!(raw(&*store, "k"), None, "kept by this worker only");

        let mut other = worker_with(Rc::clone(&store), settings);
        for i in 0..4 {
            other.record_success(&format!("fill{i}"), 101, &[]);
        }
        let index = raw(&*store, INDEX).and_then(|b| decode_index(&b));
        assert_eq!(index.map(|keys| keys.len()), Some(20));

        let upgrade = w.record_success("k", 200, &[("x", pin(Class::Destructive))]);
        assert_eq!(upgrade.capacity, Some(CapacityLimit::MaxCatalogs));
        assert!(upgrade.retry_exhausted);
        assert_eq!(
            upgrade.changes,
            vec![PinChange::Upgraded {
                from: Class::Read,
                to: Class::Destructive
            }]
        );
        assert_eq!(class_of(w.local_copy("k"), "x"), Some(Class::Destructive));
        assert_eq!(class_of(Some(w.read("k")), "x"), Some(Class::Destructive));

        let failure = w.record_failure("k", 300);
        assert!(failure.became_stale);
        assert!(w.read("k").is_stale(400, 0));
        assert_eq!(raw(&*store, "k"), None, "still not in the shared store");
    }

    #[test]
    fn a_read_sees_every_change_to_the_shared_copy() {
        let store = Rc::new(MemoryStore::default());
        let mut w1 = worker(Rc::clone(&store));
        let mut w2 = worker(Rc::clone(&store));
        w1.record_success("k", 100, &[("x", pin(Class::Read))]);
        assert_eq!(class_of(Some(w2.read("k")), "x"), Some(Class::Read));
        assert_eq!(class_of(Some(w2.read("k")), "x"), Some(Class::Read));
        assert!(!w2.read("k").view("x", 150, 0).stale);

        w1.record_success("k", 200, &[("x", pin(Class::Destructive))]);
        assert_eq!(class_of(Some(w2.read("k")), "x"), Some(Class::Destructive));
        w1.record_failure("k", 300);
        assert!(w2.read("k").view("x", 350, 0).stale);

        // This worker's own save is read back with the shared copy.
        w2.record_success(
            "k",
            400,
            &[("x", pin(Class::Read)), ("y", pin(Class::Write))],
        );
        let read = w2.read("k");
        assert_eq!(class_of(Some(read), "x"), Some(Class::Destructive));
        assert_eq!(class_of(Some(read), "y"), Some(Class::Write));
        assert!(!read.view("x", 450, 0).stale);
    }

    /// Reports one version for every value, as a store whose version counter
    /// came round to the same number would.
    struct OneVersion(Rc<MemoryStore>);

    impl Store for OneVersion {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Version)>, StoreError> {
            let got = self.0.get(key)?;
            Ok(got.map(|(bytes, _)| (bytes, Version("1".to_owned()))))
        }

        fn save(&self, key: &str, value: Vec<u8>, _: Expect<'_>) -> Result<(), StoreError> {
            put(&self.0, key, value);
            Ok(())
        }

        fn keys(&self) -> Vec<String> {
            self.0.keys()
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.0.delete(key)
        }
    }

    #[test]
    fn a_read_compares_the_shared_copy_itself_not_its_version() {
        let store = Rc::new(MemoryStore::default());
        let mut w1 = worker(OneVersion(Rc::clone(&store)));
        let mut w2 = worker(OneVersion(Rc::clone(&store)));
        w1.record_success("k", 100, &[("x", pin(Class::Read))]);
        assert_eq!(class_of(Some(w2.read("k")), "x"), Some(Class::Read));
        w1.record_success("k", 200, &[("x", pin(Class::Destructive))]);
        assert_eq!(class_of(Some(w2.read("k")), "x"), Some(Class::Destructive));
    }

    #[test]
    fn a_removed_shared_copy_drops_the_local_copies_taken_from_it() {
        let api = "api-1";
        let (ours, next) = ("a".repeat(32), "b".repeat(32));
        let key = catalog_key(api, &ours, "");
        let store = Rc::new(MemoryStore::default());
        let mut w1 = Catalogs::new(Rc::clone(&store), SETTINGS, index_key(api, &ours));
        let mut w2 = Catalogs::new(Rc::clone(&store), SETTINGS, index_key(api, &ours));
        w1.record_success(&key, 100, &[("x", pin(Class::Read))]);
        assert_eq!(class_of(Some(w2.read(&key)), "x"), Some(Class::Read));
        w1.record_success(&key, 200, &[("x", pin(Class::Destructive))]);

        // Another configuration is applied, and this one is later served
        // again by the same workers.
        assert_eq!(remove_other_configurations(&*store, api, &next), 2);
        assert_eq!(class_of(Some(w2.read(&key)), "x"), None, "starts over");
        assert_eq!(class_of(Some(w1.read(&key)), "x"), None, "starts over");
        assert_eq!(w2.local_copy(&key).and_then(|c| c.pin("x")), None);

        // A later save does not bring back the older pin.
        w2.record_success(&key, 300, &[]);
        let mut w3 = Catalogs::new(Rc::clone(&store), SETTINGS, index_key(api, &ours));
        assert_eq!(class_of(Some(w3.read(&key)), "x"), None);
    }

    #[test]
    fn a_save_racing_a_configuration_change_leaves_one_catalog_until_the_next_change() {
        let api = "api-1";
        let (ours, next) = ("a".repeat(32), "b".repeat(32));
        let key = catalog_key(api, &ours, "");
        let index = index_key(api, &ours);
        let settings = CatalogSettings {
            max_catalogs: 1,
            ..SETTINGS
        };
        let store = Rc::new(RacingStore::default());
        let mut w = Catalogs::new(Rc::clone(&store), settings, index.clone());
        w.record_success(&key, 100, &[("x", pin(Class::Read))]);
        let removed = next.clone();
        store.before_save(&key, move |inner| {
            assert_eq!(remove_other_configurations(inner, api, &removed), 2);
        });

        // The gateway inserts into a key removed since it was read.
        let report = w.record_success(&key, 200, &[("y", pin(Class::Write))]);
        assert!(!report.retry_exhausted);
        assert_eq!(raw(&*store, &index), None);
        let left = shared(&*store, &key);
        assert_eq!(class_of(left.as_ref(), "x"), Some(Class::Read));
        assert_eq!(class_of(left.as_ref(), "y"), Some(Class::Write));

        // The next configuration change removes it.
        assert_eq!(remove_other_configurations(&*store, api, &next), 1);
        assert_eq!(raw(&*store, &key), None);
    }

    #[test]
    fn reports_describe_the_copy_that_is_kept() {
        // Another worker records a newer failure while we save a success.
        let store = Rc::new(RacingStore::default());
        let mut w = worker(Rc::clone(&store));
        w.record_success("k", 100, &[]);
        w.record_failure("k", 150);
        store.race_merge("k", catalog(&[], None, Some(170)));
        let report = w.record_success("k", 160, &[]);
        assert!(!report.became_fresh);
        assert!(w.read("k").is_stale(200, 0));

        // Another worker takes the last free place while we save a new tool.
        let settings = CatalogSettings {
            limits: CatalogLimits {
                max_cached_tools: 1,
                max_catalog_bytes: 1 << 20,
            },
            ..SETTINGS
        };
        let store = Rc::new(RacingStore::default());
        let mut w = worker_with(Rc::clone(&store), settings);
        w.record_success("k", 100, &[]);
        store.race_merge("k", catalog(&[("z", Class::Read)], None, None));
        let report = w.record_success("k", 200, &[("y", pin(Class::Destructive))]);
        assert_eq!(
            report.changes,
            vec![PinChange::NotPinned(CapacityLimit::MaxCachedTools)]
        );
        assert_eq!(report.capacity, Some(CapacityLimit::MaxCachedTools));
        assert_eq!(w.read("k").pin("y"), None);
    }
}
