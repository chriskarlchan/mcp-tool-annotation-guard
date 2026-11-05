// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Monotonic pins and the catalog store behind a `Store` trait.
//!
//! A [`Catalog`] maps tool names to pins plus two freshness timestamps.
//! [`Catalogs`] keeps a worker-local copy of each catalog and a shared copy in
//! a [`Store`] (the PDK cache in the policy crate). Merging is a per-tool
//! `max`, a union of tools and a `max` of each timestamp, so it is
//! commutative, associative and idempotent below capacity, and repeated
//! merges converge.
//!
//! Design choices:
//! - Capacity also applies when merging copies: tools already in the copy
//!   being merged into are kept, and the other copy's new tools are added in
//!   name order until a limit is reached (existing pins are never evicted).
//!   At capacity, merging is therefore no longer commutative.
//! - Worker-local copies are bounded by `limits.maxCatalogs` too, evicting
//!   the least recently used copy.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::classify::Source;
use crate::config::{Class, Classification, Config};
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
}

impl CapacityLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            CapacityLimit::MaxCachedTools => "maxCachedTools",
            CapacityLimit::MaxCatalogBytes => "maxCatalogBytes",
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

/// One catalog: pins and freshness (the stored catalog value).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    tools: BTreeMap<String, Pin>,
    freshness: Freshness,
    /// Bytes the tools add to the encoding (an upper bound).
    tools_len: usize,
}

/// Version of the encoding stored in the shared store.
const ENCODING_VERSION: u8 = 1;
/// Upper bound for the encoding without tools:
/// `{"v":1,"s":<20 digits>,"f":<20 digits>,"t":{}}` is 63 bytes.
const BASE_LEN: usize = 64;

/// Upper bound for one tool in the encoding: `"<escaped name>":"xy",`.
fn entry_len(name: &str) -> usize {
    serde_json::to_string(name).map_or(name.len() * 6 + 2, |quoted| quoted.len()) + 6
}

impl Catalog {
    pub fn pin(&self, name: &str) -> Option<Pin> {
        self.tools.get(name).copied()
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

    /// Merges one candidate into the pins: raise, keep, or add if there is room.
    pub fn observe(&mut self, name: &str, candidate: Pin, limits: CatalogLimits) -> PinChange {
        if let Some(pinned) = self.tools.get_mut(name) {
            let previous = *pinned;
            *pinned = previous.max(candidate);
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
        self.tools.insert(name.to_owned(), candidate);
        self.tools_len += added;
        PinChange::New(candidate)
    }

    /// Merges another copy into this one. Returns the limit that kept
    /// some of `other`'s tools out, if any.
    pub fn merge(&mut self, other: &Catalog, limits: CatalogLimits) -> Option<CapacityLimit> {
        let mut refused = None;
        for (name, pin) in &other.tools {
            if let PinChange::NotPinned(limit) = self.observe(name, *pin, limits) {
                refused.get_or_insert(limit);
            }
        }
        self.freshness.merge(&other.freshness);
        refused
    }

    /// `true` when this copy has every pin of `other` at least as high, and
    /// no timestamp lower (the write-verify check).
    pub fn contains(&self, other: &Catalog) -> bool {
        self.freshness.contains(&other.freshness)
            && other
                .tools
                .iter()
                .all(|(name, pin)| self.tools.get(name).is_some_and(|mine| mine >= pin))
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
                .map(|(name, pin)| (name.as_str(), pin_code(*pin)))
                .collect(),
        };
        serde_json::to_vec(&wire).unwrap_or_default()
    }

    /// Reads [`Catalog::encode`] output. Anything unreadable, or another
    /// encoding version, is `None` (treated as no shared copy). Entries with
    /// an unknown pin code are skipped.
    pub fn decode(bytes: &[u8]) -> Option<Catalog> {
        let wire: WireIn = serde_json::from_slice(bytes).ok()?;
        if wire.v != ENCODING_VERSION {
            return None;
        }
        let mut catalog = Catalog {
            freshness: Freshness {
                last_success_at: wire.s,
                last_failure_at: wire.f,
            },
            ..Catalog::default()
        };
        for (name, code) in wire.t {
            if let Some(pin) = pin_from_code(&code) {
                catalog.tools_len += entry_len(&name);
                catalog.tools.insert(name, pin);
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
    t: BTreeMap<&'a str, &'static str>,
}

#[derive(Deserialize)]
struct WireIn {
    v: u8,
    s: Option<u64>,
    f: Option<u64>,
    t: BTreeMap<String, String>,
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

/// The store key for `(apiInstanceKey, configFingerprint, partitionKey)`.
/// The two hashes have fixed lengths and come first, so the free-form API
/// instance key cannot make two keys collide.
pub fn catalog_key(api_instance: &str, fingerprint: &str, partition: &str) -> String {
    format!("mtag1:{fingerprint}:{partition}:{api_instance}")
}

// --- stores -----------------------------------------------------------------------

/// A save that the store did not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError;

/// The shared store (the PDK cache in the policy crate). It offers no atomic
/// operations, and a save may overwrite a concurrent save.
pub trait Store {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn save(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError>;
}

impl<T: Store + ?Sized> Store for Rc<T> {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        (**self).get(key)
    }

    fn save(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        (**self).save(key, value)
    }
}

/// An in-memory [`Store`] for tests and host-side tools.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: RefCell<HashMap<String, Vec<u8>>>,
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.entries.borrow().get(key).cloned()
    }

    fn save(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.entries.borrow_mut().insert(key.to_owned(), value);
        Ok(())
    }
}

// --- local + shared copies --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogSettings {
    pub limits: CatalogLimits,
    /// `catalog.maxAgeSeconds`.
    pub max_age_seconds: u64,
    /// Bound for worker-local copies (`limits.maxCatalogs`).
    pub max_local_catalogs: usize,
}

impl CatalogSettings {
    pub fn from_config(config: &Config) -> CatalogSettings {
        CatalogSettings {
            limits: CatalogLimits {
                max_cached_tools: config.limits.max_cached_tools,
                max_catalog_bytes: config.limits.max_catalog_bytes,
            },
            max_age_seconds: config.catalog_max_age_seconds,
            max_local_catalogs: config.limits.max_catalogs,
        }
    }
}

/// Attempts of the write-verify loop.
pub const WRITE_ATTEMPTS: usize = 3;

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
    /// `catalog_merge_retry_exhausted`: the shared copy still lacks something.
    pub retry_exhausted: bool,
}

#[derive(Debug, Default)]
struct LocalEntry {
    catalog: Catalog,
    last_used: u64,
}

/// Worker-local copies plus the shared store (two layers).
pub struct Catalogs<S> {
    store: S,
    settings: CatalogSettings,
    local: HashMap<String, LocalEntry>,
    tick: u64,
}

impl<S: Store> Catalogs<S> {
    pub fn new(store: S, settings: CatalogSettings) -> Catalogs<S> {
        Catalogs {
            store,
            settings,
            local: HashMap::new(),
            tick: 0,
        }
    }

    pub fn settings(&self) -> CatalogSettings {
        self.settings
    }

    /// Read path (`tools/call`): merges the shared copy into the local copy
    /// and returns the local copy, which therefore only ever gains knowledge.
    pub fn read(&mut self, key: &str) -> &Catalog {
        let limits = self.settings.limits;
        let shared = self.load_shared(key);
        let local = self.local_entry(key);
        if let Some(shared) = shared {
            local.merge(&shared, limits);
        }
        local
    }

    /// Write path after a list response was fully validated and processed:
    /// merge the candidates, set `lastSuccessAt`, then write-verify.
    pub fn record_success(
        &mut self,
        key: &str,
        now_ms: u64,
        observations: &[(&str, Pin)],
    ) -> WriteReport {
        self.write(key, now_ms, |catalog, limits| {
            let changes: Vec<PinChange> = observations
                .iter()
                .map(|(name, pin)| catalog.observe(name, *pin, limits))
                .collect();
            catalog.mark_success(now_ms);
            changes
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
        self.write(key, now_ms, |catalog, limits| {
            let changes: Vec<PinChange> = observations
                .iter()
                .map(|(name, pin)| catalog.observe(name, *pin, limits))
                .collect();
            catalog.mark_success(now_ms);
            catalog.mark_failure(now_ms);
            changes
        })
    }

    /// Write path after a list response could not be inspected.
    pub fn record_failure(&mut self, key: &str, now_ms: u64) -> WriteReport {
        self.write(key, now_ms, |catalog, _| {
            catalog.mark_failure(now_ms);
            Vec::new()
        })
    }

    fn write(
        &mut self,
        key: &str,
        now_ms: u64,
        update: impl FnOnce(&mut Catalog, CatalogLimits) -> Vec<PinChange>,
    ) -> WriteReport {
        let settings = self.settings;
        let shared = self.load_shared(key);
        let local = self.local_entry(key);
        if let Some(shared) = shared {
            local.merge(&shared, settings.limits);
        }
        let was_stale = local.is_stale(now_ms, settings.max_age_seconds);
        let changes = update(local, settings.limits);
        let is_stale = local.is_stale(now_ms, settings.max_age_seconds);
        let wanted = local.clone();

        let capacity = changes.iter().find_map(|change| match change {
            PinChange::NotPinned(limit) => Some(*limit),
            _ => None,
        });
        let verified = self.write_verify(key, &wanted);
        WriteReport {
            changes,
            capacity,
            became_stale: !was_stale && is_stale,
            became_fresh: was_stale && !is_stale,
            retry_exhausted: !verified,
        }
    }

    /// Read, merge, save, re-read; retry while the re-read copy lacks
    /// something of `wanted`. Returns `true` once verified.
    fn write_verify(&mut self, key: &str, wanted: &Catalog) -> bool {
        let limits = self.settings.limits;
        for _ in 0..WRITE_ATTEMPTS {
            let mut merged = self.load_shared(key).unwrap_or_default();
            merged.merge(wanted, limits);
            let saved = self.store.save(key, merged.encode()).is_ok();
            if let Some(reread) = self.load_shared(key) {
                let verified = saved && reread.contains(wanted);
                self.local_entry(key).merge(&reread, limits);
                if verified {
                    return true;
                }
            }
        }
        false
    }

    fn load_shared(&self, key: &str) -> Option<Catalog> {
        self.store
            .get(key)
            .and_then(|bytes| Catalog::decode(&bytes))
    }

    fn local_entry(&mut self, key: &str) -> &mut Catalog {
        self.tick += 1;
        let tick = self.tick;
        if !self.local.contains_key(key) && self.local.len() >= self.settings.max_local_catalogs {
            let oldest = self
                .local
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                self.local.remove(&oldest);
            }
        }
        let entry = self.local.entry(key.to_owned()).or_default();
        entry.last_used = tick;
        &mut entry.catalog
    }

    /// The local copy, if this worker has one (for tests and diagnostics).
    pub fn local_copy(&self, key: &str) -> Option<&Catalog> {
        self.local.get(key).map(|entry| &entry.catalog)
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
        max_local_catalogs: 10,
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
        c.mark_failure(u64::MAX);
        let encoded = c.encode();
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
        c.mark_failure(45);
        assert_eq!(Catalog::decode(&c.encode()), Some(c));
        assert_eq!(
            Catalog::decode(&Catalog::default().encode()),
            Some(Catalog::default())
        );
    }

    #[test]
    fn unreadable_or_other_versions_decode_to_nothing() {
        assert_eq!(Catalog::decode(b"garbage"), None);
        assert_eq!(
            Catalog::decode(br#"{"v":2,"s":null,"f":null,"t":{}}"#),
            None
        );
        let skipped = Catalog::decode(br#"{"v":1,"s":1,"f":null,"t":{"ok":"ra","bad":"zz"}}"#);
        assert_eq!(skipped.map(|c| c.len()), Some(1));
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

    /// Simulates another worker overwriting the shared copy with a stale
    /// value right after each of our saves.
    #[derive(Default)]
    struct RacingStore {
        inner: MemoryStore,
        clobbers: RefCell<VecDeque<Vec<u8>>>,
    }

    impl Store for RacingStore {
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.get(key)
        }

        fn save(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
            self.inner.save(key, value)?;
            if let Some(stale) = self.clobbers.borrow_mut().pop_front() {
                self.inner.save(key, stale)?;
            }
            Ok(())
        }
    }

    struct FailingStore;

    impl Store for FailingStore {
        fn get(&self, _: &str) -> Option<Vec<u8>> {
            None
        }

        fn save(&self, _: &str, _: Vec<u8>) -> Result<(), StoreError> {
            Err(StoreError)
        }
    }

    fn observations() -> Vec<(&'static str, Pin)> {
        vec![
            ("search", pin(Class::Read)),
            ("drop", pin(Class::Destructive)),
        ]
    }

    #[test]
    fn success_writes_local_and_shared_copies() {
        let store = Rc::new(MemoryStore::default());
        let mut worker = Catalogs::new(Rc::clone(&store), SETTINGS);
        let report = worker.record_success("k", 100, &observations());
        assert_eq!(
            report.changes,
            vec![
                PinChange::New(pin(Class::Read)),
                PinChange::New(pin(Class::Destructive))
            ]
        );
        assert!(!report.retry_exhausted);
        let shared = store.get("k").and_then(|b| Catalog::decode(&b));
        assert_eq!(
            shared.as_ref().and_then(|c| c.pin("drop")).map(|p| p.class),
            Some(Class::Destructive)
        );
        assert_eq!(
            shared.map(|c| c.freshness().last_success_at),
            Some(Some(100))
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
        let mut worker = Catalogs::new(Rc::clone(&store), SETTINGS);
        worker.record_success(&a, 100, &[("operate", pin(Class::Read))]);
        worker.record_success(&b, 100, &[("operate", pin(Class::Destructive))]);
        assert_eq!(
            worker.read(&a).pin("operate").map(|p| p.class),
            Some(Class::Read)
        );
        assert_eq!(
            worker.read(&b).pin("operate").map(|p| p.class),
            Some(Class::Destructive)
        );
        let mut other = Catalogs::new(Rc::clone(&store), SETTINGS);
        assert_eq!(
            other.read(&a).pin("operate").map(|p| p.class),
            Some(Class::Read)
        );
    }

    #[test]
    fn another_worker_reads_pins_from_the_shared_copy() {
        let store = Rc::new(MemoryStore::default());
        let mut first = Catalogs::new(Rc::clone(&store), SETTINGS);
        let mut second = Catalogs::new(Rc::clone(&store), SETTINGS);
        first.record_success("k", 100, &observations());
        assert_eq!(
            second.read("k").pin("drop").map(|p| p.class),
            Some(Class::Destructive)
        );
    }

    #[test]
    fn concurrent_writers_converge() {
        let store = Rc::new(MemoryStore::default());
        let mut first = Catalogs::new(Rc::clone(&store), SETTINGS);
        let mut second = Catalogs::new(Rc::clone(&store), SETTINGS);
        first.record_success("k", 100, &[("a", pin(Class::Read))]);
        second.record_success(
            "k",
            101,
            &[("b", pin(Class::Write)), ("a", pin(Class::Write))],
        );
        let shared = store.get("k").and_then(|b| Catalog::decode(&b));
        assert_eq!(
            shared.as_ref().and_then(|c| c.pin("a")).map(|p| p.class),
            Some(Class::Write)
        );
        assert_eq!(
            shared.as_ref().and_then(|c| c.pin("b")).map(|p| p.class),
            Some(Class::Write)
        );
        assert_eq!(
            first.read("k").pin("b").map(|p| p.class),
            Some(Class::Write)
        );
    }

    #[test]
    fn a_stale_overwrite_is_detected_and_repaired() {
        let store = Rc::new(RacingStore::default());
        // Another worker's older copy, without our pins.
        store
            .clobbers
            .borrow_mut()
            .push_back(catalog(&[("old", Class::Read)], Some(1), None).encode());
        let mut worker = Catalogs::new(Rc::clone(&store), SETTINGS);
        let report = worker.record_success("k", 100, &observations());
        assert!(!report.retry_exhausted, "the second attempt repairs it");
        let shared = store.get("k").and_then(|b| Catalog::decode(&b));
        assert!(shared
            .as_ref()
            .is_some_and(|c| c.pin("drop").is_some() && c.pin("old").is_some()));
        assert!(
            worker
                .local_copy("k")
                .is_some_and(|c| c.pin("old").is_some()),
            "local copy gains the other worker's pins"
        );
    }

    #[test]
    fn retries_are_bounded() {
        let store = Rc::new(RacingStore::default());
        for _ in 0..WRITE_ATTEMPTS {
            store
                .clobbers
                .borrow_mut()
                .push_back(Catalog::default().encode());
        }
        let mut worker = Catalogs::new(Rc::clone(&store), SETTINGS);
        let report = worker.record_success("k", 100, &observations());
        assert!(report.retry_exhausted);
        assert_eq!(
            worker.read("k").pin("drop").map(|p| p.class),
            Some(Class::Destructive),
            "local pins stay"
        );
    }

    #[test]
    fn a_failing_store_keeps_local_pins() {
        let mut worker = Catalogs::new(FailingStore, SETTINGS);
        let report = worker.record_success("k", 100, &observations());
        assert!(report.retry_exhausted);
        assert!(worker.read("k").pin("drop").is_some());
    }

    #[test]
    fn freshness_transitions_are_reported() {
        let mut worker = Catalogs::new(MemoryStore::default(), SETTINGS);
        assert!(
            !worker
                .record_success("k", 100, &observations())
                .became_fresh
        );
        let failure = worker.record_failure("k", 200);
        assert!(failure.became_stale && !failure.became_fresh);
        assert!(worker.read("k").is_stale(250, 0));
        assert!(
            !worker.record_failure("k", 300).became_stale,
            "already stale"
        );
        let success = worker.record_success("k", 400, &[]);
        assert!(success.became_fresh);
        assert!(
            worker.read("k").pin("drop").is_some(),
            "pins survive staleness"
        );
    }

    #[test]
    fn a_change_after_the_list_learns_pins_and_ends_stale() {
        let mut worker = Catalogs::new(MemoryStore::default(), SETTINGS);
        let report = worker.record_success_then_changed("k", 100, &observations());
        assert!(report.became_stale && !report.became_fresh);
        assert!(worker.read("k").is_stale(100, 0));
        assert!(worker.read("k").pin("drop").is_some());
        // The next processed list clears it once the clock has moved on.
        assert!(worker.record_success("k", 101, &[]).became_fresh);
    }

    #[test]
    fn local_copies_are_bounded() {
        let settings = CatalogSettings {
            max_local_catalogs: 2,
            ..SETTINGS
        };
        let mut worker = Catalogs::new(FailingStore, settings);
        worker.record_success("a", 1, &observations());
        worker.record_success("b", 2, &observations());
        worker.read("a");
        worker.record_success("c", 3, &observations());
        assert!(worker.local_copy("a").is_some(), "recently used");
        assert!(
            worker.local_copy("b").is_none(),
            "least recently used is evicted"
        );
        assert!(worker.local_copy("c").is_some());
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
        let mut worker = Catalogs::new(MemoryStore::default(), settings);
        let report = worker.record_success("k", 1, &observations());
        assert_eq!(report.capacity, Some(CapacityLimit::MaxCachedTools));
        assert_eq!(
            report.changes.get(1),
            Some(&PinChange::NotPinned(CapacityLimit::MaxCachedTools))
        );
    }
}
