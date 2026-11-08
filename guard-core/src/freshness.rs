// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Stale and fresh catalog state.
//!
//! Times are milliseconds from the PDK clock. A catalog is stale when its last
//! failure is later than its last success, or when `catalog.maxAgeSeconds` is
//! set and the last success is older than that. A pin is used for decisions
//! only while its own tool is fresh: the tool was shown by an inspected list
//! after the last failure, and within `catalog.maxAgeSeconds`
//! ([`Freshness::trusts`]).

/// Why a catalog was marked stale (logged as `catalog_stale.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleReason {
    Encoded,
    TooLarge,
    ParseError,
    ResponseInvalid,
    UnsupportedContentType,
    InternalError,
    /// The gateway ended the response before its body was complete.
    Incomplete,
    /// `notifications/tools/list_changed` seen in a parsed stream.
    ListChanged,
}

impl StaleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StaleReason::Encoded => "encoded",
            StaleReason::TooLarge => "too_large",
            StaleReason::ParseError => "parse_error",
            StaleReason::ResponseInvalid => "response_invalid",
            StaleReason::UnsupportedContentType => "unsupported_content_type",
            StaleReason::InternalError => "internal_error",
            StaleReason::Incomplete => "incomplete",
            StaleReason::ListChanged => "list_changed",
        }
    }
}

/// The two timestamps that decide freshness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Freshness {
    pub last_success_at: Option<u64>,
    pub last_failure_at: Option<u64>,
}

impl Freshness {
    /// `true` when the catalog must not be trusted for decisions.
    pub fn is_stale(&self, now_ms: u64, max_age_seconds: u64) -> bool {
        // `None` orders before `Some`, so a failure with no success is stale.
        if self.last_failure_at > self.last_success_at {
            return true;
        }
        if max_age_seconds > 0 {
            return match self.last_success_at {
                None => true,
                Some(success) => {
                    now_ms.saturating_sub(success) > max_age_seconds.saturating_mul(1000)
                }
            };
        }
        false
    }

    /// `true` when a tool may be decided with its pin. `listed_at` is the
    /// last success whose list showed the tool: no failure may be recorded
    /// since, and with `catalog.maxAgeSeconds` set it must be no older than
    /// that. A success for another list (a later page, say) does not count,
    /// so a tool is trusted again only once a list the guard inspects shows it.
    pub fn trusts(&self, listed_at: Option<u64>, now_ms: u64, max_age_seconds: u64) -> bool {
        let Some(listed) = listed_at else {
            return false;
        };
        if self.last_failure_at >= Some(listed) {
            return false;
        }
        max_age_seconds == 0
            || now_ms.saturating_sub(listed) <= max_age_seconds.saturating_mul(1000)
    }

    /// Takes the later of each timestamp (merge).
    pub fn merge(&mut self, other: &Freshness) {
        self.last_success_at = self.last_success_at.max(other.last_success_at);
        self.last_failure_at = self.last_failure_at.max(other.last_failure_at);
    }

    /// `true` when no timestamp of `other` is later than this one's.
    pub fn contains(&self, other: &Freshness) -> bool {
        self.last_success_at >= other.last_success_at
            && self.last_failure_at >= other.last_failure_at
    }

    /// Each record is later than every record before it, even when the clock
    /// has not moved (same millisecond) or reads earlier (another worker's
    /// clock is ahead). Otherwise a failure right after a success would tie
    /// with it and leave the catalog fresh.
    pub fn mark_success(&mut self, now_ms: u64) {
        self.last_success_at = Some(Self::next(
            now_ms,
            self.last_success_at,
            self.last_failure_at,
        ));
    }

    pub fn mark_failure(&mut self, now_ms: u64) {
        self.last_failure_at = Some(Self::next(
            now_ms,
            self.last_failure_at,
            self.last_success_at,
        ));
    }

    /// `now`, but no earlier than `own` and strictly after `other`.
    fn next(now_ms: u64, own: Option<u64>, other: Option<u64>) -> u64 {
        let after_other = other.map_or(0, |other| other.saturating_add(1));
        now_ms.max(own.unwrap_or(0)).max(after_other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(success: Option<u64>, failure: Option<u64>) -> Freshness {
        Freshness {
            last_success_at: success,
            last_failure_at: failure,
        }
    }

    #[test]
    fn a_new_catalog_is_fresh_without_max_age() {
        assert!(!Freshness::default().is_stale(1_000, 0));
    }

    #[test]
    fn a_failure_after_the_last_success_makes_it_stale() {
        assert!(at(Some(10), Some(11)).is_stale(20, 0));
        assert!(at(None, Some(11)).is_stale(20, 0));
        assert!(!at(Some(11), Some(10)).is_stale(20, 0));
        assert!(
            !at(Some(10), Some(10)).is_stale(20, 0),
            "equal times are not 'later'"
        );
    }

    #[test]
    fn the_next_success_clears_staleness() {
        let mut f = at(Some(10), None);
        f.mark_failure(20);
        assert!(f.is_stale(25, 0));
        f.mark_success(30);
        assert!(!f.is_stale(35, 0));
    }

    #[test]
    fn a_tool_is_trusted_only_if_listed_after_the_last_failure() {
        let f = at(Some(30), Some(20));
        assert!(f.trusts(Some(30), 40, 0));
        assert!(!f.trusts(Some(10), 40, 0), "listed before the failure");
        assert!(!f.trusts(Some(20), 40, 0), "a tie is not 'after'");
        assert!(!f.trusts(None, 40, 0), "never listed");
        assert!(at(Some(30), None).trusts(Some(10), 40, 0));
    }

    #[test]
    fn max_age_counts_from_the_list_that_showed_the_tool() {
        let f = at(Some(61_000), None);
        assert!(f.trusts(Some(1_000), 61_000, 60));
        assert!(
            !f.trusts(Some(1_000), 61_001, 60),
            "a later list without the tool does not renew it"
        );
        assert!(f.trusts(Some(61_000), 61_001, 60));
        assert!(
            f.trusts(Some(1_000), u64::MAX, 0),
            "maxAge 0 disables expiry"
        );
    }

    #[test]
    fn max_age_expires_the_last_success() {
        let f = at(Some(1_000), None);
        assert!(!f.is_stale(61_000, 60), "exactly maxAge old is still fresh");
        assert!(f.is_stale(61_001, 60));
        assert!(
            at(None, None).is_stale(0, 60),
            "never listed is stale when maxAge is set"
        );
        assert!(!f.is_stale(u64::MAX, 0), "maxAge 0 disables expiry");
    }

    #[test]
    fn a_clock_going_backwards_does_not_expire() {
        assert!(!at(Some(5_000), None).is_stale(1_000, 1));
    }

    #[test]
    fn timestamps_only_move_forward() {
        let mut f = at(Some(50), Some(60));
        f.mark_failure(5);
        assert_eq!(f, at(Some(50), Some(60)));
    }

    #[test]
    fn a_failure_in_the_same_millisecond_as_a_success_is_later() {
        let mut f = Freshness::default();
        f.mark_success(100);
        f.mark_failure(100);
        assert!(f.is_stale(100, 0));
        f.mark_success(100);
        assert!(!f.is_stale(100, 0), "and a success after it is later again");
    }

    #[test]
    fn a_failure_with_a_clock_behind_the_last_success_still_counts() {
        let mut f = at(Some(50), Some(40));
        f.mark_failure(5);
        assert_eq!(f, at(Some(50), Some(51)));
        assert!(f.is_stale(5, 0));
    }

    #[test]
    fn merge_takes_the_later_of_each() {
        let mut a = at(Some(10), None);
        a.merge(&at(Some(5), Some(7)));
        assert_eq!(a, at(Some(10), Some(7)));
        assert!(a.contains(&at(Some(10), Some(7))));
        assert!(a.contains(&at(None, Some(3))));
        assert!(!a.contains(&at(Some(11), None)));
    }

    #[test]
    fn reasons_have_log_names() {
        assert_eq!(
            StaleReason::UnsupportedContentType.as_str(),
            "unsupported_content_type"
        );
        assert_eq!(StaleReason::ListChanged.as_str(), "list_changed");
    }
}
