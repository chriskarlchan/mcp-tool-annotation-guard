// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Decision logic for the MCP Tool Annotation Guard.
//!
//! Pure Rust with no PDK dependencies, so it is unit-tested on the host with
//! `cargo test`. The policy crate in the repository root depends on it and
//! contains only the gateway glue.

// The policy must never panic on the request path.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

pub mod catalog;
pub mod classify;
pub mod config;
pub mod decide;
pub mod envelope;
pub mod filter;
pub mod freshness;
pub mod ids;
pub mod list;
pub mod log;
pub mod response;
pub mod sse;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "guard-core");
    }
}
