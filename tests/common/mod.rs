// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// This module contains common Rust stuff shared between test files.

// Directory where the policies implementations are stored.
pub const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/wasm32-wasip1/release");

// Directory with the common configurations for tests.
pub const COMMON_CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/config");

// In case the project name changes, override this value with the actual policy name.
// To obtain the current name, run the "make show-policy-ref-name" goal, or read it from
// "target/policy-ref-name.txt" after building the project.
pub const POLICY_NAME: &str = "mcp-tool-annotation-guard-flex-v1-0";

// Omni Gateway image version the integration tests run on. Defaults to 1.13.0.
// Set PDK_TEST_FLEX_IMAGE_VERSION (the variable pdk-test itself reads) to run
// the same tests on another version, for example the declared minimum 1.11.4.
pub fn flex_version() -> String {
    std::env::var("PDK_TEST_FLEX_IMAGE_VERSION").unwrap_or_else(|_| "1.13.0".to_string())
}
