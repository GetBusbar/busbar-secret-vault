// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real Vault
//! module. Hermetic — no network (a valid `addr`/`token` pair only builds an HTTP client; it never
//! connects until `resolve()` is called). This crate owns config-parsing coverage only, not the Vault
//! HTTP/KV-v2 logic itself, which is `busbar-secret-vault`'s own job. The real over-the-ABI, real-Vault
//! success path lives in this crate's own `tests/e2e.rs`.

use super::open;
use busbar_contract::secret::SecretModule;

/// `open` returns `Result<Box<dyn SecretModule>, String>`, and `dyn SecretModule` is not `Debug`
/// (it carries no such bound), so the standard `.unwrap_err()` doesn't compile here. This is the
/// equivalent for this specific `Result` shape — mirrors `auth-oidc-plugin`'s `expect_err`.
fn expect_err(result: Result<Box<dyn SecretModule>, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

#[test]
fn empty_config_is_rejected() {
    let err = expect_err(open(""));
    assert!(
        err.contains("config"),
        "error should name that config is required: {err}"
    );
}

#[test]
fn whitespace_only_config_is_rejected() {
    let err = expect_err(open("   \n\t  "));
    assert!(err.contains("config"), "got: {err}");
}

#[test]
fn malformed_json_is_rejected() {
    let err = expect_err(open("{ this is not json"));
    assert!(
        err.contains("invalid hashicorp-vault plugin config"),
        "error should name the config as invalid: {err}"
    );
}

#[test]
fn config_missing_addr_is_rejected() {
    // `addr` has no `#[serde(default)]` in `VaultConfig` — it is required. `deny_unknown_fields`
    // is also on, so this proves the missing-required-field path specifically, not a stray typo.
    let err = expect_err(open(r#"{"token":"root"}"#));
    assert!(
        err.contains("invalid hashicorp-vault plugin config"),
        "got: {err}"
    );
}

#[test]
fn config_missing_token_is_rejected() {
    let err = expect_err(open(r#"{"addr":"http://127.0.0.1:8200"}"#));
    assert!(
        err.contains("invalid hashicorp-vault plugin config"),
        "got: {err}"
    );
}

#[test]
fn unknown_config_field_is_rejected() {
    // `VaultConfig` is `#[serde(deny_unknown_fields)]` — a typo'd or stray operator key must fail
    // loud at boot, not be silently ignored.
    let err = expect_err(open(
        r#"{"addr":"http://127.0.0.1:8200","token":"root","bogus_field":true}"#,
    ));
    assert!(
        err.contains("invalid hashicorp-vault plugin config"),
        "got: {err}"
    );
}

#[test]
fn minimal_valid_config_succeeds_without_network() {
    // `open()` only builds an HTTP client and stores the address/token; it never connects until
    // `resolve()` is called, so this succeeds fully hermetically even though nothing is listening
    // on this address.
    let module = open(r#"{"addr":"http://127.0.0.1:8200","token":"root"}"#)
        .expect("minimal valid config must succeed without network");
    // No further trait surface to assert on hermetically — `resolve()` would need real network.
    let _: &dyn SecretModule = module.as_ref();
}

#[test]
fn full_config_with_optional_fields_succeeds_without_network() {
    let module = open(
        r#"{"addr":"https://vault.internal:8200/","token":"s.xxx","ca_cert_pem":null,"timeout_secs":5}"#,
    )
    .expect("full config with optional fields must succeed without network");
    let _: &dyn SecretModule = module.as_ref();
}
