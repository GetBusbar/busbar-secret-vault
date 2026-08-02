// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests for the Vault KV v2 client: reference-parsing (both field-addressing
//! forms), the response-body size cap, and — gated on `BUSBAR_TEST_VAULT_ADDR`/`BUSBAR_TEST_VAULT_TOKEN`
//! — a real round trip against a live Vault dev-mode server.

use super::*;
use serde_json::json;

fn settings(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn hash_suffix_addressing_matches_the_published_doc_convention() {
    let s = settings(json!({ "path": "kv/data/openai#api_key" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/openai");
    assert_eq!(field, "api_key");
}

#[test]
fn explicit_field_key_is_accepted() {
    let s = settings(json!({ "path": "kv/data/openai", "field": "api_key" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/openai");
    assert_eq!(field, "api_key");
}

#[test]
fn explicit_field_wins_over_a_hash_in_path() {
    // Deliberately adversarial: a `#` that is not the intended split point.
    let s = settings(json!({ "path": "kv/data/weird#name", "field": "real_field" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/weird#name");
    assert_eq!(field, "real_field");
}

#[test]
fn missing_path_is_rejected() {
    let s = settings(json!({ "field": "api_key" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::Invalid);
    assert!(err.message.contains("path"), "{}", err.message);
}

#[test]
fn path_with_no_field_and_no_hash_is_rejected() {
    let s = settings(json!({ "path": "kv/data/openai" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::Invalid);
    assert!(err.message.contains("field to extract"), "{}", err.message);
}

#[test]
fn empty_field_after_hash_is_rejected() {
    let s = settings(json!({ "path": "kv/data/openai#" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::Invalid);
    assert!(err.message.contains("field to extract"), "{}", err.message);
}

#[test]
fn empty_explicit_field_is_rejected() {
    let s = settings(json!({ "path": "kv/data/openai", "field": "" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::Invalid);
    assert!(err.message.contains("must not be empty"), "{}", err.message);
}

#[test]
fn read_capped_refuses_over_the_cap_and_accepts_at_the_cap() {
    let cap = 16usize;
    let over = std::io::repeat(b'x').take(cap as u64 * 2);
    assert!(read_capped(over, cap).is_err());
    let at = std::io::repeat(b'x').take(cap as u64);
    assert_eq!(read_capped(at, cap).unwrap().len(), cap);
}

/// End-to-end against a REAL Vault dev-mode server, gated on `BUSBAR_TEST_VAULT_ADDR` +
/// `BUSBAR_TEST_VAULT_TOKEN` — mirrors `store-postgres`'s `BUSBAR_TEST_POSTGRES_URL` pattern
/// exactly, including the hard-fail-under-CI guard: skips cleanly when unset LOCALLY, but a
/// missing var under `CI` is a hard failure, not a silent skip, so this — the only live coverage
/// of the real Vault HTTP client — cannot quietly vanish.
///
/// Start a real Vault first:
/// ```sh
/// docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
/// BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test -p busbar-hashicorp-vault
/// ```
///
/// Vault dev mode auto-mounts a `kv-v2` engine at `secret/`, so the test seeds
/// `secret/data/busbar-test` directly via a raw HTTP PUT (a read-only client can't test itself
/// without something to read) and reads it back through [`VaultSecretModule`], asserting BOTH
/// field-addressing forms and the fail-closed 404 path.
#[test]
fn roundtrip_against_live_vault() {
    let (addr, token) = match (
        std::env::var("BUSBAR_TEST_VAULT_ADDR"),
        std::env::var("BUSBAR_TEST_VAULT_TOKEN"),
    ) {
        (Ok(addr), Ok(token)) => (addr, token),
        _ if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_VAULT_ADDR / BUSBAR_TEST_VAULT_TOKEN are unset under CI: a Vault \
                 dev-mode service container must provision them (see .github/workflows/ci.yml). \
                 Refusing to silently skip the only live-Vault coverage in CI."
            );
        }
        _ => {
            eprintln!(
                "skip: set BUSBAR_TEST_VAULT_ADDR + BUSBAR_TEST_VAULT_TOKEN to run the live \
                 Vault test (docker run --rm -p 8200:8200 --cap-add=IPC_LOCK \
                 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault)"
            );
            return;
        }
    };

    // Seed a real secret with two fields directly via Vault's KV v2 write endpoint — this test's
    // own setup, not part of the crate's (read-only) public API.
    let seed = reqwest::blocking::Client::new();
    let put_body =
        json!({ "data": { "api_key": "sk-live-abc123", "org_id": "org-xyz" } }).to_string();
    let put_resp = seed
        .post(format!("{addr}/v1/secret/data/busbar-test"))
        .header("X-Vault-Token", &token)
        .header("Content-Type", "application/json")
        .body(put_body)
        .send()
        .expect("seed PUT to Vault failed (is the dev server running and reachable?)");
    assert!(
        put_resp.status().is_success(),
        "seeding the test secret failed: HTTP {}",
        put_resp.status()
    );

    let module = VaultSecretModule::new(&VaultConfig {
        addr: addr.clone(),
        token: token.clone(),
        ca_cert_pem: None,
        timeout_secs: 10,
    })
    .expect("build VaultSecretModule");

    // `#field` addressing (the published doc convention).
    let hash_settings = settings(json!({ "path": "secret/data/busbar-test#api_key" }));
    let got = module.resolve(&hash_settings).expect("resolve api_key");
    assert_eq!(got, b"sk-live-abc123");

    // Explicit `field` key addressing the SECOND field in the same entry.
    let explicit_settings =
        settings(json!({ "path": "secret/data/busbar-test", "field": "org_id" }));
    let got = module.resolve(&explicit_settings).expect("resolve org_id");
    assert_eq!(got, b"org-xyz");

    // A wrong path is a distinct, loud 404 — never an empty Ok.
    let missing = settings(json!({ "path": "secret/data/no-such-secret#x" }));
    let err = module.resolve(&missing).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::NotFound);
    assert!(
        err.message.contains("404"),
        "expected a 404 error, got: {}",
        err.message
    );

    // A wrong field on a REAL path is also a distinct, loud error naming the field.
    let bad_field = settings(json!({ "path": "secret/data/busbar-test#no_such_field" }));
    let err = module.resolve(&bad_field).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::NotFound);
    assert!(
        err.message.contains("no_such_field"),
        "expected the error to name the missing field, got: {}",
        err.message
    );

    // A bad token is a distinct, loud 403 — never conflated with the 404 path.
    let bad_token_module = VaultSecretModule::new(&VaultConfig {
        addr,
        token: "not-a-real-token".to_string(),
        ca_cert_pem: None,
        timeout_secs: 10,
    })
    .expect("build VaultSecretModule with a bad token");
    let err = bad_token_module.resolve(&hash_settings).unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::Denied);
    assert!(
        err.message.contains("403"),
        "expected a 403 error, got: {}",
        err.message
    );
}
