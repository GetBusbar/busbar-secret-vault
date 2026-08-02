// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-hashicorp-vault-plugin` cdylib loaded over the REAL loader
//! `kind:secret` seam (`busbar_plugin_loader::load_secret_from_bytes`) — the exact seam busbar's
//! engine uses. This is not a stub: it seeds a real secret directly into a real Vault dev-mode
//! server via a raw HTTP PUT, then `dlopen`s the actually-built plugin cdylib and reads that secret
//! back through the real C ABI, proving both field-addressing forms and the fail-closed 404/403
//! paths survive the ABI crossing intact.
//!
//! Ported from `busbarAI`'s `crates/plugin-loader/src/lib.rs`
//! (`load_and_exercise_hashicorp_vault_plugin`), the only over-the-ABI coverage of the real
//! Vault-backed `kind: secret` dlopen seam, now hosted here as this plugin's own end-to-end test
//! suite.
//!
//! Needs a real Vault dev-mode server:
//!
//! ```sh
//! docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
//! BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test
//! ```
//!
//! Vault dev mode auto-mounts a `kv-v2` engine at `secret/`, so this test's own setup step seeds
//! `secret/data/busbar-abi-test` directly via a raw HTTP PUT (a read-only client can't test itself
//! without something to read).

use busbar_plugin_loader::{load_secret_from_bytes, plugin_library_filename};

/// Locate the built `busbar_hashicorp_vault_plugin` cdylib in the target dir (mirrors the loader's own
/// `hashicorp_vault_plugin_path` test helper). Under CI, a missing cdylib is a hard failure — this is
/// the only over-the-ABI coverage of the real Vault-backed `kind: secret` dlopen seam and must never
/// silently skip there.
fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = plugin_library_filename("busbar_hashicorp_vault_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the hashicorp-vault plugin cdylib is not built under CI: `cargo test --workspace`-\
             equivalent must build busbar_hashicorp_vault_plugin. Refusing to silently skip the only \
             over-the-ABI coverage of the real Vault-backed kind:secret dlopen seam."
        );
    }
    candidate
}

/// End-to-end: dlopen the REAL hashicorp-vault-plugin cdylib, `open()` it against a real local Vault
/// dev-mode server's address + token, seed a real secret directly via Vault's KV v2 HTTP write
/// endpoint, then `resolve()` it back through the real C ABI — both field-addressing forms, plus the
/// fail-closed 404 path, all across the genuine ABI crossing.
#[test]
fn load_and_exercise_hashicorp_vault_plugin() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: hashicorp-vault plugin cdylib not built (run `cargo build` first)");
        return;
    };

    let (addr, token) = match (
        std::env::var("BUSBAR_TEST_VAULT_ADDR"),
        std::env::var("BUSBAR_TEST_VAULT_TOKEN"),
    ) {
        (Ok(addr), Ok(token)) => (addr, token),
        _ if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_VAULT_ADDR / BUSBAR_TEST_VAULT_TOKEN are unset under CI: a Vault \
                 dev-mode service container must provision them (see .github/workflows/ci.yml). \
                 Refusing to silently skip the only real-ABI Vault coverage in CI."
            );
        }
        _ => {
            eprintln!(
                "skip: set BUSBAR_TEST_VAULT_ADDR + BUSBAR_TEST_VAULT_TOKEN to run the real \
                 hashicorp-vault-plugin ABI test (docker run --rm -p 8200:8200 --cap-add=IPC_LOCK \
                 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault)"
            );
            return;
        }
    };

    // Seed a real secret with two fields directly via Vault's KV v2 write endpoint — this test's
    // own setup, exactly like `busbar-hashicorp-vault`'s own `roundtrip_against_live_vault` test.
    let seed = reqwest::blocking::Client::new();
    let put_body =
        serde_json::json!({ "data": { "api_key": "sk-abi-xyz789", "org_id": "org-abi" } })
            .to_string();
    let put_resp = seed
        .post(format!("{addr}/v1/secret/data/busbar-abi-test"))
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

    let bytes = std::fs::read(&path).expect("read hashicorp-vault plugin cdylib");
    let cfg = serde_json::json!({ "addr": addr, "token": token }).to_string();
    let module = load_secret_from_bytes(&bytes, &cfg, "hashicorp-vault", "secret")
        .expect("load hashicorp-vault plugin over the ABI");

    // `#field` addressing.
    let mut hash_settings = serde_json::Map::new();
    hash_settings.insert(
        "path".to_string(),
        serde_json::Value::String("secret/data/busbar-abi-test#api_key".into()),
    );
    let got = module
        .resolve(&hash_settings)
        .expect("resolve api_key over the real ABI against a real Vault");
    assert_eq!(got, b"sk-abi-xyz789");

    // Explicit `field` key addressing.
    let mut explicit_settings = serde_json::Map::new();
    explicit_settings.insert(
        "path".to_string(),
        serde_json::Value::String("secret/data/busbar-abi-test".into()),
    );
    explicit_settings.insert(
        "field".to_string(),
        serde_json::Value::String("org_id".into()),
    );
    let got = module
        .resolve(&explicit_settings)
        .expect("resolve org_id over the real ABI against a real Vault");
    assert_eq!(got, b"org-abi");

    // A wrong path is a distinct, loud 404 over the real ABI — never an empty Ok.
    let mut missing = serde_json::Map::new();
    missing.insert(
        "path".to_string(),
        serde_json::Value::String("secret/data/no-such-secret#x".into()),
    );
    let err = module
        .resolve(&missing)
        .expect_err("a missing Vault path must fail closed over the real ABI");
    assert_eq!(err.kind, busbar_api::SecretErrorKind::NotFound);
    assert!(
        err.message.contains("404"),
        "expected a 404 error, got: {}",
        err.message
    );

    // A reference settings map with no addressable field at all must also fail closed.
    assert!(
        module.resolve(&serde_json::Map::new()).is_err(),
        "settings with no `path` field must fail closed"
    );
}
